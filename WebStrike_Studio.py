#!/usr/bin/env python3
"""
WebScan Studio
==============

Interactive Tkinter front-end for an authorized web-security assessment.
Each selected tool gets its own live output tab and a matching text file in
the run directory.

Added features:
  * Content discovery tools grouped cleanly into their own column.
  * Individual custom wordlist inputs and browse options for each wordlist tool.
  * Dynamic auto-incrementing file archival/versioning to avoid overwrites.
"""

from __future__ import annotations

import os
import queue
import re
import shlex
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DEFAULT_TIMEOUT = 900

WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/dirb/wordlists/common.txt",
]

@dataclass
class ToolContext:
    url: str
    host: str
    port: int
    scheme: str
    wordlist: Optional[str] = None
    request_file: Optional[str] = None
    tool_custom_wordlists: Dict[str, str] = field(default_factory=dict)


@dataclass
class Tool:
    name: str
    binary: str
    build_cmd: Callable[[ToolContext], List[str]]
    category: str = "Other"
    needs_wordlist: bool = False
    aliases: List[str] = field(default_factory=list)
    manual: bool = False
    note: str = ""

    def resolve_binary(self) -> Optional[str]:
        for candidate in [self.binary, *self.aliases]:
            path = shutil.which(candidate)
            if path:
                return path
        return None


def content_url(ctx: ToolContext) -> str:
    return ctx.url.rstrip("/") + "/FUZZ"


def get_effective_wordlist(c: ToolContext, tool_name: str) -> str:
    """Returns the tool-specific wordlist if set, otherwise falls back to global."""
    custom = c.tool_custom_wordlists.get(tool_name, "").strip()
    if custom:
        return custom
    return c.wordlist or ""


TOOLS: List[Tool] = [
    # --- Recon ---
    Tool("whatweb", "whatweb",
         lambda c: ["whatweb", "-a", "3", "--color=never", c.url],
         category="Recon"),
    Tool("wafw00f", "wafw00f",
         lambda c: ["wafw00f", c.url], category="Recon"),
    Tool("nmap", "nmap",
         lambda c: ["nmap", "-sV", "-Pn", "-T4", "--top-ports", "1000", c.host],
         category="Recon"),
    Tool("naabu", "naabu",
         lambda c: ["naabu", "-host", c.host, "-top-ports", "100"],
         category="Recon", aliases=["naabu.exe"]),
    Tool("katana", "katana",
         lambda c: ["katana", "-u", c.url, "-silent", "-nc"],
         category="Recon", aliases=["katana.exe"]),
    Tool("recon", "recon-ng",
         lambda c: [], category="Recon", manual=True,
         aliases=["recon"],
         note="Recon-ng interactive framework."),
    # --- Vulnerability ---
    Tool("nikto", "nikto",
         lambda c: ["nikto", "-h", c.url, "-nointeractive"],
         category="Vulnerability"),
    Tool("nuclei", "nuclei",
         lambda c: ["nuclei", "-u", c.url, "-nc"],
         category="Vulnerability"),
    Tool("wapiti", "wapiti",
         lambda c: ["wapiti", "-u", c.url, "--flush-session"],
         category="Vulnerability"),
    Tool("owasp-zap", "zap.sh",
         lambda c: ["zap.sh", "-cmd", "-quickurl", c.url, "-quickprogress"],
         category="Vulnerability", aliases=["zaproxy", "zap"]),
    Tool("burpsuite", "burpsuite", lambda c: [], category="Vulnerability",
         manual=True, aliases=["BurpSuiteCommunity", "BurpSuitePro"],
         note="Burp Suite manual intercept proxy."),
    # --- Injection ---
    Tool("sqlmap", "sqlmap",
         lambda c: (["sqlmap", "-r", c.request_file, "--batch", "--crawl=1", "--level=1"] if c.request_file
                    else ["sqlmap", "-u", c.url, "--batch", "--crawl=1", "--level=1"]),
         category="Injection"),
    Tool("commix", "commix",
         lambda c: (["commix", "-r", c.request_file, "--batch"] if c.request_file
                    else ["commix", "--url", c.url, "--batch"]),
         category="Injection"),
    # --- TLS ---
    Tool("sslscan", "sslscan",
         lambda c: ["sslscan", "--no-colour", f"{c.host}:{c.port}"],
         category="TLS"),
    Tool("testssl", "testssl.sh",
         lambda c: ["testssl.sh", "--color", "0", c.url],
         category="TLS", aliases=["testssl"]),
    # --- Content Discovery (Needs special layout treatment) ---
    Tool("dirb", "dirb",
         lambda c: (["dirb", c.url, get_effective_wordlist(c, "dirb"), "-S"] if get_effective_wordlist(c, "dirb")
                    else ["dirb", c.url]),
         category="Content discovery", needs_wordlist=True),
    Tool("gobuster", "gobuster",
         lambda c: ["gobuster", "dir", "-u", c.url, "-w", get_effective_wordlist(c, "gobuster"),
                    "-q", "-k", "-t", "40"],
         category="Content discovery", needs_wordlist=True),
    Tool("ffuf", "ffuf",
         lambda c: ["ffuf", "-u", content_url(c), "-w", get_effective_wordlist(c, "ffuf"),
                    "-ac", "-noninteractive"],
         category="Content discovery", needs_wordlist=True),
    Tool("feroxbuster", "feroxbuster",
         lambda c: ["feroxbuster", "-u", c.url, "-w", get_effective_wordlist(c, "feroxbuster"),
                    "--no-state", "--silent"],
         category="Content discovery", needs_wordlist=True,
         aliases=["feroxbuster.exe"]),
]

# Separate standard tools from wordlist discovery tools for grid orchestration
STANDARD_TOOLS = [t for t in TOOLS if not t.needs_wordlist]
WORDLIST_TOOLS = [t for t in TOOLS if t.needs_wordlist]

TOOLS_BY_NAME: Dict[str, Tool] = {tool.name: tool for tool in TOOLS}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty URL")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    return raw


def parse_target(url: str) -> ToolContext:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"Could not extract a host from: {url!r}")
    scheme = parsed.scheme or "http"
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError(f"Invalid port in target URL: {url!r}") from exc
    return ToolContext(url, parsed.hostname, port, scheme, None, None)


def sanitize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def find_wordlist() -> Optional[str]:
    for path in WORDLIST_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


def format_command(cmd: List[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(cmd)
    return shlex.join(cmd)


def get_unique_output_path(directory: Path, base_name: str) -> Path:
    sanitized_base = sanitize(base_name)
    candidate = directory / f"{sanitized_base}.txt"
    if not candidate.exists():
        return candidate

    counter = 1
    while True:
        candidate = directory / f"{sanitized_base}_{counter}.txt"
        if not candidate.exists():
            return candidate
        counter += 1


# --------------------------------------------------------------------------- #
# GUI application
# --------------------------------------------------------------------------- #

class WebScanGUI(tk.Tk):
    POLL_MS = 80

    def __init__(self) -> None:
        super().__init__()
        self.title("Web Security Scan Orchestrator")
        self.geometry("1100x820")
        self.minsize(950, 650)

        self.msg_q: "queue.Queue[tuple]" = queue.Queue()
        self.stop_event = threading.Event()
        self.proc_lock = threading.Lock()
        self.processes: List[subprocess.Popen] = []
        self.worker: Optional[threading.Thread] = None
        
        self.tool_vars: Dict[str, tk.BooleanVar] = {}
        self.tool_checks: Dict[str, ttk.Checkbutton] = {}
        self.tool_installed: Dict[str, bool] = {}
        self.custom_wordlist_vars: Dict[str, tk.StringVar] = {}
        
        self.tabs: Dict[str, ScrolledText] = {}
        self.out_dir: Optional[Path] = None
        self.total_selected = 0
        self.completed = 0
        self.status_var = tk.StringVar(value="Idle.")

        self._build_ui()
        self.after(self.POLL_MS, self._drain_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------------------- UI layout ---------------------------- #

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Target URL:").grid(row=0, column=0, sticky="w")
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(top, textvariable=self.url_var, width=60)
        url_entry.grid(row=0, column=1, columnspan=3, sticky="we", padx=6)
        url_entry.focus()

        ttk.Label(top, text="Output dir:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.outdir_var = tk.StringVar(value="scan_results")
        ttk.Entry(top, textvariable=self.outdir_var, width=40).grid(
            row=1, column=1, sticky="we", padx=6, pady=(6, 0))
        ttk.Button(top, text="Browse...", command=self._pick_outdir).grid(
            row=1, column=2, sticky="w", pady=(6, 0))

        ttk.Label(top, text="Global Wordlist:").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.wordlist_var = tk.StringVar(value=find_wordlist() or "")
        ttk.Entry(top, textvariable=self.wordlist_var, width=40).grid(
            row=2, column=1, sticky="we", padx=6, pady=(6, 0))
        ttk.Button(top, text="Browse...", command=self._pick_wordlist).grid(
            row=2, column=2, sticky="w", pady=(6, 0))

        ttk.Label(top, text="Request File:").grid(row=3, column=0, sticky="w", pady=(6, 0))
        self.request_file_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.request_file_var, width=40).grid(
            row=3, column=1, sticky="we", padx=6, pady=(6, 0))
        ttk.Button(top, text="Browse...", command=self._pick_request_file).grid(
            row=3, column=2, sticky="w", pady=(6, 0))

        opts = ttk.Frame(top)
        opts.grid(row=4, column=0, columnspan=4, sticky="w", pady=(8, 0))
        self.parallel_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Run in parallel", variable=self.parallel_var).pack(side="left")
        ttk.Label(opts, text="  Workers:").pack(side="left")
        self.workers_var = tk.IntVar(value=4)
        ttk.Spinbox(opts, from_=1, to=16, width=4, textvariable=self.workers_var).pack(side="left")
        ttk.Label(opts, text="  Timeout (s):").pack(side="left")
        self.timeout_var = tk.IntVar(value=DEFAULT_TIMEOUT)
        ttk.Spinbox(opts, from_=30, to=7200, increment=30, width=7,
                    textvariable=self.timeout_var).pack(side="left")
        top.columnconfigure(1, weight=1)

        # Main Tools Container Box splitting standard scans and targeted discovery
        toolbox = ttk.LabelFrame(self, text="Tools Configuration Matrix", padding=8)
        toolbox.pack(fill="x", padx=10, pady=5)
        
        # Configure columns inside the toolbox frame
        toolbox.columnconfigure(0, weight=1)
        toolbox.columnconfigure(1, weight=1)
        toolbox.columnconfigure(2, weight=2) # Content discovery area gets more room

        # Left & Middle Columns: Standard Tools
        left_middle_frame = ttk.Frame(toolbox)
        left_middle_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=(0, 10))
        
        for index, tool in enumerate(STANDARD_TOOLS):
            available = tool.manual or tool.resolve_binary() is not None
            self.tool_installed[tool.name] = available
            var = tk.BooleanVar(value=available and not tool.manual)
            self.tool_vars[tool.name] = var
            
            label = tool.name + ("  (manual/GUI)" if tool.manual else ("" if available else "  (not found)"))
            check = ttk.Checkbutton(left_middle_frame, text=label, variable=var)
            self.tool_checks[tool.name] = check
            if not available:
                check.state(["disabled"])
            check.grid(row=index // 2, column=index % 2, sticky="w", padx=6, pady=4)

        # Right / Last Column: Content Discovery Tools + Custom File Choosers
        right_frame = ttk.LabelFrame(toolbox, text="Content Discovery (Custom Wordlists)", padding=6)
        right_frame.grid(row=0, column=2, sticky="nsew")
        right_frame.columnconfigure(1, weight=1)

        for index, tool in enumerate(WORDLIST_TOOLS):
            available = tool.resolve_binary() is not None
            self.tool_installed[tool.name] = available
            var = tk.BooleanVar(value=available)
            self.tool_vars[tool.name] = var
            
            lbl_txt = tool.name if available else f"{tool.name} (not found)"
            chk = ttk.Checkbutton(right_frame, text=lbl_txt, variable=var)
            self.tool_checks[tool.name] = chk
            if not available:
                chk.state(["disabled"])
            chk.grid(row=index, column=0, sticky="w", padx=4, pady=4)
            
            # Contextual path variable and browse mechanics for this specific runtime tool execution
            w_var = tk.StringVar(value="")
            self.custom_wordlist_vars[tool.name] = w_var
            ent = ttk.Entry(right_frame, textvariable=w_var, font=("Courier New", 8))
            ent.grid(row=index, column=1, sticky="we", padx=4, pady=4)
            
            # Helper dynamic assignment mapping closure to bind index properly
            btn = ttk.Button(
                right_frame, 
                text="Browse", 
                width=7,
                command=lambda t=tool.name, v=w_var: self._pick_tool_wordlist(t, v)
            )
            btn.grid(row=index, column=2, padx=2, pady=4)
            if not available:
                ent.state(["disabled"])
                btn.state(["disabled"])

        # Operational Control Actions Block
        actions = ttk.Frame(self, padding=(10, 6))
        actions.pack(fill="x")
        self.start_btn = ttk.Button(actions, text="Start Scan", command=self._on_start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(actions, text="Stop", command=self._on_stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(actions, text="Clear output", command=self._clear_tabs).pack(side="left", padx=6)
        ttk.Button(actions, text="Open results folder", command=self._open_results).pack(side="left", padx=6)
        self.progress = ttk.Progressbar(actions, mode="determinate")
        self.progress.pack(side="right", fill="x", expand=True, padx=(10, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(4, 4))
        self.log_widget = self._add_tab("Run Log")
        ttk.Label(self, textvariable=self.status_var, relief="sunken",
                  anchor="w", padding=4).pack(fill="x", side="bottom")

    # ---------------------------- callbacks ---------------------------- #

    def _pick_outdir(self) -> None:
        path = filedialog.askdirectory(title="Select output directory")
        if path:
            self.outdir_var.set(path)

    def _pick_wordlist(self) -> None:
        path = filedialog.askopenfilename(title="Select global wordlist")
        if path:
            self.wordlist_var.set(path)

    def _pick_tool_wordlist(self, tool_name: str, var: tk.StringVar) -> None:
        path = filedialog.askopenfilename(title=f"Select dedicated wordlist for {tool_name}")
        if path:
            var.set(path)

    def _pick_request_file(self) -> None:
        path = filedialog.askopenfilename(title="Select Raw HTTP Request File")
        if path:
            self.request_file_var.set(path)

    def _open_results(self) -> None:
        target = self.out_dir or Path(self.outdir_var.get()).expanduser()
        target.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "nt":
                os.startfile(target)
            elif shutil.which("xdg-open"):
                subprocess.Popen(["xdg-open", str(target)])
            elif shutil.which("open"):
                subprocess.Popen(["open", str(target)])
            else:
                messagebox.showinfo("Results", f"Results are in:\n{target}")
        except Exception as exc:
            messagebox.showinfo("Results", f"Results are in:\n{target}\n\n{exc}")

    def _clear_tabs(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Busy", "Stop the current scan first.")
            return
        for tab_id in self.notebook.tabs():
            self.notebook.forget(tab_id)
        self.tabs.clear()
        self.log_widget = self._add_tab("Run Log")

    def _on_start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        try:
            url = normalize_url(self.url_var.get())
            ctx = parse_target(url)
            timeout = max(30, int(self.timeout_var.get()))
            workers = max(1, int(self.workers_var.get()))
        except (ValueError, tk.TclError) as exc:
            messagebox.showerror("Invalid settings", str(exc))
            return

        # Handle global fallback wordlist status mappings
        global_wl = self.wordlist_var.get().strip() or None
        if global_wl and not os.path.isfile(global_wl):
            messagebox.showwarning("Wordlist Verification", "Global wordlist path invalid; dropping fallback configurations.")
            global_wl = None
        ctx.wordlist = global_wl

        # Build map tracking all explicit custom file-path indicators inside specific items
        for t_name, t_var in self.custom_wordlist_vars.items():
            path_val = t_var.get().strip()
            if path_val:
                if os.path.isfile(path_val):
                    ctx.tool_custom_wordlists[t_name] = path_val
                else:
                    messagebox.showwarning("Custom Target Skip", f"Custom wordlist path for {t_name} is broken. Will attempt default matching.")

        request_file = self.request_file_var.get().strip() or None
        if request_file and not os.path.isfile(request_file):
            messagebox.showwarning("Request File", "Raw HTTP request target path missing.")
            request_file = None
        ctx.request_file = request_file

        selected = [TOOLS_BY_NAME[name] for name, var in self.tool_vars.items() if var.get()]
        
        # Verify wordlist readiness for all context-discovery components chosen
        runnable_selected = []
        for tool in selected:
            if tool.needs_wordlist:
                effective = get_effective_wordlist(ctx, tool.name)
                if not effective:
                    self._log(f"[!] Alert: Skipped {tool.name} because no general or custom wordlist was designated.")
                    continue
            runnable_selected.append(tool)

        if not runnable_selected:
            messagebox.showwarning("No tools", "No runnable tools are designated.")
            return

        started = datetime.now()
        run_name = f"{sanitize(ctx.host)}"
        self.out_dir = Path(self.outdir_var.get()).expanduser() / run_name
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self._clear_tabs()
        for tool in runnable_selected:
            self.tabs[tool.name] = self._add_tab(f"{tool.name} ...")
        self.stop_event.clear()
        self.completed = 0
        self.total_selected = len(runnable_selected)
        self.progress.configure(maximum=self.total_selected, value=0)
        self.start_btn.state(["disabled"])
        self.stop_btn.state(["!disabled"])
        self.status_var.set(f"Scanning {ctx.url} ...")

        self._log(f"=== Scan started {started:%Y-%m-%d %H:%M:%S} ===")
        self._log(f"Target       : {ctx.url}")
        self._log(f"Output dir   : {self.out_dir.resolve()}")
        self._log(f"Mode         : {'parallel' if self.parallel_var.get() else 'sequential'}")
        self._log("-" * 70)

        self.worker = threading.Thread(
            target=self._run_all,
            args=(runnable_selected, ctx, self.out_dir, timeout,
                  self.parallel_var.get(), workers),
            daemon=True,
        )
        self.worker.start()

    def _on_stop(self) -> None:
        self.stop_event.set()
        self.status_var.set("Stopping running processes...")
        with self.proc_lock:
            for proc in list(self.processes):
                try:
                    proc.terminate()
                except Exception:
                    pass

    def _on_close(self) -> None:
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno("Quit", "A execution is active. Stop and exit?"):
                return
            self._on_stop()
        self.destroy()

    # ------------------------- worker threads -------------------------- #

    def _run_all(self, tools: List[Tool], ctx: ToolContext, out_dir: Path,
                 timeout: int, parallel: bool, workers: int) -> None:
        try:
            if parallel:
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [executor.submit(self._run_one, tool, ctx, out_dir, timeout)
                               for tool in tools]
                    for future in futures:
                        future.result()
            else:
                for tool in tools:
                    if self.stop_event.is_set():
                        self.msg_q.put(("finish", tool.name, "stopped", None, 0.0))
                        continue
                    self._run_one(tool, ctx, out_dir, timeout)
        finally:
            self.msg_q.put(("all_done",))

    def _run_one(self, tool: Tool, ctx: ToolContext, out_dir: Path,
                 timeout: int) -> None:
        started = datetime.now()
        out_file = get_unique_output_path(out_dir, tool.name)

        if tool.manual:
            note = tool.note or "Manual intervention tool."
            self.msg_q.put(("start", tool.name, "(manual - skipped execution)"))
            self.msg_q.put(("output", tool.name, note + "\n"))
            out_file.write_text(note + "\n", encoding="utf-8")
            self.msg_q.put(("finish", tool.name, "manual", None, 0.0))
            return

        cmd = tool.build_cmd(ctx)
        display_cmd = format_command(cmd)
        self.msg_q.put(("start", tool.name, display_cmd))
        if self.stop_event.is_set():
            self.msg_q.put(("finish", tool.name, "stopped", None, 0.0))
            return

        effective_wl = get_effective_wordlist(ctx, tool.name) if tool.needs_wordlist else "N/A"
        header = (f"# Tool    : {tool.name}\n# Command : {display_cmd}\n"
                  f"# Target  : {ctx.url}\n# Wordlist: {effective_wl}\n# Started : {started:%Y-%m-%d %H:%M:%S}\n"
                  + "-" * 70 + "\n")
                  
        proc: Optional[subprocess.Popen] = None
        timed_out = threading.Event()
        try:
            with out_file.open("w", encoding="utf-8") as handle:
                handle.write(header)
                handle.flush()
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
                with self.proc_lock:
                    self.processes.append(proc)

                def watchdog() -> None:
                    assert proc is not None
                    try:
                        proc.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        timed_out.set()
                        try:
                            proc.terminate()
                        except Exception:
                            pass
                        self.msg_q.put(("output", tool.name, f"\n[!] Timeout reached after {timeout}s\n"))

                threading.Thread(target=watchdog, daemon=True).start()
                assert proc.stdout is not None
                for line in proc.stdout:
                    handle.write(line)
                    handle.flush()
                    self.msg_q.put(("output", tool.name, line))
                    if self.stop_event.is_set():
                        try:
                            proc.terminate()
                        except Exception:
                            pass
                        break

                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                rc = proc.returncode
                duration = (datetime.now() - started).total_seconds()
                handle.write(f"\n{'-' * 70}\n# Exit code: {rc}\n# Duration : {duration:.1f}s\n")

            status = "stopped" if self.stop_event.is_set() else ("timeout" if timed_out.is_set() else ("done" if rc == 0 else "warn"))
            self.msg_q.put(("finish", tool.name, status, rc, duration))
        except FileNotFoundError:
            self.msg_q.put(("finish", tool.name, "missing", None, 0.0))
        except Exception as exc:
            duration = (datetime.now() - started).total_seconds()
            self.msg_q.put(("output", tool.name, f"\n[!] Error: {exc}\n"))
            self.msg_q.put(("finish", tool.name, "error", None, duration))
        finally:
            if proc is not None:
                with self.proc_lock:
                    if proc in self.processes:
                        self.processes.remove(proc)

    # ------------------------- UI queue pump --------------------------- #

    def _drain_queue(self) -> None:
        try:
            while True:
                self._handle_msg(self.msg_q.get_nowait())
        except queue.Empty:
            pass
        self.after(self.POLL_MS, self._drain_queue)

    def _handle_msg(self, msg: tuple) -> None:
        kind = msg[0]
        if kind == "start":
            _, tool, command = msg
            self._append(tool, f"$ {command}\n")
            self._set_tab_label(tool, f"{tool}  >")
            self._log(f"[start] {tool}")
        elif kind == "output":
            _, tool, line = msg
            self._append(tool, line)
        elif kind == "finish":
            _, tool, status, rc, duration = msg
            icon = {"done": "OK", "warn": "!", "timeout": "TIME",
                    "stopped": "STOP", "error": "ERR", "missing": "N/A",
                    "manual": "INFO"}.get(status, "?")
            self._set_tab_label(tool, f"{tool}  [{icon}]")
            code = "" if rc is None else f" (exit {rc})"
            self._log(f"[{status}] {tool}{code}  {duration:.1f}s")
            self.completed += 1
            self.progress.configure(value=self.completed)
        elif kind == "all_done":
            self.start_btn.state(["!disabled"])
            self.stop_btn.state(["disabled"])
            done = "stopped" if self.stop_event.is_set() else "completed"
            self.status_var.set(f"Scan {done}. Results saved in {self.out_dir}" if self.out_dir else f"Scan {done}.")
            self._log(f"=== Scan {done} ===")

    # ----------------------------- widgets ----------------------------- #

    def _add_tab(self, name: str) -> ScrolledText:
        frame = ttk.Frame(self.notebook)
        text = ScrolledText(frame, wrap="none", height=10, font=("Courier New", 9))
        text.pack(fill="both", expand=True)
        text.configure(state="disabled")
        self.notebook.add(frame, text=name)
        return text

    def _append(self, tool: str, text: str) -> None:
        widget = self.tabs.get(tool)
        if widget is None:
            return
        widget.configure(state="normal")
        widget.insert("end", text)
        widget.see("end")
        widget.configure(state="disabled")

    def _log(self, text: str) -> None:
        self.log_widget.configure(state="normal")
        self.log_widget.insert("end", text + "\n")
        self.log_widget.see("end")
        self.log_widget.configure(state="disabled")

    def _set_tab_label(self, tool: str, label: str) -> None:
        widget = self.tabs.get(tool)
        if widget is None:
            return
        frame = widget.master
        for tab_id in self.notebook.tabs():
            if self.notebook.nametowidget(tab_id) is frame:
                self.notebook.tab(tab_id, text=label)
                break


def main() -> None:
    app = WebScanGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
