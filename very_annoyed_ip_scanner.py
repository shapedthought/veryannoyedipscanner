#!/usr/bin/env python3
"""Very Annoyed IP Scanner - a grumpy little clone of Angry IP Scanner.

Stdlib only (tkinter + threads). Pings hosts, resolves hostnames, looks up
MAC addresses from the ARP cache and probes TCP ports. Complains throughout.
"""

import csv
import ipaddress
import platform
import queue
import random
import re
import socket
import subprocess
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import filedialog, messagebox, ttk

APP_NAME = "Very Annoyed IP Scanner"
DEFAULT_PORTS = "22,80,443,3389,8080"
IS_MAC = platform.system() == "Darwin"
IS_WIN = platform.system() == "Windows"

GRUMBLES_START = [
    "Ugh. Fine. Scanning.",
    "You want me to knock on how many doors?",
    "Starting scan. Again. As always.",
    "Oh great, more packets. My favourite.",
]
GRUMBLES_DONE = [
    "Done. You're welcome, I guess.",
    "Finished. Can I go back to sleep now?",
    "There. Happy? Don't answer that.",
    "Scan complete. That was exhausting.",
]
GRUMBLES_STOP = [
    "Stopped. Make up your mind.",
    "Oh, NOW you want me to stop?",
    "Cancelled. All that effort, wasted.",
]


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------

def ping(ip, timeout_ms):
    """Return round-trip time in ms, or None if the host didn't answer."""
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    start = time.monotonic()
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout_ms / 1000 + 2)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if out.returncode != 0:
        return None
    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", out.stdout)
    if m:
        return float(m.group(1))
    return (time.monotonic() - start) * 1000


def tcp_open(ip, port, timeout_ms):
    try:
        with socket.create_connection((ip, port), timeout=timeout_ms / 1000):
            return True
    except OSError:
        return False


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def mac_address(ip):
    try:
        out = subprocess.run(["arp", "-a" if IS_WIN else "-n", ip],
                             capture_output=True, text=True, timeout=2).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""
    m = re.search(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", out)
    if not m:
        return ""
    # macOS drops leading zeros (e.g. 0:1a:2b:...), normalise it.
    parts = re.split(r"[:-]", m.group(0))
    return ":".join(p.zfill(2) for p in parts).upper()


def scan_host(ip, ports, timeout_ms, stop_event):
    if stop_event.is_set():
        return None
    rtt = ping(ip, timeout_ms)
    open_ports = []
    # Hosts that drop ICMP may still have open ports, so probe anyway.
    for p in ports:
        if stop_event.is_set():
            break
        if tcp_open(ip, p, timeout_ms):
            open_ports.append(p)
    alive = rtt is not None or bool(open_ports)
    return {
        "ip": ip,
        "alive": alive,
        "ping": f"{rtt:.0f} ms" if rtt is not None else ("[n/a]" if alive else "[dead]"),
        "hostname": reverse_dns(ip) if alive else "",
        "mac": mac_address(ip) if alive else "",
        "ports": ",".join(map(str, open_ports)),
    }


# --------------------------------------------------------------------------
# Input parsing
# --------------------------------------------------------------------------

def parse_ports(text):
    ports = set()
    for chunk in text.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(chunk))
    bad = [p for p in ports if not 0 < p < 65536]
    if bad:
        raise ValueError(f"Port {bad[0]} is not a real port. Come on.")
    return sorted(ports)


def ip_range(start, end):
    a, b = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
    if a > b:
        a, b = b, a
    if b - a > 65535:
        raise ValueError("More than 65,536 addresses? Absolutely not.")
    return [str(ipaddress.IPv4Address(i)) for i in range(a, b + 1)]


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet sent, just picks a route
        return s.getsockname()[0]
    except OSError:
        return "192.168.1.1"
    finally:
        s.close()


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

class App(tk.Tk):
    COLUMNS = ("ip", "ping", "hostname", "mac", "ports")
    HEADINGS = {"ip": "IP", "ping": "Ping", "hostname": "Hostname",
                "mac": "MAC Address", "ports": "Ports"}
    WIDTHS = {"ip": 130, "ping": 80, "hostname": 240, "mac": 150, "ports": 180}

    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("880x560")
        self.minsize(640, 360)

        self.results = queue.Queue()
        self.stop_event = threading.Event()
        self.scan_thread = None
        self.total = self.done = self.alive = 0
        self.rows = {}

        self._build_ui()
        self._prefill_range()
        self.after(100, self._drain)

    # -- layout -------------------------------------------------------------

    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="IP Range:").grid(row=0, column=0, sticky="w")
        self.start_var = tk.StringVar()
        self.end_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.start_var, width=16).grid(row=0, column=1, padx=4)
        ttk.Label(top, text="to").grid(row=0, column=2)
        ttk.Entry(top, textvariable=self.end_var, width=16).grid(row=0, column=3, padx=4)

        ttk.Label(top, text="or CIDR:").grid(row=0, column=4, padx=(12, 0))
        self.cidr_var = tk.StringVar()
        cidr = ttk.Entry(top, textvariable=self.cidr_var, width=18)
        cidr.grid(row=0, column=5, padx=4)
        cidr.bind("<Return>", lambda e: self._apply_cidr())
        ttk.Button(top, text="Apply", command=self._apply_cidr).grid(row=0, column=6)

        self.scan_btn = ttk.Button(top, text="▶ Start", command=self.toggle_scan)
        self.scan_btn.grid(row=0, column=7, padx=(16, 0))

        ttk.Label(top, text="Ports:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.ports_var = tk.StringVar(value=DEFAULT_PORTS)
        ttk.Entry(top, textvariable=self.ports_var, width=36).grid(
            row=1, column=1, columnspan=3, sticky="we", padx=4, pady=(6, 0))

        ttk.Label(top, text="Timeout (ms):").grid(row=1, column=4, padx=(12, 0), pady=(6, 0))
        self.timeout_var = tk.IntVar(value=800)
        ttk.Spinbox(top, from_=100, to=10000, increment=100, width=7,
                    textvariable=self.timeout_var).grid(row=1, column=5, sticky="w", padx=4, pady=(6, 0))

        ttk.Label(top, text="Threads:").grid(row=1, column=6, pady=(6, 0))
        self.threads_var = tk.IntVar(value=64)
        ttk.Spinbox(top, from_=1, to=512, width=5,
                    textvariable=self.threads_var).grid(row=1, column=7, sticky="w", padx=(16, 0), pady=(6, 0))

        self.hide_dead = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Hide dead hosts (they're boring)",
                        variable=self.hide_dead, command=self._refilter).grid(
            row=2, column=1, columnspan=4, sticky="w", pady=(6, 0))
        ttk.Button(top, text="Export CSV…", command=self.export_csv).grid(
            row=2, column=7, sticky="e", pady=(6, 0))

        body = ttk.Frame(self, padding=(8, 0, 8, 0))
        body.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(body, columns=self.COLUMNS, show="headings")
        for c in self.COLUMNS:
            self.tree.heading(c, text=self.HEADINGS[c], command=lambda c=c: self._sort(c, False))
            self.tree.column(c, width=self.WIDTHS[c], anchor="w")
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Angry IP Scanner's classic colour coding.
        self.tree.tag_configure("dead", background="#f8d7d7", foreground="#7a1f1f")
        self.tree.tag_configure("alive", background="#d9f2d9", foreground="#1e4d1e")
        self.tree.tag_configure("ports", background="#d6e6fb", foreground="#16365c")

        self.tree.bind("<Double-1>", self._copy_ip)
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Copy IP", command=lambda: self._copy_field("ip"))
        self.menu.add_command(label="Copy hostname", command=lambda: self._copy_field("hostname"))
        self.menu.add_command(label="Copy MAC", command=lambda: self._copy_field("mac"))
        self.menu.add_separator()
        self.menu.add_command(label="Rescan this host", command=self._rescan_selected)
        self.tree.bind("<Button-2>" if IS_MAC else "<Button-3>", self._popup)
        self.tree.bind("<Control-Button-1>", self._popup)

        bottom = ttk.Frame(self, padding=8)
        bottom.pack(fill="x")
        self.progress = ttk.Progressbar(bottom, mode="determinate", length=200)
        self.progress.pack(side="right")
        self.status_var = tk.StringVar(value="Ready. Reluctantly.")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left")

    def _prefill_range(self):
        net = ipaddress.IPv4Network(f"{local_ip()}/24", strict=False)
        self.start_var.set(str(net.network_address + 1))
        self.end_var.set(str(net.broadcast_address - 1))
        self.cidr_var.set(str(net))

    def _apply_cidr(self):
        try:
            net = ipaddress.IPv4Network(self.cidr_var.get().strip(), strict=False)
        except ValueError:
            messagebox.showerror(APP_NAME, "That's not a CIDR. Try something like 192.168.1.0/24.")
            return
        hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
        self.start_var.set(str(hosts[0]))
        self.end_var.set(str(hosts[-1]))

    # -- scanning -----------------------------------------------------------

    def toggle_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_event.set()
            self.status_var.set("Stopping… hold your horses.")
            self.scan_btn.state(["disabled"])
            return
        try:
            ips = ip_range(self.start_var.get().strip(), self.end_var.get().strip())
            ports = parse_ports(self.ports_var.get())
            timeout = int(self.timeout_var.get())
            threads = max(1, int(self.threads_var.get()))
        except (ValueError, tk.TclError) as e:
            messagebox.showerror(APP_NAME, f"I can't work with this.\n\n{e}")
            return

        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        self.total, self.done, self.alive = len(ips), 0, 0
        self.progress.configure(maximum=self.total, value=0)
        self.stop_event.clear()
        self.scan_btn.configure(text="■ Stop")
        self.status_var.set(random.choice(GRUMBLES_START))
        self.started = time.monotonic()
        self.scan_thread = threading.Thread(
            target=self._run, args=(ips, ports, timeout, threads), daemon=True)
        self.scan_thread.start()

    def _run(self, ips, ports, timeout, threads):
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(scan_host, ip, ports, timeout, self.stop_event) for ip in ips]
            for f in futures:
                res = f.result()
                if res:
                    self.results.put(("row", res))
        self.results.put(("done", None))

    def _rescan_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        ip = self.tree.set(sel[0], "ip")
        try:
            ports = parse_ports(self.ports_var.get())
        except ValueError as e:
            messagebox.showerror(APP_NAME, str(e))
            return
        timeout = int(self.timeout_var.get())
        self.status_var.set(f"Rescanning {ip}. Like I don't have better things to do.")

        def work():
            res = scan_host(ip, ports, timeout, threading.Event())
            self.results.put(("update", res))
        threading.Thread(target=work, daemon=True).start()

    def _drain(self):
        try:
            while True:
                kind, res = self.results.get_nowait()
                if kind == "row":
                    self.done += 1
                    self.alive += res["alive"]
                    self._insert(res)
                    self.progress.configure(value=self.done)
                    self.status_var.set(
                        f"Scanned {self.done}/{self.total} · {self.alive} alive · sighing loudly")
                elif kind == "update":
                    old = self.rows.pop(res["ip"], None)
                    if old and self.tree.exists(old[0]):
                        self.tree.delete(old[0])
                    self._insert(res)
                    self.status_var.set(f"Rescanned {res['ip']}. " +
                                        ("Still alive." if res["alive"] else "Still dead. Shocking."))
                elif kind == "done":
                    elapsed = time.monotonic() - self.started
                    msg = GRUMBLES_STOP if self.stop_event.is_set() else GRUMBLES_DONE
                    self.status_var.set(
                        f"{random.choice(msg)}  {self.alive} alive of {self.done} "
                        f"in {elapsed:.1f}s.")
                    self.scan_btn.configure(text="▶ Start")
                    self.scan_btn.state(["!disabled"])
        except queue.Empty:
            pass
        self.after(50, self._drain)

    # -- table helpers ------------------------------------------------------

    def _insert(self, res):
        tag = "ports" if res["ports"] else ("alive" if res["alive"] else "dead")
        values = tuple(res[c] for c in self.COLUMNS)
        iid = None
        if res["alive"] or not self.hide_dead.get():
            iid = self.tree.insert("", self._position_for(res["ip"]), values=values, tags=(tag,))
        self.rows[res["ip"]] = (iid, res)

    def _position_for(self, ip):
        """Keep rows in IP order even though results arrive out of order."""
        key = int(ipaddress.IPv4Address(ip))
        children = self.tree.get_children()
        lo, hi = 0, len(children)
        while lo < hi:
            mid = (lo + hi) // 2
            if int(ipaddress.IPv4Address(self.tree.set(children[mid], "ip"))) < key:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _refilter(self):
        self.tree.delete(*self.tree.get_children())
        rows, self.rows = self.rows, {}
        for _, res in sorted(rows.values(), key=lambda r: int(ipaddress.IPv4Address(r[1]["ip"]))):
            self._insert(res)

    def _sort(self, col, reverse):
        def key(iid):
            v = self.tree.set(iid, col)
            if col == "ip":
                return int(ipaddress.IPv4Address(v))
            if col == "ping":
                m = re.match(r"([\d.]+)", v)
                return float(m.group(1)) if m else float("inf")
            return v.lower()
        items = sorted(self.tree.get_children(), key=key, reverse=reverse)
        for i, iid in enumerate(items):
            self.tree.move(iid, "", i)
        self.tree.heading(col, command=lambda: self._sort(col, not reverse))

    def _popup(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.menu.tk_popup(event.x_root, event.y_root)

    def _copy_field(self, field):
        sel = self.tree.selection()
        if sel:
            self.clipboard_clear()
            self.clipboard_append(self.tree.set(sel[0], field))

    def _copy_ip(self, _event):
        self._copy_field("ip")
        self.status_var.set("Copied. Don't say I never do anything for you.")

    def export_csv(self):
        if not self.rows:
            messagebox.showinfo(APP_NAME, "Export what? You haven't scanned anything.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")],
                                            initialfile="annoyed-scan.csv")
        if not path:
            return
        rows = sorted((r for _, r in self.rows.values()),
                      key=lambda r: int(ipaddress.IPv4Address(r["ip"])))
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([self.HEADINGS[c] for c in self.COLUMNS])
            for r in rows:
                if r["alive"] or not self.hide_dead.get():
                    w.writerow([r[c] for c in self.COLUMNS])
        self.status_var.set(f"Exported to {path}. Fine.")


if __name__ == "__main__":
    App().mainloop()
