#!/usr/bin/env python3
"""
UbiDiscover - descobridor de dispositius Ubiquiti (protocol UDP 10001).
Autor: Albert Coll Bordas - https://www.acollbordas.com
Codi: https://github.com/acoll90/ubidiscover
Compilar a .exe (Windows):  python build.py
"""
import base64
import csv
import hashlib
import json
import os
import random
import tempfile
import ipaddress
import queue
import select
import socket
import sys
import struct
import subprocess
import threading
import time
import tkinter as tk
import urllib.request
import webbrowser
from tkinter import ttk, filedialog, messagebox

from lang import LANGUAGES, Translator, detect_system_language

__version__ = "1.2.0"
APP_NAME = "UbiDiscover"
REPO = "acoll90/ubidiscover"
WEB_URL = "https://www.acollbordas.com"
REPO_URL = f"https://github.com/{REPO}"
PAYPAL_URL = "https://www.paypal.me/acollbordas"
DONATION_AMOUNTS = (3, 5, 10, 20)

PORT = 10001
# v1 (airOS clàssic) i v2 (UniFi / equips nous)
PROBES = (b"\x01\x00\x00\x00", b"\x02\x08\x00\x00")
MAX_HOSTS = 65536
WMODES = {2: "Station", 3: "AP"}

COLS = (  # (clau, amplada); el títol surt de lang.py com a "col_<clau>"
    ("ip", 120), ("ips", 130), ("mac", 130), ("hostname", 170),
    ("model", 170), ("firmware", 230), ("essid", 130), ("wmode", 80), ("uptime", 100),
)

T = Translator()


def config_path():
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, APP_NAME, "config.json")


def load_config():
    try:
        with open(config_path(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    try:
        os.makedirs(os.path.dirname(config_path()), exist_ok=True)
        with open(config_path(), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except OSError:
        pass


# ---------------------------------------------------------------- protocol
def _txt(v):
    return v.decode("utf-8", "replace").strip("\x00 ")


def _mac(v):
    return ":".join(f"{b:02X}" for b in v)


def _uptime(sec):
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    return f"{d}d {h}h {r // 60}m"


def parse(data):
    """Descodifica una resposta TLV. Retorna dict o None."""
    if len(data) < 4:
        return None
    length = struct.unpack(">H", data[2:4])[0]
    end = min(len(data), 4 + length)
    pos, info = 4, {}
    while pos + 3 <= end:
        t = data[pos]
        ln = struct.unpack(">H", data[pos + 1:pos + 3])[0]
        v = data[pos + 3:pos + 3 + ln]
        pos += 3 + ln
        if t in (0x01, 0x13) and len(v) == 6:
            info.setdefault("mac", _mac(v))
        elif t == 0x02 and len(v) == 10:
            info.setdefault("mac", _mac(v[:6]))
            info.setdefault("ips", []).append(socket.inet_ntoa(v[6:]))
        elif t == 0x03:
            info["firmware"] = _txt(v)
        elif t == 0x0A and len(v) == 4:
            info["uptime"] = _uptime(struct.unpack(">I", v)[0])
        elif t == 0x0B:
            info["hostname"] = _txt(v)
        elif t == 0x0C:
            info.setdefault("model", _txt(v))
        elif t == 0x0D:
            info["essid"] = _txt(v)
        elif t == 0x0E and len(v) == 1:
            info["wmode"] = WMODES.get(v[0], str(v[0]))
        elif t == 0x14:
            info["model"] = _txt(v)          # model complet, té prioritat
        elif t == 0x16:
            info.setdefault("firmware", _txt(v))
    return info or None


# ---------------------------------------------------------------- xarxa
def local_ipv4s():
    ips = set()
    try:
        for i in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(i[4][0])
    except socket.gaierror:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))


def _make_sock(bind_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if hasattr(socket, "SIO_UDP_CONNRESET"):      # Windows: ignora ICMP unreachable
        s.ioctl(socket.SIO_UDP_CONNRESET, False)
    s.bind((bind_ip, 0))
    s.setblocking(False)
    return s


def scan(local_ips, targets, timeout, out):
    """Envia sondes i posa els resultats a la cua `out`."""
    socks = []
    try:
        # Broadcast per cada interfície local
        for ip in local_ips:
            try:
                s = _make_sock(ip)
                socks.append(s)
                for p in PROBES:
                    s.sendto(p, ("255.255.255.255", PORT))
            except OSError as e:
                out.put(("log", f"{ip}: {e}"))
        # Unicast a un rang (xarxes enrutades / altres segments)
        if targets:
            s = _make_sock("0.0.0.0")
            socks.append(s)
            for i, t in enumerate(targets):
                for p in PROBES:
                    try:
                        s.sendto(p, (t, PORT))
                    except OSError:
                        pass
                if i % 64 == 63:
                    time.sleep(0.01)
        deadline = time.monotonic() + timeout
        while socks:
            rem = deadline - time.monotonic()
            if rem <= 0:
                break
            ready, _, _ = select.select(socks, [], [], min(rem, 0.2))
            for s in ready:
                try:
                    data, addr = s.recvfrom(4096)
                except OSError:
                    continue
                info = parse(data)
                if info:
                    info["ip"] = addr[0]
                    info["via"] = s.getsockname()[0]
                    out.put(("dev", info))
    finally:
        for s in socks:
            s.close()
        out.put(("done", None))



def probe_web(ip, timeout=0.8):
    """Retorna l'URL si l'equip respon a 443 o 80, si no None."""
    for port, scheme in ((443, "https"), (80, "http")):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return f"{scheme}://{ip}"
        except OSError:
            continue
    return None


def temp_ip_candidates(dev_ip, known=(), count=25):
    """Llista d'IPs candidates (en ordre de preferència) al segment de l'equip."""
    known = set(known) | {dev_ip}
    if dev_ip.startswith("169.254."):
        cands = []
        while len(cands) < count:
            ip = f"169.254.{random.randint(1, 254)}.{random.randint(1, 254)}"
            if ip not in known and ip not in cands:
                cands.append(ip)
        return cands, 16
    base = dev_ip.rsplit(".", 1)[0]
    cands = [f"{base}.{h}" for h in range(253, 1, -1) if f"{base}.{h}" not in known]
    return cands[:count], 24


def run_elevated_ps(script):
    """Executa PowerShell com a administrador (demana UAC). Només Windows."""
    import ctypes
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    r = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", "powershell.exe",
        f"-NoProfile -WindowStyle Hidden -EncodedCommand {enc}", None, 0)
    return r > 32


def ps_add_ip(via, candidates, prefix, outfile):
    """Prova cada IP: l'afegeix, espera el DAD de Windows i, si surt
    'Duplicate' (ocupada), la treu i prova la següent. Escriu la IP
    triada (o FAIL) a outfile."""
    ips = ",".join(f"'{ip}'" for ip in candidates)
    return f"""
$out = '{outfile}'
$a = $null
if ('{via}' -and '{via}' -ne '0.0.0.0') {{
  $a = (Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{via}' -ErrorAction SilentlyContinue).InterfaceAlias
}}
if (-not $a) {{
  $a = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias
}}
foreach ($ip in @({ips})) {{
  try {{
    New-NetIPAddress -InterfaceAlias $a -IPAddress $ip -PrefixLength {prefix} -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
  }} catch {{ continue }}
  $st = 'Tentative'
  for ($i = 0; $i -lt 25 -and "$st" -eq 'Tentative'; $i++) {{
    Start-Sleep -Milliseconds 200
    $st = (Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue).AddressState
  }}
  if ("$st" -eq 'Preferred') {{
    Set-Content -Path $out -Value $ip -Encoding ASCII
    exit
  }}
  Remove-NetIPAddress -IPAddress $ip -Confirm:$false -ErrorAction SilentlyContinue
}}
Set-Content -Path $out -Value 'FAIL' -Encoding ASCII
"""


def ps_remove_ips(ips):
    return "\n".join(
        f"Remove-NetIPAddress -IPAddress '{ip}' -Confirm:$false -ErrorAction SilentlyContinue"
        for ip in ips)


def resource_path(rel):
    """Ruta a un recurs, tant en desenvolupament com dins l'.exe (PyInstaller)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


def _ver_tuple(v):
    out = []
    for part in v.lstrip("vV").split("."):
        num = "".join(ch for ch in part if ch.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out)


def _http(url, timeout=30, accept=None):
    headers = {"User-Agent": f"{APP_NAME}/{__version__}"}
    if accept:
        headers["Accept"] = accept
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout)


def check_latest_release(timeout=5):
    """Retorna (tag, url_pàgina, {nom_fitxer: url_descàrrega}) de la darrera release."""
    with _http(f"https://api.github.com/repos/{REPO}/releases/latest",
               timeout, "application/vnd.github+json") as r:
        data = json.load(r)
    assets = {a["name"]: a["browser_download_url"] for a in data.get("assets", [])}
    return data.get("tag_name", ""), data.get("html_url", REPO_URL + "/releases"), assets


def install_mode():
    """'setup' si s'ha instal·lat amb l'instal·lador, 'portable' si és l'.exe
    solt, o None si s'executa des del codi font (no es pot autoactualitzar)."""
    if not getattr(sys, "frozen", False) or os.name != "nt":
        return None
    folder = os.path.dirname(sys.executable)
    return "setup" if os.path.exists(os.path.join(folder, "unins000.exe")) else "portable"


def download_file(url, dest, progress=None):
    with _http(url, timeout=60) as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest().lower()


def parse_sha256sums(text):
    out = {}
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            out[parts[-1].lstrip("*")] = parts[0].lower()
    return out


def write_update_script(mode, new_file, exe, workdir):
    """Script .cmd que espera que l'app es tanqui, aplica l'actualització,
    torna a obrir l'app i s'esborra."""
    name = os.path.basename(exe)
    pids = [os.getpid(), os.getppid()]   # amb --onefile hi ha 2 processos
    waits = "\n".join(
        f'tasklist /FI "PID eq {p}" /FI "IMAGENAME eq {name}" /NH 2>nul | find "{p}" >nul '
        f'&& (timeout /t 1 /nobreak >nul & goto wait)' for p in pids)
    if mode == "setup":
        apply = f'"{new_file}" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-'
    else:
        apply = f"""set R=0
:mv
set /a R+=1
move /y "{new_file}" "{exe}" >nul 2>&1
if errorlevel 1 if %R% lss 30 (timeout /t 1 /nobreak >nul & goto mv)"""
    script = f"""@echo off
chcp 65001 >nul
set N=0
:wait
set /a N+=1
if %N% gtr 60 goto go
{waits}
:go
{apply}
start "" "{exe}"
(goto) 2>nul & rd /s /q "{workdir}"
"""
    path = os.path.join(workdir, "update.cmd")
    with open(path, "w", encoding="utf-8") as f:
        f.write(script.replace("\n", "\r\n"))
    return path


# ---------------------------------------------------------------- GUI
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        T.set(self.cfg.get("language") or detect_system_language())
        self.lang_var = tk.StringVar(value=T.lang)
        self.auto_update_var = tk.BooleanVar(value=bool(self.cfg.get("auto_update", False)))
        self.upd_win = None
        self.title(f"{APP_NAME} v{__version__}")
        try:
            self.iconbitmap(resource_path(os.path.join("assets", "ubidiscover.ico")))
        except Exception:
            pass
        self.geometry("1150x520")
        self.q = queue.Queue()
        self.rows = {}
        self.data = {}
        self.temp_ips = []
        self.sort_rev = {}
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        self.btn_local = ttk.Button(bar, command=self.scan_local)
        self.btn_local.pack(side="left")
        self.lbl_range = ttk.Label(bar)
        self.lbl_range.pack(side="left", padx=(14, 3))
        self.range_var = tk.StringVar()
        ent = ttk.Entry(bar, textvariable=self.range_var, width=20)
        ent.pack(side="left")
        ent.bind("<Return>", lambda e: self.scan_range())
        self.btn_range = ttk.Button(bar, command=self.scan_range)
        self.btn_range.pack(side="left", padx=4)
        self.lbl_timeout = ttk.Label(bar)
        self.lbl_timeout.pack(side="left", padx=(14, 3))
        self.timeout_var = tk.IntVar(value=4)
        ttk.Spinbox(bar, from_=1, to=30, textvariable=self.timeout_var, width=4).pack(side="left")
        self.btn_donate = ttk.Button(bar, command=self.donate)
        self.btn_donate.pack(side="right", padx=(8, 0))
        self.btn_export = ttk.Button(bar, command=self.export)
        self.btn_export.pack(side="right")
        self.btn_clear = ttk.Button(bar, command=self.clear)
        self.btn_clear.pack(side="right", padx=4)

        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, padx=6)
        self.tree = ttk.Treeview(frame, columns=[c[0] for c in COLS], show="headings")
        for key, w in COLS:
            self.tree.heading(key, command=lambda k=key: self.sort(k))
            self.tree.column(key, width=w, anchor="w")
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.open_web())
        self.tree.bind("<Button-3>", self.popup)

        self.status = tk.StringVar()
        ttk.Label(self, textvariable=self.status, padding=6, anchor="w").pack(fill="x")
        self.retranslate()
        self.status.set(T("st_ready", ips=", ".join(local_ipv4s())))
        self.after(100, self.poll)
        self.after(1500, lambda: self.check_updates(manual=False))

    # --- menú, actualitzacions i donacions
    def retranslate(self):
        """Aplica l'idioma actual a tots els textos de la finestra."""
        self.btn_local.config(text=T("btn_scan_local"))
        self.lbl_range.config(text=T("lbl_range"))
        self.btn_range.config(text=T("btn_scan_range"))
        self.lbl_timeout.config(text=T("lbl_timeout"))
        self.btn_donate.config(text=T("btn_donate"))
        self.btn_export.config(text=T("btn_export"))
        self.btn_clear.config(text=T("btn_clear"))
        for key, _ in COLS:
            self.tree.heading(key, text=T(f"col_{key}"))
        self._build_ctx_menu()
        self._build_menubar()

    def set_language(self):
        T.set(self.lang_var.get())
        self.cfg["language"] = T.lang
        save_config(self.cfg)
        self.retranslate()
        self.status.set(T("st_ready", ips=", ".join(local_ipv4s())))

    def _build_ctx_menu(self):
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label=T("ctx_open"), command=self.open_web)
        self.menu.add_command(label=T("ctx_copy_ip"), command=lambda: self.copy(0))
        self.menu.add_command(label=T("ctx_copy_mac"), command=lambda: self.copy(2))
        self.menu.add_separator()
        self.menu.add_command(label=T("ctx_remove_temp"), command=self.remove_temp_ips)

    def _build_menubar(self):
        mb = tk.Menu(self)
        lm = tk.Menu(mb, tearoff=0)
        for code, name in LANGUAGES.items():
            lm.add_radiobutton(label=name, value=code, variable=self.lang_var,
                               command=self.set_language)
        hm = tk.Menu(mb, tearoff=0)
        hm.add_command(label=T("menu_updates"), command=lambda: self.check_updates(manual=True))
        hm.add_checkbutton(label=T("menu_auto_update"), variable=self.auto_update_var,
                           command=self.toggle_auto_update)
        hm.add_command(label=T("menu_donate"), command=self.donate)
        hm.add_separator()
        hm.add_command(label=T("menu_web"), command=lambda: webbrowser.open(WEB_URL))
        hm.add_command(label=T("menu_github"), command=lambda: webbrowser.open(REPO_URL))
        hm.add_separator()
        hm.add_command(label=T("menu_about", app=APP_NAME), command=self.about)
        mb.add_cascade(label=T("menu_language"), menu=lm)
        mb.add_cascade(label=T("menu_help"), menu=hm)
        self.config(menu=mb)

    def check_updates(self, manual):
        def worker():
            try:
                tag, url, assets = check_latest_release()
            except Exception as e:
                if manual:
                    self.q.put(("status", T("st_update_err", err=e)))
                return
            newer = bool(tag) and _ver_tuple(tag) > _ver_tuple(__version__)
            if newer or manual:
                self.q.put(("update", (tag, url, newer, assets, manual)))
        threading.Thread(target=worker, daemon=True).start()

    def _show_update(self, tag, url, newer, assets, manual):
        if not newer:
            messagebox.showinfo(T("upd_title"), T("upd_latest", ver=__version__))
            return
        auto = self.auto_update_var.get() and not manual and install_mode()
        if auto or messagebox.askyesno(
                T("upd_new_title"), T("upd_new_msg", tag=tag, ver=__version__, app=APP_NAME)):
            self.start_update(tag, url, assets)

    def toggle_auto_update(self):
        self.cfg["auto_update"] = bool(self.auto_update_var.get())
        save_config(self.cfg)

    def start_update(self, tag, url, assets):
        mode = install_mode()
        if not mode:                      # executant-se des del .py
            webbrowser.open(url)
            return
        ver = tag.lstrip("vV")
        name = f"{APP_NAME}-{ver}-{'setup' if mode == 'setup' else 'portable'}.exe"
        if name not in assets:
            self._update_failed(T("upd_no_asset", name=name), url)
            return

        win = tk.Toplevel(self)
        win.title(T("upd_progress_title", app=APP_NAME))
        win.resizable(False, False)
        win.transient(self)
        win.protocol("WM_DELETE_WINDOW", lambda: None)
        frm = ttk.Frame(win, padding=16)
        frm.pack()
        self.upd_label = ttk.Label(frm, text=T("upd_downloading", tag=tag), width=46)
        self.upd_label.pack(anchor="w")
        self.upd_bar = ttk.Progressbar(frm, length=320, mode="determinate", maximum=100)
        self.upd_bar.pack(pady=(8, 0))
        self.upd_win = win

        def worker():
            try:
                workdir = tempfile.mkdtemp(prefix="ubidiscover_update_")
                dest = os.path.join(workdir, name)
                download_file(assets[name], dest,
                              lambda d, t: self.q.put(("upd_progress", (d, t))))
                if "SHA256SUMS.txt" in assets:
                    self.q.put(("upd_text", T("upd_verifying")))
                    with _http(assets["SHA256SUMS.txt"]) as r:
                        sums = parse_sha256sums(r.read().decode("utf-8", "replace"))
                    if sums.get(name) != sha256_file(dest):
                        raise RuntimeError(T("upd_bad_hash"))
                self.q.put(("upd_ready", (mode, dest, workdir)))
            except Exception as e:
                self.q.put(("upd_error", (str(e), url)))
        threading.Thread(target=worker, daemon=True).start()

    def _apply_update(self, mode, new_file, workdir):
        self.upd_label.config(text=T("upd_restarting"))
        self.update_idletasks()
        script = write_update_script(mode, new_file, sys.executable, workdir)
        subprocess.Popen(["cmd.exe", "/c", script], cwd=workdir, close_fds=True,
                         creationflags=0x08000000 | 0x00000200)  # NO_WINDOW | NEW_PROCESS_GROUP
        self.after(300, self.destroy)

    def _update_failed(self, err, url):
        if getattr(self, "upd_win", None):
            self.upd_win.destroy()
            self.upd_win = None
        if messagebox.askyesno(T("upd_title"), T("upd_failed", err=err)):
            webbrowser.open(url)

    def donate(self):
        win = tk.Toplevel(self)
        win.title(T("don_title"))
        win.resizable(False, False)
        win.transient(self)
        frm = ttk.Frame(win, padding=16)
        frm.pack()
        ttk.Label(frm, text=T("don_free_app", app=APP_NAME), font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(frm, text=T("don_text"),
                  wraplength=320).pack(anchor="w", pady=(4, 10))
        row = ttk.Frame(frm)
        row.pack(fill="x")
        for amt in DONATION_AMOUNTS:
            ttk.Button(row, text=f"{amt} €", width=7,
                       command=lambda a=amt: self._paypal(a, win)).pack(side="left", padx=3)
        free = ttk.Frame(frm)
        free.pack(fill="x", pady=(12, 0))
        ttk.Label(free, text=T("don_amount")).pack(side="left")
        amount = tk.StringVar()
        ent = ttk.Entry(free, textvariable=amount, width=8)
        ent.pack(side="left", padx=4)
        ttk.Label(free, text="€").pack(side="left")
        ttk.Button(free, text=T("don_button"),
                   command=lambda: self._paypal(amount.get(), win)).pack(side="left", padx=8)
        ttk.Label(frm, text=T("don_thanks"), foreground="#c0392b").pack(anchor="w", pady=(12, 0))
        ent.focus_set()

    def _paypal(self, amount, win=None):
        txt = str(amount).strip().replace(",", ".")
        try:
            val = float(txt)
            if val <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror(T("err_amount_title"), T("err_amount"), parent=win)
            return
        val_txt = f"{val:.2f}".rstrip("0").rstrip(".")
        webbrowser.open(f"{PAYPAL_URL}/{val_txt}EUR")
        if win:
            win.destroy()

    def about(self):
        messagebox.showinfo(
            T("menu_about", app=APP_NAME),
            f"{APP_NAME} v{__version__}\n\n" + T("about_text", web=WEB_URL, repo=REPO_URL))

    # --- accions
    def _start(self, targets):
        self.btn_local.state(["disabled"])
        self.btn_range.state(["disabled"])
        self.status.set(T("st_scanning"))
        threading.Thread(target=scan, daemon=True,
                         args=(local_ipv4s(), targets, self.timeout_var.get(), self.q)).start()

    def scan_local(self):
        self._start([])

    def scan_range(self):
        txt = self.range_var.get().strip()
        try:
            net = ipaddress.ip_network(txt, strict=False)
        except ValueError:
            messagebox.showerror(T("err_range_title"), T("err_range_format"))
            return
        if net.num_addresses > MAX_HOSTS:
            messagebox.showerror(T("err_range_title"), T("err_range_big", max=MAX_HOSTS))
            return
        hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
        self._start(hosts)

    def poll(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                if kind == "dev":
                    self.add(data)
                elif kind == "log":
                    print(data)
                elif kind == "status":
                    self.status.set(data)
                elif kind == "open":
                    webbrowser.open(data)
                    self.status.set(T("st_opened", url=data))
                elif kind == "update":
                    self._show_update(*data)
                elif kind == "upd_progress":
                    done, total = data
                    if total:
                        self.upd_bar["value"] = done * 100 / total
                elif kind == "upd_text":
                    self.upd_label.config(text=data)
                elif kind == "upd_ready":
                    self._apply_update(*data)
                elif kind == "upd_error":
                    self._update_failed(*data)
                elif kind == "tempip":
                    self.temp_ips.append(data)
                elif kind == "unreachable":
                    self.offer_temp_ip(*data)
                elif kind == "done":
                    self.btn_local.state(["!disabled"])
                    self.btn_range.state(["!disabled"])
                    self.status.set(T("st_done", n=len(self.rows)))
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def add(self, info):
        key = info.get("mac") or info["ip"]
        prev = self.data.get(key, {})
        allips = []
        for ip in [info["ip"]] + info.get("ips", []) + prev.get("all", []):
            if ip not in allips and ip != "0.0.0.0":
                allips.append(ip)
        info["all"] = allips
        info["via"] = info.get("via") or prev.get("via", "")
        self.data[key] = info
        view = dict(info, ips=", ".join(allips[1:]))
        vals = [view.get(k, "") for k, _ in COLS]
        if key in self.rows:
            self.tree.item(self.rows[key], values=vals)
        else:
            self.rows[key] = self.tree.insert("", "end", values=vals)
        self.status.set(T("st_scanning_n", n=len(self.rows)))

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        self.data.clear()

    def sort(self, col):
        idx = [c[0] for c in COLS].index(col)
        rev = self.sort_rev[col] = not self.sort_rev.get(col, True)

        def keyf(item):
            v = self.tree.item(item, "values")[idx]
            if col == "ip":
                try:
                    return (0, int(ipaddress.ip_address(v)))
                except ValueError:
                    return (1, 0)
            return (0, str(v).lower())
        for i, item in enumerate(sorted(self.tree.get_children(), key=keyf, reverse=rev)):
            self.tree.move(item, "", i)

    def _selected(self):
        sel = self.tree.selection()
        return self.tree.item(sel[0], "values") if sel else None

    def _selected_dev(self):
        sel = self.tree.selection()
        if not sel:
            return None
        for key, item in self.rows.items():
            if item == sel[0]:
                return self.data[key]
        return None

    def open_web(self):
        dev = self._selected_dev()
        if not dev:
            return
        self.status.set(T("st_checking"))
        threading.Thread(target=self._open_worker, args=(dev,), daemon=True).start()

    def _open_worker(self, dev):
        for ip in dev["all"]:
            url = probe_web(ip)
            if url:
                self.q.put(("open", url))
                return
        self.q.put(("unreachable", (dev,)))

    def offer_temp_ip(self, dev):
        # Prioritza la 169.254 (link-local), si no la primera IP anunciada
        target = next((ip for ip in dev["all"] if ip.startswith("169.254.")), dev["all"][0])
        if os.name != "nt":
            self.status.set(T("st_no_access", ip=target))
            return
        known = {ip for d in self.data.values() for ip in d.get("all", [])}
        cands, prefix = temp_ip_candidates(target, known)
        rang = "169.254.0.0/16" if prefix == 16 else target.rsplit(".", 1)[0] + ".0/24"
        ok = messagebox.askyesno(
            T("tmp_title"),
            T("tmp_msg", ips=", ".join(dev["all"]), range=rang, target=target, first=cands[0]))
        if not ok:
            self.status.set(T("st_cancelled"))
            return
        outfile = os.path.join(tempfile.gettempdir(), f"ubidiscover_{os.getpid()}.txt")
        try:
            os.remove(outfile)
        except OSError:
            pass
        if not run_elevated_ps(ps_add_ip(dev.get("via", ""), cands, prefix, outfile)):
            self.status.set(T("st_no_admin"))
            return
        self.status.set(T("st_finding_ip"))
        threading.Thread(target=self._wait_temp_ip, args=(outfile, target), daemon=True).start()

    def _wait_temp_ip(self, outfile, target):
        deadline = time.monotonic() + 90      # 25 candidates x ~3 s màxim
        while time.monotonic() < deadline:
            try:
                with open(outfile, encoding="ascii") as f:
                    res = f.read().strip()
            except OSError:
                time.sleep(0.5)
                continue
            if not res:
                time.sleep(0.3)
                continue
            try:
                os.remove(outfile)
            except OSError:
                pass
            if res == "FAIL":
                self.q.put(("status", T("st_all_busy")))
                return
            self.q.put(("tempip", res))
            self.q.put(("status", T("st_temp_added", ip=res, target=target)))
            self._wait_and_open(target)
            return
        self.q.put(("status", T("st_temp_timeout")))

    def _wait_and_open(self, ip):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            url = probe_web(ip, timeout=1)
            if url:
                self.q.put(("open", url))
                return
            time.sleep(1)
        self.q.put(("status", T("st_no_response", ip=ip)))

    def remove_temp_ips(self):
        if not self.temp_ips:
            self.status.set(T("st_no_temp"))
            return
        if os.name == "nt" and run_elevated_ps(ps_remove_ips(self.temp_ips)):
            self.status.set(T("st_removed", ips=", ".join(self.temp_ips)))
            self.temp_ips.clear()

    def on_close(self):
        if self.temp_ips and messagebox.askyesno(
                T("tmp_exit_title"), T("tmp_exit_msg")):
            self.remove_temp_ips()
        self.destroy()

    def copy(self, idx):
        v = self._selected()
        if v:
            self.clipboard_clear()
            self.clipboard_append(v[idx])

    def popup(self, ev):
        row = self.tree.identify_row(ev.y)
        if row:
            self.tree.selection_set(row)
            self.menu.tk_popup(ev.x_root, ev.y_root)

    def export(self):
        if not self.rows:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow([T(f"col_{c[0]}") for c in COLS])
            for item in self.tree.get_children():
                w.writerow(self.tree.item(item, "values"))
        self.status.set(T("st_exported", path=path))


if __name__ == "__main__":
    App().mainloop()
