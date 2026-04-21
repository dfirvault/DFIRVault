#!/usr/bin/env python3
"""
DFIRVault - Unified DFIR Operations Console
Developed by Jacob Wilson  •  dfirvault@gmail.com

Sections:
  1. DFIR Case Manager       — case folder creation & archiving
  2. Hayabusa Scanner        — EVTX log scanning (CSV + HTML reports)
  3. Chainsaw Scanner        — EVTX log hunting with Sigma rules
  4. Thor Scanner            — Drive/filesystem IOC scanning
  5. Splunk Index Manager    — create / backup / restore Splunk indexes
  6. CSV → ELK               — upload CSV data to Elasticsearch
  7. SFTP/FTP Monitor        — bidirectional file-sync monitoring
  8. VaultMirror             — safe scheduled sync via Windows Task Scheduler
  9. CSV Log Enricher        — enrich CSV logs with OTX / AbuseIPDB / IP2Location / Tor
  10. Body file to CSV       — convert a body file to CSV
"""

# ──────────────────────────────────────────────────────────────────
# STANDARD IMPORTS
# ──────────────────────────────────────────────────────────────────
import os
import re
import json
import sys
import math
import time
import shutil
import string
import hashlib
import getpass
import logging
import zipfile
import ctypes
import platform
import threading
import subprocess
import webbrowser
from pathlib import Path
from datetime import datetime, timedelta
from http.server import HTTPServer, SimpleHTTPRequestHandler
import tkinter as tk
from tkinter import filedialog, messagebox, Listbox, Scrollbar, ttk

IS_WINDOWS = platform.system() == "Windows"

# ── LogEnricher additional imports ────────────────────────────────
import csv
import ipaddress
import zipfile
import tempfile
import struct
import socket
import pickle
from typing import Dict, List, Set, Tuple, Optional, Any
from urllib.parse import urlparse
from collections import defaultdict
from io import StringIO

try:
    import requests as _le_requests
    from rich.console import Console as _LE_Console
    from rich.progress import Progress as _LE_Progress
    from rich.panel import Panel as _LE_Panel
    _LE_IMPORTS_OK = True
except ImportError:
    _LE_IMPORTS_OK = False

if IS_WINDOWS:
    try:
        import colorama
        colorama.init(autoreset=True)
    except ImportError:
        pass
    try:
        import winreg
    except ImportError:
        pass

# ──────────────────────────────────────────────────────────────────
# REGISTRY CONFIGURATION MANAGER
# ──────────────────────────────────────────────────────────────────
REGISTRY_PATH = r"Software\DFIRVault"

class RegistryConfig:
    """Manages configuration storage in Windows registry"""
    
    @staticmethod
    def _get_registry_key(subkey=""):
        """Open or create registry key"""
        full_path = REGISTRY_PATH
        if subkey:
            full_path = f"{REGISTRY_PATH}\\{subkey}"
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, full_path)
            return key
        except Exception as e:
            print(f"Registry error: {e}")
            return None
    
    @staticmethod
    def save_config(section, key, value):
        """Save a configuration value to registry"""
        if not IS_WINDOWS:
            return False
        try:
            key_handle = RegistryConfig._get_registry_key(section)
            if key_handle:
                # Convert value to appropriate type
                if isinstance(value, str):
                    winreg.SetValueEx(key_handle, key, 0, winreg.REG_SZ, value)
                elif isinstance(value, int):
                    winreg.SetValueEx(key_handle, key, 0, winreg.REG_DWORD, value)
                elif isinstance(value, bool):
                    winreg.SetValueEx(key_handle, key, 0, winreg.REG_DWORD, 1 if value else 0)
                elif isinstance(value, dict) or isinstance(value, list):
                    winreg.SetValueEx(key_handle, key, 0, winreg.REG_SZ, json.dumps(value))
                else:
                    winreg.SetValueEx(key_handle, key, 0, winreg.REG_SZ, str(value))
                winreg.CloseKey(key_handle)
                return True
        except Exception as e:
            print(f"Failed to save config: {e}")
        return False
    
    @staticmethod
    def load_config(section, key, default=None):
        """Load a configuration value from registry"""
        if not IS_WINDOWS:
            return default
        try:
            key_handle = RegistryConfig._get_registry_key(section)
            if key_handle:
                value, reg_type = winreg.QueryValueEx(key_handle, key)
                winreg.CloseKey(key_handle)
                
                # Try to parse JSON if it looks like a dict/list
                if reg_type == winreg.REG_SZ and isinstance(value, str):
                    if value.startswith('{') or value.startswith('['):
                        try:
                            return json.loads(value)
                        except:
                            pass
                return value
        except FileNotFoundError:
            return default
        except Exception as e:
            print(f"Failed to load config: {e}")
            return default
    
    @staticmethod
    def delete_config(section, key):
        """Delete a configuration value from registry"""
        if not IS_WINDOWS:
            return False
        try:
            key_handle = RegistryConfig._get_registry_key(section)
            if key_handle:
                winreg.DeleteValue(key_handle, key)
                winreg.CloseKey(key_handle)
                return True
        except:
            pass
        return False
    
    @staticmethod
    def list_section(section):
        """List all keys in a registry section"""
        if not IS_WINDOWS:
            return []
        try:
            key_handle = RegistryConfig._get_registry_key(section)
            if key_handle:
                keys = []
                i = 0
                while True:
                    try:
                        name = winreg.EnumValue(key_handle, i)[0]
                        keys.append(name)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key_handle)
                return keys
            return []
        except:
            return []


# ──────────────────────────────────────────────────────────────────
# GLOBAL UI HELPERS
# ──────────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    OK      = "✔"
    FAIL    = "✘"
    WARN    = "⚠"
    INFO    = "ℹ"
    ARROW   = "➤"
    BULLET  = "•"
    SPIN    = ['⣾','⣽','⣻','⢿','⡿','⣟','⣯','⣷']
    HEAVY   = "━"
    LIGHT   = "─"


def _c(colour, text):
    return f"{colour}{text}{C.RESET}"

def ok(msg):     print(f"  {_c(C.GREEN,  C.OK   + ' ' + msg)}")
def err(msg):    print(f"  {_c(C.RED,    C.FAIL  + ' ' + msg)}")
def warn(msg):   print(f"  {_c(C.YELLOW, C.WARN  + ' ' + msg)}")
def info(msg):   print(f"  {_c(C.CYAN,   C.INFO  + ' ' + msg)}")
def prompt(msg): return input(f"  {_c(C.MAGENTA, C.ARROW)} {msg} ")

def header(title, width=64):
    bar = C.HEAVY * width
    pad = (width - len(title) - 2) // 2
    print(f"\n{_c(C.CYAN, bar)}")
    print(f"{_c(C.CYAN, C.HEAVY)}{_c(C.BOLD+C.WHITE, ' '*pad + title + ' '*pad)}{_c(C.CYAN, C.HEAVY)}")
    print(f"{_c(C.CYAN, bar)}")

def subheader(title, width=64):
    bar = C.LIGHT * width
    print(f"\n{_c(C.BLUE, bar)}")
    print(f"  {_c(C.BOLD+C.BLUE, title)}")
    print(f"{_c(C.BLUE, bar)}")

def divider(width=64):
    print(_c(C.DIM, C.LIGHT * width))

def clear_screen():
    os.system("cls" if IS_WINDOWS else "clear")

def spinner(message, duration=2.0):
    end = time.time() + duration
    i = 0
    while time.time() < end:
        print(f"\r  {_c(C.BLUE, C.SPIN[i % len(C.SPIN)])} {message}", end="", flush=True)
        time.sleep(0.1)
        i += 1
    print("\r" + " " * (len(message) + 6) + "\r", end="", flush=True)

def progress_bar(current, total, width=40, label=""):
    filled = int(width * current / max(total, 1))
    bar    = _c(C.GREEN, "█" * filled) + _c(C.DIM, "░" * (width - filled))
    pct    = int(100 * current / max(total, 1))
    print(f"\r  [{bar}] {_c(C.BOLD, str(pct)+'%')} {label}", end="", flush=True)

def pause(msg="Press Enter to continue..."):
    input(f"\n  {_c(C.DIM, msg)}")

def pick_folder(title="Select Folder"):
    root = tk.Tk(); root.withdraw(); root.attributes("-topmost", True)
    p = filedialog.askdirectory(title=title); root.destroy(); return p

def pick_file(title="Select File", filetypes=None):
    root = tk.Tk(); root.withdraw(); root.attributes("-topmost", True)
    kw = {"filetypes": filetypes} if filetypes else {}
    p = filedialog.askopenfilename(title=title, **kw); root.destroy(); return p

def yesno_dialog(title, message):
    root = tk.Tk(); root.withdraw(); root.attributes("-topmost", True)
    r = messagebox.askyesno(title, message); root.destroy(); return r


# ══════════════════════════════════════════════════════════════════
#  SECTION 1 — DFIR CASE MANAGER
# ══════════════════════════════════════════════════════════════════

def _case_7zip():
    if getattr(sys, "frozen", False):
        base = sys._MEIPASS
        exe, dll = os.path.join(base, "7z.exe"), os.path.join(base, "7z.dll")
        if not all(os.path.exists(f) for f in [exe, dll]):
            return None
        return exe
    default = r"C:\Program Files\7-Zip\7z.exe"
    return default if os.path.exists(default) else None

def _case_read_backup():
    """Read backup location from registry"""
    return RegistryConfig.load_config("CaseManager", "backup_location", "")

def _case_write_backup(path):
    """Write backup location to registry"""
    RegistryConfig.save_config("CaseManager", "backup_location", path)

def _case_read_case_folder():
    """Read case folder location from registry"""
    return RegistryConfig.load_config("CaseManager", "case_folder", "")

def _case_write_case_folder(folder_path):
    """Write case folder location to registry"""
    RegistryConfig.save_config("CaseManager", "case_folder", folder_path)

def case_create(case_folder):
    subheader("Create New Case")
    name = prompt("Case name:").strip()
    if not name:
        err("Case name cannot be empty.")
        return
    
    # Create case in the tracked case folder
    case_path = os.path.join(case_folder, name)
    folders = [
        f"{case_path}/01 - Evidence",
        f"{case_path}/02 - Case",
        f"{case_path}/03 - Malware",
        f"{case_path}/04 - Extracted Evidence/01 - Axiom",
        f"{case_path}/04 - Extracted Evidence/02 - XWays",
        f"{case_path}/04 - Extracted Evidence/03 - Thor",
        f"{case_path}/04 - Extracted Evidence/04 - Hayabusa",
        f"{case_path}/04 - Extracted Evidence/05 - Chainsaw",
    ]
    print()
    for i, f in enumerate(folders, 1):
        os.makedirs(f, exist_ok=True)
        progress_bar(i, len(folders), label=f)
    print()
    open(f"{case_path}/Keywords.txt", "a").close()
    ok(f"Case '{_c(C.BOLD, name)}' created at: {case_path}")
    info("01-Evidence | 02-Case | 03-Malware | 04-Extracted Evidence")
    if IS_WINDOWS:
        try: os.startfile(os.path.abspath(case_path))
        except: pass

def case_archive(backup_location, case_folder):
    subheader("Archive Case")
    if not os.path.exists(case_folder):
        err(f"Case folder not found: {case_folder}")
        return
    
    folders = [f for f in os.listdir(case_folder) if os.path.isdir(os.path.join(case_folder, f))]
    if not folders:
        warn("No cases found in case folder.")
        return
    
    print()
    for i, f in enumerate(folders, 1):
        print(f"  {_c(C.CYAN, f'[{i}]')} {f}")
    print()
    raw = prompt(f"Select case [1-{len(folders)}]:").strip()
    try:
        target = folders[int(raw) - 1]
    except (ValueError, IndexError):
        err("Invalid selection.")
        return
    
    target_path = os.path.join(case_folder, target)
    use_pw = prompt("Password-protect ZIP? (y/n):").lower().startswith("y")
    pw = ""
    if use_pw:
        pw = prompt("ZIP password:").strip()
        if not pw:
            warn("No password — creating unprotected ZIP.")
            use_pw = False
    info("Select destination for ZIP…")
    dst = pick_folder("Select backup destination")
    if not dst:
        warn("Cancelled.")
        return
    zip_path = os.path.join(dst, f"{target}.zip")
    spinner(f"Archiving '{target}'…", 1.5)
    try:
        seven = _case_7zip()
        if use_pw and seven:
            subprocess.run([seven, "a", "-tzip", zip_path,
                            os.path.join(target_path, "*"),
                            f"-p{pw}", "-mem=AES256"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            shutil.make_archive(os.path.splitext(zip_path)[0], "zip", target_path)
        if os.path.exists(zip_path):
            spinner("Removing source folder…", 1.0)
            shutil.rmtree(target_path)
            ok(f"Archived → {zip_path}")
        else:
            err("Archive creation failed.")
    except FileNotFoundError:
        warn("7-Zip unavailable — using standard ZIP.")
        shutil.make_archive(os.path.splitext(zip_path)[0], "zip", target_path)
        ok(f"Archived (no password) → {zip_path}")

def case_change_case_folder():
    """Change the case folder location"""
    info("Select new case folder location…")
    loc = pick_folder("Select Case Folder Location")
    if loc and os.path.isdir(loc):
        _case_write_case_folder(loc)
        ok(f"Case folder location set: {loc}")
        return loc
    warn("No valid location selected.")
    return None

def case_change_backup():
    info("Select new backup location…")
    loc = pick_folder("Select Case Backup Location")
    if loc and os.path.isdir(loc):
        _case_write_backup(loc)
        ok(f"Backup location set: {loc}")
        return loc
    warn("No valid location selected."); return None

def menu_case_manager():
    # Get or set case folder
    case_folder = _case_read_case_folder()
    if not case_folder:
        warn("No case folder configured. Cases will be created in current directory.")
        if prompt("Would you like to set a case folder now? (y/n):").lower().startswith('y'):
            case_folder = case_change_case_folder()
    
    # Get or set backup location
    backup = _case_read_backup()
    if not backup:
        warn("No backup location configured.")
        if prompt("Would you like to set a backup location now? (y/n):").lower().startswith('y'):
            backup = case_change_backup()
    
    while True:
        header("DFIR CASE MANAGER")
        print(f"\n  {_c(C.DIM, 'Case Folder:')} {_c(C.YELLOW, case_folder or 'Not Set (using current dir)')}")
        print(f"  {_c(C.DIM, 'Backup:')}      {_c(C.YELLOW, backup or 'Not Set')}\n")
        print(f"  {_c(C.CYAN, '[1]')} Create new case")
        print(f"  {_c(C.CYAN, '[2]')} Archive existing case")
        print(f"  {_c(C.CYAN, '[3]')} Change case folder location")
        print(f"  {_c(C.CYAN, '[4]')} Change backup location")
        print(f"  {_c(C.CYAN, '[5]')} Open case folder")
        print(f"  {_c(C.RED, '[0]')} Back")
        divider()
        ch = prompt("Choice:").strip()
        
        if ch == "1":
            if not case_folder:
                warn("No case folder set. Cases will be created in current directory.")
                if prompt("Set case folder now? (y/n):").lower().startswith('y'):
                    case_folder = case_change_case_folder()
            case_create(case_folder if case_folder else ".")
            
        elif ch == "2":
            if not case_folder:
                err("No case folder configured. Please set case folder first.")
                if prompt("Set case folder now? (y/n):").lower().startswith('y'):
                    case_folder = case_change_case_folder()
                if not case_folder:
                    continue
            
            if not backup:
                warn("No backup location configured.")
                if prompt("Set backup location now? (y/n):").lower().startswith('y'):
                    backup = case_change_backup()
                if not backup:
                    continue
            case_archive(backup, case_folder)
            
        elif ch == "3":
            r = case_change_case_folder()
            if r:
                case_folder = r
                
        elif ch == "4":
            r = case_change_backup()
            if r:
                backup = r
                
        elif ch == "5":
            if case_folder and os.path.exists(case_folder):
                if IS_WINDOWS:
                    try:
                        os.startfile(os.path.abspath(case_folder))
                        ok(f"Opened case folder: {case_folder}")
                    except:
                        err("Could not open folder")
                else:
                    info(f"Case folder location: {case_folder}")
            else:
                warn("Case folder not set or does not exist.")
                
        elif ch == "0":
            break
        else:
            err("Invalid choice.")
        pause()


# ══════════════════════════════════════════════════════════════════
#  SECTION 2 — HAYABUSA SCANNER
# ══════════════════════════════════════════════════════════════════

def _hayabusa_find_evtx(start):
    folders = []
    for root, dirs, files in os.walk(start):
        if any(f.lower().endswith(".evtx") for f in files):
            if root not in folders:
                folders.append(root)
    return folders

def _hayabusa_load_path():
    """Load Hayabusa path from registry"""
    path = RegistryConfig.load_config("Hayabusa", "executable_path", "")
    if path and os.path.exists(path):
        return path
    defaults = [r"C:\Tools\Hayabusa\hayabusa.exe", "hayabusa.exe"]
    for d in defaults:
        if os.path.exists(d):
            return os.path.abspath(d)
    return ""

def _hayabusa_save_path(path):
    """Save Hayabusa path to registry"""
    RegistryConfig.save_config("Hayabusa", "executable_path", path)

def _hayabusa_pick_path():
    p = pick_file("Select Hayabusa executable",
                  filetypes=[("Hayabusa", "hayabusa*.exe"), ("All", "*.*")])
    if p and os.path.isdir(p):
        p = os.path.join(p, "hayabusa.exe")
    return p

def hayabusa_run_scan(hayabusa_path, evtx_folder):
    subheader("Hayabusa Scan")
    info("Select folder to save reports…")
    report_path = pick_folder("Select report destination")
    if not report_path:
        warn("Cancelled."); return
    os.makedirs(report_path, exist_ok=True)
    folder_name = re.sub(r'[^a-zA-Z0-9_-]', '_', os.path.basename(os.path.normpath(evtx_folder))) or "scan"
    while True:
        case_name = prompt("Case name (e.g. MAL2024-001):").strip()
        if case_name:
            case_name = re.sub(r'[^a-zA-Z0-9_-]', '_', case_name); break
        err("Case name cannot be empty.")
    date_prefix = datetime.now().strftime("%Y%m%d")
    base = f"{date_prefix}-{folder_name}-{case_name}"
    csv_out  = os.path.join(report_path, f"{base}-results.csv")
    html_out = os.path.join(report_path, f"{base}-report.html")
    log_out  = os.path.join(report_path, f"{base}-log.txt")
    cmd = [hayabusa_path, "csv-timeline", "-d", evtx_folder,
           "-o", csv_out, "--ISO-8601", "--no-wizard", "--quiet",
           "--HTML-report", html_out]
    info(f"Scanning: {evtx_folder}")
    info(f"Reports:  {report_path}")
    print()
    try:
        with open(log_out, "w") as log:
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.PIPE, universal_newlines=True)
            _, stderr = proc.communicate()
        if proc.returncode != 0:
            err(f"Scan error (exit {proc.returncode})")
            if stderr: print(f"  {stderr.strip()}")
        else:
            ok("Scan completed successfully!")
            ok(f"CSV:  {csv_out}")
            ok(f"HTML: {html_out}")
    except Exception as e:
        err(f"Failed to start Hayabusa: {e}")
    if IS_WINDOWS:
        try: os.startfile(report_path)
        except: pass
    pause()

def hayabusa_scan_folder(hayabusa_path):
    subheader("Select EVTX Folder")
    evtx_folder = pick_folder("Select folder containing EVTX files")
    if not evtx_folder:
        warn("Cancelled."); return
    evtx_files = [f for f in os.listdir(evtx_folder) if f.lower().endswith(".evtx")]
    if not evtx_files:
        warn("No EVTX files found in selected folder.")
        if prompt("Search subfolders? (y/n):").lower().startswith("y"):
            subs = _hayabusa_find_evtx(evtx_folder)
            if not subs:
                err("No EVTX files found anywhere."); pause(); return
            if len(subs) == 1:
                evtx_folder = subs[0]
            else:
                print()
                for i, s in enumerate(subs, 1):
                    print(f"  {_c(C.CYAN,f'[{i}]')} {s}")
                print(f"  {_c(C.CYAN,'[a]')} All folders")
                sel = prompt("Select:").strip().lower()
                if sel == "a":
                    for s in subs:
                        hayabusa_run_scan(hayabusa_path, s)
                    return
                try:
                    evtx_folder = subs[int(sel) - 1]
                except (ValueError, IndexError):
                    err("Invalid selection."); return
        else:
            return
    hayabusa_run_scan(hayabusa_path, evtx_folder)

def menu_hayabusa():
    hayabusa_path = _hayabusa_load_path()
    while not os.path.exists(hayabusa_path):
        warn("Hayabusa executable not found.")
        hayabusa_path = _hayabusa_pick_path()
        if not hayabusa_path:
            err("No executable selected."); pause(); return
    _hayabusa_save_path(hayabusa_path)
    while True:
        header("HAYABUSA EVENT LOG SCANNER")
        info(f"Binary: {hayabusa_path}")
        print()
        print(f"  {_c(C.CYAN,'[1]')} Scan folder / mounted image for EVTX files")
        print(f"  {_c(C.RED, '[0]')} Back")
        divider()
        ch = prompt("Choice:").strip()
        if ch == "1": hayabusa_scan_folder(hayabusa_path)
        elif ch == "0": break
        else: err("Invalid choice.")


# ══════════════════════════════════════════════════════════════════
#  SECTION 3 — CHAINSAW SCANNER
# ══════════════════════════════════════════════════════════════════

def _chainsaw_find_evtx(start):
    return _hayabusa_find_evtx(start)   # same logic

def _chainsaw_load_path():
    """Load Chainsaw path from registry"""
    path = RegistryConfig.load_config("Chainsaw", "executable_path", "")
    if path and os.path.exists(path):
        return path
    defaults = [r"C:\Tools\Chainsaw\chainsaw_x86_64-pc-windows-msvc.exe", "chainsaw.exe"]
    for d in defaults:
        if os.path.exists(d):
            return os.path.abspath(d)
    return ""

def _chainsaw_save_path(path):
    """Save Chainsaw path to registry"""
    RegistryConfig.save_config("Chainsaw", "executable_path", path)

def _chainsaw_pick_path():
    return pick_file("Select Chainsaw executable",
                     filetypes=[("Chainsaw", "chainsaw*.exe"), ("All", "*.*")])

def chainsaw_run_scan(chainsaw_path, evtx_folder):
    subheader("Chainsaw Scan")
    info("Select folder to save reports…")
    report_path = pick_folder("Select report destination")
    if not report_path:
        warn("Cancelled."); return
    os.makedirs(report_path, exist_ok=True)
    chainsaw_dir = os.path.dirname(os.path.abspath(chainsaw_path))
    sigma_rules = os.path.join(chainsaw_dir, "rules")
    sigma_map   = os.path.join(chainsaw_dir, "mappings", "sigma-event-logs-all.yml")
    if not os.path.exists(sigma_rules):
        err(f"Sigma rules not found: {sigma_rules}"); pause(); return
    if not os.path.exists(sigma_map):
        err(f"Sigma mappings not found: {sigma_map}"); pause(); return
    folder_name = re.sub(r'[^a-zA-Z0-9_-]', '_', os.path.basename(os.path.normpath(evtx_folder))) or "scan"
    while True:
        case_name = prompt("Case name (e.g. MAL2024-001):").strip()
        if case_name:
            case_name = re.sub(r'[^a-zA-Z0-9_-]', '_', case_name); break
        err("Case name cannot be empty.")
    date_prefix = datetime.now().strftime("%Y%m%d")
    base    = f"{date_prefix}-{folder_name}-{case_name}"
    log_out = os.path.join(report_path, f"{base}-log.txt")
    cmd = [chainsaw_path, "hunt", evtx_folder,
           "-s", "sigma/", "--mapping", sigma_map,
           "-r", sigma_rules, "--csv", "--output", report_path]
    info(f"Scanning:    {evtx_folder}")
    info(f"Sigma rules: {sigma_rules}")
    info(f"Output:      {report_path}")
    print()
    try:
        with open(log_out, "w") as log:
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.PIPE,
                                    universal_newlines=True, cwd=chainsaw_dir)
            _, stderr = proc.communicate()
        if proc.returncode != 0:
            err(f"Scan error (exit {proc.returncode})")
            if stderr: print(f"  {stderr.strip()}")
        else:
            ok("Scan completed successfully!")
            ok(f"Reports: {report_path}")
    except Exception as e:
        err(f"Failed to start Chainsaw: {e}")
    if IS_WINDOWS:
        try: os.startfile(report_path)
        except: pass
    pause()

def chainsaw_scan_folder(chainsaw_path):
    subheader("Select EVTX Folder")
    evtx_folder = pick_folder("Select folder containing EVTX files")
    if not evtx_folder:
        warn("Cancelled."); return
    evtx_files = [f for f in os.listdir(evtx_folder) if f.lower().endswith(".evtx")]
    if not evtx_files:
        warn("No EVTX files in selected folder.")
        if prompt("Search subfolders? (y/n):").lower().startswith("y"):
            subs = _chainsaw_find_evtx(evtx_folder)
            if not subs:
                err("No EVTX files found."); pause(); return
            if len(subs) == 1:
                evtx_folder = subs[0]
            else:
                print()
                for i, s in enumerate(subs, 1):
                    print(f"  {_c(C.CYAN,f'[{i}]')} {s}")
                print(f"  {_c(C.CYAN,'[a]')} All folders")
                sel = prompt("Select:").strip().lower()
                if sel == "a":
                    for s in subs: chainsaw_run_scan(chainsaw_path, s)
                    return
                try:
                    evtx_folder = subs[int(sel) - 1]
                except (ValueError, IndexError):
                    err("Invalid selection."); return
        else:
            return
    chainsaw_run_scan(chainsaw_path, evtx_folder)

def menu_chainsaw():
    chainsaw_path = _chainsaw_load_path()
    while not os.path.exists(chainsaw_path):
        warn("Chainsaw executable not found.")
        chainsaw_path = _chainsaw_pick_path()
        if not chainsaw_path:
            err("No executable selected."); pause(); return
    _chainsaw_save_path(chainsaw_path)
    while True:
        header("CHAINSAW EVENT LOG SCANNER")
        info(f"Binary: {chainsaw_path}")
        print()
        print(f"  {_c(C.CYAN,'[1]')} Scan folder / mounted image for EVTX files")
        print(f"  {_c(C.RED, '[0]')} Back")
        divider()
        ch = prompt("Choice:").strip()
        if ch == "1": chainsaw_scan_folder(chainsaw_path)
        elif ch == "0": break
        else: err("Invalid choice.")


# ══════════════════════════════════════════════════════════════════
#  SECTION 4 — THOR SCANNER
# ══════════════════════════════════════════════════════════════════

def _thor_is_running():
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(["tasklist", "/FI", "IMAGENAME eq thor64-lite.exe"],
                                          stderr=subprocess.DEVNULL, universal_newlines=True)
            return "thor64-lite.exe" in out.lower()
    except:
        pass
    return False

def _thor_drive_type_desc(dt):
    return {0:"Unknown",1:"No Root Dir",2:"Removable",3:"Fixed",4:"Remote",5:"CD-ROM",6:"RAM disk"}.get(dt, f"Type {dt}")

def _thor_get_drives():
    drives = []
    if not IS_WINDOWS:
        return drives
    try:
        out = subprocess.check_output(
            "wmic logicaldisk get DeviceID,VolumeName,Size,DriveType /format:csv",
            stderr=subprocess.DEVNULL, universal_newlines=True, shell=True)
        for line in out.splitlines()[1:]:
            parts = line.strip().split(",")
            if len(parts) >= 5:
                dev   = parts[1]
                label = parts[2] if len(parts) > 2 else ""
                size  = parts[3] if len(parts) > 3 else "0"
                dt    = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0
                if dev and dev.endswith(":"):
                    drives.append((dev, label, size, dt))
        if drives:
            return drives
    except:
        pass
    for letter in string.ascii_uppercase:
        drv = f"{letter}:\\"
        if os.path.exists(drv):
            drives.append((f"{letter}:", "", "0", 0))
    return drives

def _thor_load_path():
    """Load Thor path from registry"""
    path = RegistryConfig.load_config("Thor", "executable_path", "")
    if path and os.path.exists(path):
        return path
    defaults = [r"C:\Tools\Thor\thor64-lite.exe", "thor64-lite.exe", "thor-lite.exe"]
    for d in defaults:
        if os.path.exists(d):
            return os.path.abspath(d)
    return ""

def _thor_save_path(path):
    """Save Thor path to registry"""
    RegistryConfig.save_config("Thor", "executable_path", path)

def menu_thor():
    if IS_WINDOWS and not ctypes.windll.shell32.IsUserAnAdmin():
        err("Thor Scanner requires administrator privileges.")
        pause(); return
    if _thor_is_running():
        err("Another THOR process is currently running — please wait for it to finish.")
        pause(); return
    thor_path = _thor_load_path()
    while not os.path.exists(thor_path):
        warn("Thor executable not found.")
        thor_path = pick_file("Select Thor executable (thor64-lite.exe)",
                              filetypes=[("THOR", "thor*.exe"), ("All", "*.*")])
        if not thor_path:
            err("No executable selected."); pause(); return
        if os.path.isdir(thor_path):
            thor_path = os.path.join(thor_path, "thor64-lite.exe")
    _thor_save_path(thor_path)
    thor_dir = os.path.dirname(os.path.abspath(thor_path))

    # Update signatures
    subheader("Updating THOR Signatures")
    util = os.path.join(thor_dir, "thor-lite-util.exe")
    if os.path.exists(util):
        spinner("Running signature update…", 1)
        try:
            subprocess.run([util, "upgrade"], check=True, stdout=subprocess.DEVNULL)
            ok("Signatures updated.")
        except subprocess.CalledProcessError:
            warn("Signature update failed — continuing anyway.")
    else:
        warn("thor-lite-util.exe not found — skipping update.")
    time.sleep(1)

    while True:
        header("THOR SCANNER  —  DRIVE SELECTION")
        drives = _thor_get_drives()
        if not drives:
            err("No drives detected."); pause(); return
        print()
        for i, (dev, label, size, dt) in enumerate(drives, 1):
            desc = _thor_drive_type_desc(dt)
            lbl  = f"  [{label}]" if label else ""
            print(f"  {_c(C.CYAN,f'[{i}]')} {dev}{lbl}  {_c(C.DIM, desc)}")
        print()
        info("Enter one drive number or several separated by commas (e.g. 1,3)")
        raw = prompt("Drive selection:").strip()
        selected = []
        bad = False
        for part in raw.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(drives):
                    selected.append(drives[idx][0])
                else:
                    err(f"Invalid option: {part}"); bad = True
            elif part:
                err(f"Invalid input: '{part}'"); bad = True
        if bad or not selected:
            warn("Please make a valid selection."); pause(); continue
        break

    info("Select folder to save reports…")
    report_path = pick_folder("Select report destination")
    if not report_path:
        err("No report folder selected."); pause(); return
    os.makedirs(report_path, exist_ok=True)

    case_names = []
    for drv in selected:
        while True:
            cn = prompt(f"Case name for drive {drv} (e.g. MAL2024-001):").strip()
            if cn:
                case_names.append(cn); break
            err("Case name cannot be empty.")

    perf = prompt("Use all threads for max performance? (y/n):").lower().startswith("y")

    subheader("Running THOR Scans")
    for i, drv in enumerate(selected):
        date   = datetime.now().strftime("%Y%m%d")
        letter = drv[0]
        cn     = case_names[i]
        csv_f  = os.path.join(report_path, f"{date}-{cn}-drive({letter})_files_md5s.csv")
        html_f = os.path.join(report_path, f"{date}-{cn}-drive({letter})_thor_scan.html")
        log_f  = os.path.join(report_path, f"{date}-{cn}-drive({letter})_thor_log.txt")
        info(f"Scanning {drv}  [case: {cn}]")
        cmd = [thor_path, "-a", "Filescan", "--intense", "--norescontrol",
               "--nosoft", "--cross-platform", "--rebase-dir", report_path,
               "--alldrives", "-p", drv,
               "--csvfile", csv_f, "--htmlfile", html_f, "--logfile", log_f]
        if perf:
            cmd.extend(["--threads", "0"])
        try:
            subprocess.run(cmd, check=True)
            ok(f"Scan complete: {drv}")
        except subprocess.CalledProcessError as e:
            err(f"Error scanning {drv}: {e}")
    ok(f"All scans complete. Reports saved to: {report_path}")
    if IS_WINDOWS:
        try: os.startfile(report_path)
        except: pass
    pause()


# ══════════════════════════════════════════════════════════════════
#  SECTION 5 — SPLUNK INDEX MANAGER
# ══════════════════════════════════════════════════════════════════
DEFAULT_SPLUNK_PATHS = [
    "/opt/splunk/bin/splunk",
    r"C:\Program Files\Splunk\bin\splunk.exe",
    "/Applications/Splunk/bin/splunk",
]

class SplunkManager:
    def __init__(self):
        self.splunk_path = ""
        self.username    = ""
        self.password    = ""
        self._load_config()
        self._verify()

    def _load_config(self):
        """Load Splunk config from registry"""
        self.splunk_path = RegistryConfig.load_config("Splunk", "splunk_path", "")
        self.username = RegistryConfig.load_config("Splunk", "username", "")
        self.password = RegistryConfig.load_config("Splunk", "password", "")
        
        if not self.splunk_path or not os.path.exists(self.splunk_path):
            self._pick_splunk_path()
        if not self.username or not self.password:
            self._pick_creds()
        self._save_config()

    def _save_config(self):
        """Save Splunk config to registry"""
        RegistryConfig.save_config("Splunk", "splunk_path", self.splunk_path)
        RegistryConfig.save_config("Splunk", "username", self.username)
        RegistryConfig.save_config("Splunk", "password", self.password)

    def _pick_splunk_path(self):
        root = tk.Tk(); root.withdraw()
        for p in DEFAULT_SPLUNK_PATHS:
            if os.path.exists(p):
                if messagebox.askyesno("Splunk Found", f"Use Splunk at:\n{p}?"):
                    self.splunk_path = p; root.destroy(); return
        messagebox.showinfo("Splunk Path", "Select the Splunk binary.")
        self.splunk_path = filedialog.askopenfilename(title="Select Splunk binary")
        root.destroy()

    def _pick_creds(self):
        print()
        warn("Splunk credentials required.")
        self.username = prompt("Splunk username:").strip()
        self.password = getpass.getpass(f"  {_c(C.MAGENTA, C.ARROW)} Splunk password: ")

    def _run(self, args):
        try:
            r = subprocess.run([self.splunk_path] + args, capture_output=True, text=True,
                               shell=IS_WINDOWS,
                               env={**os.environ, "SPLUNK_CLI_SERVER_CERT_VERIFY": "0"})
            def fil(t):
                return "\n".join(l for l in t.split("\n") if "Server Certificate Hostname Validation" not in l)
            return fil(r.stdout) + fil(r.stderr)
        except Exception as e:
            err(f"Splunk command error: {e}"); return None

    def _verify(self):
        if not os.path.exists(self.splunk_path):
            err("Splunk binary not found."); self._pick_splunk_path(); self._save_config()
        spinner("Verifying Splunk connection…", 2)
        result = self._run(["login", "-auth", f"{self.username}:{self.password}"])
        if result is None or "Login failed" in (result or ""):
            err("Login failed."); self._pick_creds(); self._save_config(); self._verify()
        else:
            ok(f"Connected to Splunk → http://127.0.0.1:8000/")
            info(f"Binary: {self.splunk_path}  |  User: {self.username}")

    def _splunk_db(self):
        return os.path.join(os.path.dirname(os.path.dirname(self.splunk_path)), "var", "lib", "splunk")

    def _index_size(self, name):
        path = os.path.join(self._splunk_db(), name)
        if not os.path.exists(path): return 0
        total = 0
        for dp, _, fns in os.walk(path):
            for fn in fns:
                try: total += os.path.getsize(os.path.join(dp, fn))
                except: pass
        return total

    def _fmt_size(self, b):
        mb = b / 1_048_576
        return f"{mb/1024:.1f} GB" if mb > 2000 else f"{mb:.1f} MB"

    def list_indexes(self, exclude_system=True):
        spinner("Fetching indexes…", 1.5)
        result = self._run(["list", "index", "-auth", f"{self.username}:{self.password}"])
        if not result: return []
        excl = {"_", "summary", "splunklogger", "main", "history"} if exclude_system else set()
        out = []
        for line in result.split("\n"):
            line = line.strip()
            if not line or "\\" in line or "/" in line: continue
            if any(line.lower().startswith(e) for e in excl): continue
            out.append(f"{line} - {self._fmt_size(self._index_size(line))}")
        return out

    def index_exists(self, name):
        r = self._run(["list", "index", "-auth", f"{self.username}:{self.password}"])
        return bool(r and name in r)

    def create_index(self, name):
        spinner(f"Creating index '{name}'…", 1.5)
        result = self._run(["add", "index", name, "-auth", f"{self.username}:{self.password}"])
        if result is None: return False, "Command failed."
        norm = " ".join(result.lower().split())
        if any(p in norm for p in ["created","added","already exists","index created"]):
            return True, f"Index '{name}' created."
        if "error" in norm or "failed" in norm: return False, f"Splunk error: {result.strip()}"
        return False, f"Unexpected response: {result.strip()}"

    def delete_index(self, name):
        spinner(f"Deleting index '{name}'…", 1.5)
        result = self._run(["remove", "index", name, "-auth", f"{self.username}:{self.password}"])
        if result is None: return False, "Command failed."
        norm = " ".join(result.lower().split())
        if (any(p in norm for p in ["removed","deleted","removal of index","successfully"]) or
                (IS_WINDOWS and "admin handler not found" in norm)):
            self._remove_from_indexes_conf(name)
            return True, f"Index '{name}' deleted."
        if "error" in norm or "failed" in norm: return False, f"Splunk error: {result.strip()}"
        return False, f"Unexpected response: {result.strip()}"

    def _conf_path(self, fname):
        base = os.path.dirname(os.path.dirname(self.splunk_path))
        for p in [os.path.join(base,"etc","system","local",fname),
                  os.path.join(base,"etc","apps","search","local",fname),
                  os.path.join(base,"etc","system","default",fname)]:
            if os.path.exists(p): return p
        return None

    def _remove_from_indexes_conf(self, name):
        conf = self._conf_path("indexes.conf")
        if not conf:
            root = tk.Tk(); root.withdraw()
            messagebox.showinfo("indexes.conf", "Could not auto-locate indexes.conf.")
            conf = filedialog.askopenfilename(title="Select indexes.conf", filetypes=[("Config","*.conf")])
            root.destroy()
            if not conf: return False
        try:
            content = open(conf).read()
            start = content.find(f"[{name}]")
            if start == -1: return True
            end = content.find("\n[", start)
            end = len(content) if end == -1 else content.rfind("\n", start, end)
            open(conf,"w").write(content[:start] + content[end:])
            info(f"Removed [{name}] from {conf}")
            return True
        except Exception as e:
            warn(f"Could not update indexes.conf: {e}"); return False

    def _update_indexes_conf(self, name):
        spinner(f"Updating indexes.conf for '{name}'…", 1)
        conf = self._conf_path("indexes.conf")
        if not conf:
            root = tk.Tk(); root.withdraw()
            messagebox.showinfo("indexes.conf","Could not auto-locate indexes.conf.")
            conf = filedialog.askopenfilename(title="Select indexes.conf",filetypes=[("Config","*.conf")])
            root.destroy()
            if not conf: return False
        block = (f"\n[{name}]\ncoldPath = $SPLUNK_DB\\{name}\\colddb\n"
                 f"enableDataIntegrityControl = 0\nenableTsidxReduction = 0\n"
                 f"homePath = $SPLUNK_DB\\{name}\\db\nmaxTotalDataSizeMB = 512000\n"
                 f"thawedPath = $SPLUNK_DB\\{name}\\thaweddb\n")
        try:
            content = open(conf).read()
            if f"[{name}]" in content:
                start = content.find(f"[{name}]")
                end   = content.find("\n\n", start)
                end   = len(content) if end == -1 else end
                content = content[:start] + block + content[end:]
            else:
                content += block
            open(conf,"w").write(content)
            ok(f"indexes.conf updated: {conf}"); return True
        except Exception as e:
            warn(f"Could not update indexes.conf: {e}"); return False

    def _add_monitor_to_inputs_conf(self, folder, index):
        base      = os.path.dirname(os.path.dirname(self.splunk_path))
        conf_dir  = os.path.join(base,"etc","apps","search","local")
        conf_path = os.path.join(conf_dir,"inputs.conf")
        os.makedirs(conf_dir, exist_ok=True)
        mon = os.path.normpath(folder)
        hdr = f"[monitor://{mon}]"
        try:
            if os.path.exists(conf_path):
                content = open(conf_path, encoding="utf-8").read()
                if hdr in content:
                    lines = content.splitlines()
                    in_s = False; cur_idx = None
                    for line in lines:
                        s = line.strip()
                        if s.startswith("[") and s.endswith("]"):
                            in_s = (s == hdr)
                        if in_s and s.startswith("index ="):
                            cur_idx = s.split("=",1)[1].strip()
                    if cur_idx == index:
                        warn(f"Monitor already exists with index '{index}'."); return True
                    if cur_idx:
                        new = []
                        in_s = False
                        for line in lines:
                            s = line.strip()
                            if s.startswith("[") and s.endswith("]"):
                                in_s = (s == hdr)
                            new.append(f"index = {index}" if in_s and s.startswith("index =") else line)
                        open(conf_path,"w",encoding="utf-8").write("\n".join(new))
                        ok(f"Updated monitor index → '{index}'"); return True
            stanza = f"\n[monitor://{mon}]\ndisabled = false\nhost = dfir-server\nindex = {index}\n"
            open(conf_path,"a",encoding="utf-8").write(stanza)
            ok(f"Monitor added → {mon}  (index: {index})")
            info(f"Config: {conf_path}"); return True
        except Exception as e:
            err(f"Failed to update inputs.conf: {e}"); return False

    def _reload_monitor_inputs(self):
        spinner("Reloading monitor inputs…", 1.5)
        result = self._run(["_internal","call","/services/data/inputs/monitor/_reload",
                            "-auth", f"{self.username}:{self.password}"])
        if result and ("200" in result or "success" in result.lower() or "reload" in result.lower()):
            ok("Monitor inputs reloaded."); return True
        warn("Reload response unexpected — check Splunk manually."); return False

    def _open_web(self, index=None):
        if index:
            url = (f"http://localhost:8000/en-US/app/search/search?"
                   f"q=search%20index%3D%22{index.replace(chr(34),'%22')}%22&earliest=0&latest=")
        else:
            url = "http://127.0.0.1:8000"
        info(f"Opening → {url}")
        try:
            webbrowser.open(url, new=2); ok("Splunk Web opened.")
        except Exception as e:
            err(f"Could not open browser: {e}")
            print(f"\n  Open manually: {_c(C.GREEN, url)}")

    def backup_index(self, name, backup_dir, password=None):
        db     = self._splunk_db()
        folder = os.path.join(db, name)
        dat    = os.path.join(db, f"{name}.dat")
        if not os.path.exists(folder) and not os.path.exists(dat):
            return False, "No index data found on disk."
        os.makedirs(backup_dir, exist_ok=True)
        stamp    = time.strftime("%Y%m%d-%H%M%S")
        zip_path = os.path.join(backup_dir, f"{name}_backup_{stamp}.zip")
        all_files = []
        if os.path.exists(dat):
            all_files.append((dat, os.path.basename(dat)))
        if os.path.exists(folder):
            for dp, _, fns in os.walk(folder):
                for fn in fns:
                    fp  = os.path.join(dp, fn)
                    arc = os.path.join(os.path.basename(folder), os.path.relpath(fp, folder))
                    all_files.append((fp, arc))
        total = len(all_files)
        print()
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                if password:
                    zf.setpassword(password.encode()); warn("Using standard ZIP encryption.")
                for i, (fp, arc) in enumerate(all_files, 1):
                    zf.write(fp, arc); progress_bar(i, total, label=os.path.basename(fp))
            print()
            return True, f"Backup → {zip_path}"
        except Exception as e:
            return False, f"Backup failed: {e}"

    def restore_backup(self, backup_file):
        spinner("Preparing restore…", 1)
        db = self._splunk_db()
        if not os.path.exists(backup_file): return False, "Backup file not found."
        is_enc = False
        try:
            with zipfile.ZipFile(backup_file,"r") as z:
                try: z.testzip()
                except RuntimeError as e:
                    if "encrypted" in str(e): is_enc = True
        except Exception as e:
            return False, f"Cannot read backup: {e}"
        pw = None
        if is_enc:
            warn("Backup is password protected.")
            pw = getpass.getpass(f"  {_c(C.MAGENTA, C.ARROW)} Backup password: ").encode("utf-8")
        try:
            index_name = os.path.basename(backup_file).split("_backup_")[0]
            use_pz = False
            if is_enc:
                try: import pyzipper; use_pz = True
                except ImportError: warn("pyzipper unavailable — trying standard zipfile.")
            def _extract(zref):
                names = zref.namelist()
                total = len(names)
                print()
                for i, fn in enumerate(names, 1):
                    try: zref.extract(fn, db)
                    except RuntimeError as e:
                        if "Bad password" in str(e): raise ValueError("Incorrect password.")
                    progress_bar(i, total, label=fn)
                print()
            if use_pz:
                import pyzipper
                with pyzipper.AESZipFile(backup_file,"r") as zf:
                    if pw: zf.setpassword(pw)
                    _extract(zf)
            else:
                with zipfile.ZipFile(backup_file,"r") as zf:
                    if pw: zf.setpassword(pw)
                    _extract(zf)
            if not self.index_exists(index_name):
                info(f"Creating index '{index_name}'…")
                ok_flag, msg = self.create_index(index_name)
                if not ok_flag: return False, f"Restore failed: {msg}"
            self._update_indexes_conf(index_name)
            return True, (f"Restore complete!\n  Index: {index_name}\n  Location: {db}\n"
                          "  Note: Restart Splunk if changes don't appear.")
        except ValueError as ve:
            return False, str(ve)
        except Exception as e:
            return False, f"Restore failed: {e}"

    # ── Submenus ──────────────────────────────────────────────────
    def _menu_create_index(self):
        subheader("Create Index + Monitor Folder")
        name = prompt("New index name:").strip()
        if not name: err("Name cannot be empty."); return
        ok_flag, msg = self.create_index(name)
        if not ok_flag: err(msg); return
        ok(msg)
        if prompt("Monitor a folder for this index now? (y/n):").lower().startswith("y"):
            folder = pick_folder(f"Monitor folder → index: {name}")
            if folder:
                self._add_monitor_to_inputs_conf(folder, name)
                self._reload_monitor_inputs()
                self._open_web(name)
            else:
                warn("Folder selection cancelled.")

    def _menu_monitor_folder(self):
        subheader("Monitor Folder (Existing Index)")
        indexes = self.list_indexes()
        if not indexes: warn("No non-system indexes found."); return
        print()
        for i, idx in enumerate(indexes, 1):
            print(f"  {_c(C.CYAN,f'[{i}]')} {idx}")
        print(f"  {_c(C.RED,'[0]')} Back")
        print()
        raw = prompt("Select index:").strip()
        if raw == "0": return
        try:
            chosen = indexes[int(raw) - 1]
            index_name = chosen.split(" - ")[0].strip()
        except (ValueError, IndexError):
            err("Invalid selection."); return
        folder = pick_folder(f"Monitor folder → index: {index_name}")
        if folder:
            self._add_monitor_to_inputs_conf(folder, index_name)
            self._reload_monitor_inputs()
            self._open_web(index_name)
        else:
            warn("Cancelled.")

    def _menu_manage_indexes(self):
        subheader("Manage Indexes")
        indexes = self.list_indexes()
        if not indexes: warn("No non-system indexes found."); return
        print()
        for i, idx in enumerate(indexes, 1):
            print(f"  {_c(C.CYAN,f'[{i}]')} {idx}")
        print(f"  {_c(C.RED,'[0]')} Back")
        print()
        raw = prompt("Select index to manage:").strip()
        if raw == "0": return
        try:
            chosen = indexes[int(raw) - 1]
        except (ValueError, IndexError):
            err("Invalid selection."); return
        self._index_ops(chosen)

    def _index_ops(self, display):
        name = display.split(" - ")[0].strip()
        while True:
            subheader(f"Operations → {display}")
            print(f"  {_c(C.CYAN,'[1]')} Delete index")
            print(f"  {_c(C.CYAN,'[2]')} Backup index")
            print(f"  {_c(C.CYAN,'[3]')} Backup + Delete")
            print(f"  {_c(C.RED, '[0]')} Back")
            print()
            ch = prompt("Action:").strip()
            if ch == "1":
                if prompt(f"{_c(C.RED,'Permanently delete')} '{name}'? (y/n):").lower().startswith("y"):
                    ok_flag, msg = self.delete_index(name)
                    ok(msg) if ok_flag else err(msg)
                else:
                    warn("Cancelled.")
                break
            elif ch == "2":
                self._backup_flow(name); break
            elif ch == "3":
                if self._backup_flow(name):
                    if prompt(f"{_c(C.RED,'Now permanently delete')} '{name}'? (y/n):").lower().startswith("y"):
                        ok_flag, msg = self.delete_index(name)
                        ok(msg) if ok_flag else err(msg)
                    else:
                        warn("Deletion cancelled.")
                break
            elif ch == "0": break
            else: err("Invalid choice.")

    def _backup_flow(self, name):
        info("Select backup destination…")
        raw = prompt("Enter path (blank to browse):").strip()
        bdir = raw or pick_folder("Select backup directory")
        if not bdir: warn("Cancelled."); return False
        pw = None
        if prompt("Password-protect backup? (y/n):").lower().startswith("y"):
            pw = getpass.getpass(f"  {_c(C.MAGENTA, C.ARROW)} Backup password: ")
        ok_flag, msg = self.backup_index(name, bdir, pw)
        ok(msg) if ok_flag else err(msg)
        return ok_flag

    def _menu_restore(self):
        subheader("Restore from Backup")
        bfile = pick_file("Select backup ZIP", [("ZIP","*.zip")])
        if not bfile: warn("Cancelled."); return
        if not yesno_dialog("Confirm Restore","WARNING: This will overwrite existing index data.\n\nContinue?"):
            warn("Cancelled."); return
        ok_flag, msg = self.restore_backup(bfile)
        ok(msg) if ok_flag else err(msg)

    def main_menu(self):
        while True:
            header("SPLUNK INDEX MANAGER")
            print(f"\n  {_c(C.CYAN,'[1]')} Create index + monitor folder")
            print(f"  {_c(C.CYAN,'[2]')} Monitor folder (existing index)")
            print(f"  {_c(C.CYAN,'[3]')} Manage indexes")
            print(f"  {_c(C.CYAN,'[4]')} Restore from backup")
            print(f"  {_c(C.CYAN,'[5]')} Open Splunk Web")
            print(f"  {_c(C.RED, '[0]')} Back")
            divider()
            ch = prompt("Choice:").strip()
            if   ch == "1": self._menu_create_index()
            elif ch == "2": self._menu_monitor_folder()
            elif ch == "3": self._menu_manage_indexes()
            elif ch == "4": self._menu_restore()
            elif ch == "5": self._open_web()
            elif ch == "0": break
            else: err("Invalid choice.")
            pause()

def menu_splunk():
    try:
        mgr = SplunkManager()
        mgr.main_menu()
    except KeyboardInterrupt:
        warn("Splunk section interrupted.")


# ══════════════════════════════════════════════════════════════════
#  SECTION 6 — CSV → ELASTICSEARCH (CSV2ELK)
# ══════════════════════════════════════════════════════════════════

# Lazy-import pandas and requests only when this section runs
def _elk_load_heavy():
    try:
        import requests as _req
        import pandas as _pd
        return _req, _pd
    except ImportError as e:
        err(f"Missing dependency: {e}")
        info("Install with:  pip install requests pandas tqdm")
        return None, None

def _elk_load_config():
    """Load ELK config from registry"""
    config = {
        "url": RegistryConfig.load_config("Elasticsearch", "url", ""),
        "username": RegistryConfig.load_config("Elasticsearch", "username", ""),
        "password": RegistryConfig.load_config("Elasticsearch", "password", "")
    }
    return config

def _elk_save_config(url, user, pw):
    """Save ELK config to registry"""
    RegistryConfig.save_config("Elasticsearch", "url", url)
    RegistryConfig.save_config("Elasticsearch", "username", user)
    RegistryConfig.save_config("Elasticsearch", "password", pw)

def _elk_ensure_connection(cfg, req):
    url, user, pw = cfg["url"], cfg["username"], cfg["password"]
    while True:
        try:
            r = req.get(f"{url}/_cluster/health", auth=(user, pw), verify=False, timeout=5)
            if r.status_code == 200:
                ok(f"Connected to Elasticsearch at {url}")
                _elk_save_config(url, user, pw)
                return url, user, pw
            elif r.status_code == 401:
                err("Authentication failed.")
                user = prompt("Username:").strip()
                pw   = getpass.getpass(f"  {_c(C.MAGENTA, C.ARROW)} Password: ")
            else:
                err(f"Connection error {r.status_code}")
                url = prompt("Elasticsearch URL (e.g. https://host:9200):").strip()
        except Exception as e:
            err(f"Cannot reach {url}: {e}")
            url = prompt("Elasticsearch URL:").strip()

def _elk_sanitize_index(name):
    name = name.lower()
    name = re.sub(r'\s+', '_', name)
    name = re.sub(r'[^a-z0-9_]', '', name)
    return name

def _elk_sanitize_col(name):
    name = name.replace('.', '_')
    return re.sub(r'[^\w@#]', '_', name)

def _elk_date_from_index(name):
    m = re.search(r'_(\d{8})$', name)
    return m.group(1) if m else "00000000"

def _elk_get_indices(url, user, pw, req):
    r = req.get(f"{url}/_cat/indices?h=index,docs.count,store.size&format=json",
                auth=(user, pw), verify=False)
    if r.status_code == 200:
        return [i for i in r.json() if not (i["index"].startswith(".") or i["index"].startswith("log"))]
    err("Error retrieving index info."); return []

def _elk_create_index(url, user, pw, base_name, req):
    base_name = _elk_sanitize_index(base_name)
    today = datetime.today().strftime("%Y%m%d")
    index_name = f"{base_name}_{today}"
    mapping = {"mappings": {"properties": {"timestamp_field": {"type": "date"}}}}
    r = req.put(f"{url}/{index_name}", auth=(user, pw),
                headers={"Content-Type": "application/json"},
                data=json.dumps(mapping), verify=False)
    if r.status_code == 200:
        ok(f"Index '{index_name}' created.")
    else:
        err(f"Failed to create index: {r.status_code} — {r.text}")
    return index_name

def _elk_guess_ts(columns):
    priority = ["timestamp","@timestamp","time","datetime","date"]
    for p in priority:
        for col in columns:
            if re.search(p, col, re.IGNORECASE):
                return col
    return None

def _elk_select_ts(df):
    print("\n  CSV columns with sample values:")
    if df.empty: warn("DataFrame is empty."); return None
    sample = df.iloc[0].to_dict()
    for i, col in enumerate(df.columns, 1):
        print(f"  {_c(C.CYAN,str(i))}. {col}  {_c(C.DIM, str(sample.get(col,''))[:60])}")
    guess = _elk_guess_ts(df.columns)
    if guess:
        info(f"Suggested timestamp column: {guess}")
    while True:
        sel = prompt(f"Select timestamp column [Enter = '{guess}']:").strip()
        if sel == "" and guess:
            return guess
        try:
            return df.columns[int(sel) - 1]
        except (ValueError, IndexError):
            err("Invalid selection.")

def _elk_convert_csv(csv_path, index_name, ts_col, pd):
    try:
        df = pd.read_csv(csv_path, encoding="utf-8", low_memory=False, on_bad_lines="warn")
        df = df.where(pd.notnull(df), None)
        seen = {}
        dedup_cols = []
        for col in df.columns:
            if col not in seen:
                seen[col] = 0; dedup_cols.append(col)
            else:
                seen[col] += 1; dedup_cols.append(f"{col}_{seen[col]}")
        df.columns = dedup_cols
        df.columns = [_elk_sanitize_col(c) for c in df.columns]

        def clean(obj):
            if isinstance(obj, dict): return {k: clean(v) for k, v in obj.items()}
            if isinstance(obj, list): return [clean(v) for v in obj]
            if isinstance(obj, float):
                if pd.isna(obj) or obj in (float("inf"), float("-inf")): return None
            return obj

        json_path = csv_path.replace(".csv", ".json")
        total = len(df)
        print()
        with open(json_path, "w", encoding="utf-8") as f:
            for i, (_, row) in enumerate(df.iterrows(), 1):
                action = {"index": {"_index": index_name}}
                f.write(json.dumps(action, ensure_ascii=False) + "\n")
                row_dict = row.to_dict()
                if ts_col and ts_col in row_dict:
                    tv = row_dict[ts_col]
                    if pd.notna(tv) and str(tv).strip():
                        try:
                            tf = float(tv)
                            iso = (datetime.utcfromtimestamp(tf/1000 if tf > 1e12 else tf).isoformat() + "Z")
                            row_dict["timestamp_field"] = iso
                        except:
                            try:
                                row_dict["timestamp_field"] = pd.to_datetime(tv, utc=True).isoformat()
                            except: pass
                f.write(json.dumps(clean(row_dict), ensure_ascii=False) + "\n")
                if i % 500 == 0 or i == total:
                    progress_bar(i, total, label="Converting CSV")
        print()
        ok(f"CSV converted → {json_path}")
        return json_path
    except Exception as e:
        err(f"CSV conversion failed: {e}"); return None

def _elk_upload(url, user, pw, index_name, json_path, req):
    info("Uploading to Elasticsearch in chunks…")
    chunk_size = 10000
    def chunks():
        with open(json_path, "r", encoding="utf-8") as f:
            chunk = []
            for i, line in enumerate(f, 1):
                chunk.append(line)
                if i % chunk_size == 0:
                    yield "".join(chunk); chunk = []
            if chunk: yield "".join(chunk)
    all_chunks = list(chunks())
    total = len(all_chunks)
    print()
    success = True
    for i, chunk in enumerate(all_chunks, 1):
        progress_bar(i, total, label="Uploading chunks")
        for attempt in range(1, 31):
            try:
                r = req.post(f"{url}/{index_name}/_bulk", auth=(user, pw),
                             headers={"Content-Type":"application/x-ndjson"},
                             data=chunk.encode("utf-8"), verify=False, timeout=10)
                if r.status_code in (200, 201):
                    break
                if attempt == 30:
                    success = False; break
                time.sleep(1)
            except req.exceptions.RequestException:
                if attempt == 30: success = False; break
                time.sleep(1)
        if not success: break
    print()
    try: os.remove(json_path)
    except: pass
    ok("All chunks uploaded.") if success else err("Upload completed with errors.")

def _elk_delete_index(url, user, pw, index_name, req):
    r = req.delete(f"{url}/{index_name}", auth=(user, pw), verify=False)
    if r.status_code == 200:
        ok(f"Index '{index_name}' deleted.")
    else:
        err(f"Failed to delete: {r.status_code} — {r.text}")

def _elk_pick_index(url, user, pw, req):
    indices = _elk_get_indices(url, user, pw, req)
    if not indices: warn("No eligible indexes found."); return None
    indices.sort(key=lambda x: _elk_date_from_index(x["index"]))
    print()
    print(f"  {_c(C.RED,'[0]')} Return to menu")
    for i, e in enumerate(indices, 1):
        docs = f"{int(e['docs.count']):,}"
        print(f"  {_c(C.CYAN,f'[{i}]')} {e['index']}  {_c(C.DIM, docs + ' docs  ' + e['store.size'])}")
    print()
    raw = prompt("Select index:").strip()
    if raw == "0": return None
    try: return indices[int(raw) - 1]["index"]
    except (ValueError, IndexError):
        err("Invalid selection."); return None

def menu_csv2elk():
    req, pd = _elk_load_heavy()
    if not req or not pd:
        pause(); return
    try:
        import requests as req
        req.packages.urllib3.disable_warnings()
    except: pass

    cfg = _elk_load_config()
    if not cfg["url"]:
        subheader("Elasticsearch Configuration")
        cfg["url"]      = prompt("Elasticsearch URL (e.g. https://host:9200):").strip()
        cfg["username"] = prompt("Username:").strip()
        cfg["password"] = getpass.getpass(f"  {_c(C.MAGENTA, C.ARROW)} Password: ")

    url, user, pw = _elk_ensure_connection(cfg, req)

    while True:
        header("CSV → ELASTICSEARCH")
        print(f"\n  {_c(C.DIM,'Endpoint:')} {_c(C.YELLOW, url)}\n")
        print(f"  {_c(C.CYAN,'[1]')} Create new index + upload CSV")
        print(f"  {_c(C.CYAN,'[2]')} Upload CSV to existing index")
        print(f"  {_c(C.CYAN,'[3]')} Delete index")
        print(f"  {_c(C.RED, '[0]')} Back")
        divider()
        ch = prompt("Choice:").strip()

        if ch == "1":
            base  = prompt("New index name (case/project name):").strip()
            idx   = _elk_create_index(url, user, pw, base, req)
            fpath = pick_file("Select CSV file", [("CSV","*.csv")])
            if not fpath: warn("No file selected."); continue
            df = pd.read_csv(fpath, encoding="utf-8", low_memory=False, on_bad_lines="warn")
            df = df.where(pd.notnull(df), None)
            ts_col = _elk_select_ts(df)
            jpath  = _elk_convert_csv(fpath, idx, ts_col, pd)
            if jpath: _elk_upload(url, user, pw, idx, jpath, req)

        elif ch == "2":
            idx = _elk_pick_index(url, user, pw, req)
            if not idx: continue
            fpath = pick_file("Select CSV file", [("CSV","*.csv")])
            if not fpath: warn("No file selected."); continue
            df = pd.read_csv(fpath, encoding="utf-8", low_memory=False, on_bad_lines="warn")
            df = df.where(pd.notnull(df), None)
            ts_col = _elk_select_ts(df)
            jpath  = _elk_convert_csv(fpath, idx, ts_col, pd)
            if jpath: _elk_upload(url, user, pw, idx, jpath, req)

        elif ch == "3":
            idx = _elk_pick_index(url, user, pw, req)
            if not idx: continue
            if prompt(f"Delete '{idx}'? (y/n):").lower().startswith("y"):
                _elk_delete_index(url, user, pw, idx, req)
            else:
                warn("Cancelled.")

        elif ch == "0": break
        else: err("Invalid choice.")
        pause()


# ══════════════════════════════════════════════════════════════════
#  SECTION 7 — SFTP/FTP MONITOR
# ══════════════════════════════════════════════════════════════════

def _sftp_load_heavy():
    try:
        import paramiko as _pm
        from watchdog.observers import Observer as _Obs
        from watchdog.events import FileSystemEventHandler as _FSH
        from tqdm import tqdm as _tqdm
        return _pm, _Obs, _FSH, _tqdm
    except ImportError as e:
        err(f"Missing dependency: {e}")
        info("Install with:  pip install paramiko watchdog tqdm")
        return None, None, None, None

class _FTPClient:
    def __init__(self, host, username, password, port=22, use_sftp=True, pm=None):
        self.host = host; self.username = username; self.password = password
        self.port = port; self.use_sftp = use_sftp; self.connection = None
        self._pm = pm  # paramiko module

    def connect(self):
        try:
            if self.use_sftp:
                self.connection = self._pm.Transport((self.host, self.port))
                self.connection.connect(username=self.username, password=self.password)
                self.sftp = self._pm.SFTPClient.from_transport(self.connection)
                ok(f"Connected to SFTP server {self.host}:{self.port}")
            else:
                import ftplib
                self.connection = ftplib.FTP()
                self.connection.connect(self.host, self.port)
                self.connection.login(self.username, self.password)
                ok(f"Connected to FTP server {self.host}:{self.port}")
            return True
        except Exception as e:
            err(f"Connection failed: {e}"); return False

    def disconnect(self):
        if self.connection:
            try:
                (self.connection.close if self.use_sftp else self.connection.quit)()
            except: pass
            info("Disconnected from server.")

    def list_files(self, remote_path):
        try:
            return self.sftp.listdir(remote_path) if self.use_sftp else self.connection.nlst(remote_path)
        except Exception as e:
            err(f"Error listing files: {e}"); return []

    def list_folders(self, remote_path="."):
        items = self.list_files(remote_path)
        folders = []
        for item in items:
            if item in [".", ".."]: continue
            try:
                if self.use_sftp:
                    p = os.path.join(remote_path, item).replace("\\", "/")
                    if self.sftp.stat(p).st_mode & 0o40000:
                        folders.append(item)
                else:
                    folders.append(item)
            except: continue
        return folders

    def get_file_size(self, remote_path):
        try:
            return self.sftp.stat(remote_path).st_size if self.use_sftp else self.connection.size(remote_path)
        except: return -1

    def file_exists(self, remote_path):
        try:
            (self.sftp.stat if self.use_sftp else self.connection.size)(remote_path)
            return True
        except: return False

    def download_file(self, remote_path, local_path, logger, tqdm):
        try:
            if self.use_sftp:
                size = self.sftp.stat(remote_path).st_size
                with tqdm(total=size, unit="B", unit_scale=True, desc="  Downloading") as pb:
                    def cb(tx, tot): pb.total = tot; pb.update(tx - pb.n)
                    self.sftp.get(remote_path, local_path, callback=cb)
            else:
                size = self.connection.size(remote_path)
                with open(local_path, "wb") as f:
                    with tqdm(total=size, unit="B", unit_scale=True, desc="  Downloading") as pb:
                        def cb(data): f.write(data); pb.update(len(data))
                        self.connection.retrbinary(f"RETR {remote_path}", cb)
            ok(f"Downloaded: {os.path.basename(local_path)}")
            logger.info(f"DOWNLOADED: {os.path.basename(local_path)}")
            return True
        except Exception as e:
            err(f"Download failed: {e}"); logger.error(f"DOWNLOAD FAILED: {e}"); return False

    def upload_file(self, local_path, remote_path, logger, tqdm):
        try:
            size = os.path.getsize(local_path)
            if self.use_sftp:
                with tqdm(total=size, unit="B", unit_scale=True, desc="  Uploading") as pb:
                    def cb(tx, tot): pb.total = tot; pb.update(tx - pb.n)
                    self.sftp.put(local_path, remote_path, callback=cb)
            else:
                with open(local_path, "rb") as f:
                    with tqdm(total=size, unit="B", unit_scale=True, desc="  Uploading") as pb:
                        def cb(data): pb.update(len(data))
                        self.connection.storbinary(f"STOR {remote_path}", f, callback=cb)
            ok(f"Uploaded: {os.path.basename(local_path)}")
            logger.info(f"UPLOADED: {os.path.basename(local_path)}")
            return True
        except Exception as e:
            err(f"Upload failed: {e}"); logger.error(f"UPLOAD FAILED: {e}"); return False


def _sftp_select_remote_folder(client):
    root = tk.Tk()
    root.title("Select Remote Folder")
    root.geometry("620x500")
    root.configure(bg="#1e1e2e")
    style = ttk.Style(); style.theme_use("clam")
    style.configure("TFrame", background="#1e1e2e")
    style.configure("TLabel", background="#1e1e2e", foreground="#cdd6f4")
    style.configure("TButton", background="#89b4fa", foreground="#1e1e2e")
    current_path = ["/"]

    main_frame = ttk.Frame(root, padding="10")
    main_frame.grid(row=0, column=0, sticky="nsew")
    root.columnconfigure(0, weight=1); root.rowconfigure(0, weight=1)
    main_frame.columnconfigure(0, weight=1); main_frame.rowconfigure(1, weight=1)

    path_label = ttk.Label(main_frame, text=f"Current Path: {current_path[0]}")
    path_label.grid(row=0, column=0, sticky="w", pady=5)

    lb_frame = ttk.Frame(main_frame)
    lb_frame.grid(row=1, column=0, sticky="nsew", pady=5)
    sb = Scrollbar(lb_frame); sb.pack(side=tk.RIGHT, fill=tk.Y)
    lb = Listbox(lb_frame, yscrollcommand=sb.set, width=72, height=20,
                 bg="#313244", fg="#cdd6f4", selectbackground="#89b4fa", selectforeground="#1e1e2e")
    lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    sb.config(command=lb.yview)

    def update(path):
        current_path[0] = path
        path_label.config(text=f"Current Path: {path}")
        lb.delete(0, tk.END)
        if path != "/": lb.insert(tk.END, "../")
        for f in client.list_folders(path):
            lb.insert(tk.END, f + "/")

    def on_dbl(event):
        sel = lb.get(lb.curselection())
        if sel == "../":
            new = os.path.dirname(current_path[0].rstrip("/")) or "/"
        else:
            new = current_path[0].rstrip("/") + "/" + sel.rstrip("/")
        update(new)

    lb.bind("<Double-Button-1>", on_dbl)

    btn_frame = ttk.Frame(main_frame)
    btn_frame.grid(row=2, column=0, pady=10)
    ttk.Button(btn_frame, text="Select This Folder",
               command=lambda: setattr(root, "selected_path", current_path[0]) or root.destroy()
               ).pack(side=tk.LEFT, padx=10)
    ttk.Button(btn_frame, text="Cancel", command=root.destroy).pack(side=tk.LEFT, padx=10)
    update(current_path[0])
    root.mainloop()
    return getattr(root, "selected_path", None)


def _sftp_get_interval():
    subheader("Monitoring Interval")
    print(f"  {_c(C.CYAN,'[1]')}  1 minute")
    print(f"  {_c(C.CYAN,'[2]')}  5 minutes")
    print(f"  {_c(C.CYAN,'[3]')} 20 minutes")
    print(f"  {_c(C.CYAN,'[4]')} 60 minutes")
    print(f"  {_c(C.CYAN,'[5]')} Custom")
    map_ = {"1":60,"2":300,"3":1200,"4":3600}
    while True:
        ch = prompt("Choice [1-5]:").strip()
        if ch in map_: return map_[ch]
        if ch == "5":
            print(f"\n  {_c(C.CYAN,'[1]')} Seconds  {_c(C.CYAN,'[2]')} Minutes  {_c(C.CYAN,'[3]')} Hours")
            unit = prompt("Unit:").strip()
            mult = {"1":1,"2":60,"3":3600}.get(unit, 60)
            try:
                val = float(prompt("Value:").strip())
                if val > 0: return int(val * mult)
            except: pass
            err("Invalid value.")
        else:
            err("Invalid choice.")


def _sftp_get_pw_masked(msg="Password: "):
    if IS_WINDOWS:
        try:
            import msvcrt
            print(f"  {_c(C.MAGENTA, C.ARROW)} {msg}", end="", flush=True)
            chars = []
            while True:
                ch = msvcrt.getch()
                if ch in (b"\r", b"\n"):
                    print(); break
                elif ch == b"\x08":
                    if chars: chars.pop(); print("\b \b", end="", flush=True)
                else:
                    chars.append(ch.decode("utf-8","ignore")); print("*", end="", flush=True)
            return "".join(chars)
        except: pass
    return getpass.getpass(f"  {_c(C.MAGENTA, C.ARROW)} {msg}")


def _sftp_monitor_remote(config, client_cls, tqdm):
    interval = config.get("interval", 60)
    subheader("REMOTE Monitoring Active")
    info("Watching remote server for changes — downloading to local folder.")
    info(f"Base interval: {interval}s  |  Remote: {config['remote_folder']}")
    info(f"Local: {config['local_folder']}")
    log_dir = os.path.join(config["local_folder"], "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"sftp_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.FileHandler(log_file), logging.StreamHandler()])
    logger = logging.getLogger("sftp_remote")
    ftp = client_cls(config["host"], config["username"], config["password"],
                     config.get("port", 22), config.get("use_sftp", True))
    if not ftp.connect(): return
    os.makedirs(config["local_folder"], exist_ok=True)
    file_states = {}
    no_change_count = 0
    current_int = 5
    try:
        while True:
            changes = False
            try:
                remote_files = ftp.list_files(config["remote_folder"])
                for fn in remote_files:
                    if fn in [".", ".."]: continue
                    rpath = os.path.join(config["remote_folder"], fn).replace("\\", "/")
                    lpath = os.path.join(config["local_folder"], fn)
                    cur_size = ftp.get_file_size(rpath)
                    if fn not in file_states:
                        info(f"New file: {fn}")
                        if ftp.download_file(rpath, lpath, logger, tqdm):
                            file_states[fn] = {"size": cur_size}; changes = True
                    elif file_states[fn]["size"] != cur_size:
                        warn(f"Changed: {fn}")
                        if ftp.download_file(rpath, lpath, logger, tqdm):
                            file_states[fn] = {"size": cur_size}; changes = True
                for fn in list(file_states):
                    if fn not in remote_files:
                        lpath = os.path.join(config["local_folder"], fn)
                        if os.path.exists(lpath): os.remove(lpath)
                        del file_states[fn]; changes = True
                        info(f"Deleted locally: {fn}")
            except Exception as e:
                err(f"Monitoring error: {e}")
                ftp.disconnect(); time.sleep(5)
                if not ftp.connect(): break
                file_states = {}
            if changes:
                no_change_count = 0; current_int = 5
            else:
                no_change_count += 1
                current_int = 5 if no_change_count <= 3 else (15 if no_change_count <= 6 else interval)
            for remaining in range(current_int, 0, -1):
                print(f"\r  {_c(C.DIM, f'Next check in {remaining}s...')}", end="", flush=True)
                time.sleep(1)
            print("\r" + " " * 50 + "\r", end="")
    except KeyboardInterrupt:
        info("Monitoring stopped by user.")
    finally:
        ftp.disconnect()


def _sftp_monitor_local(config, client_cls, Observer, FileSystemEventHandler, tqdm):
    interval = config.get("interval", 60)
    subheader("LOCAL Monitoring Active")
    info("Watching local folder for changes — uploading to remote server.")
    log_dir = os.path.join(config["local_folder"], "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"sftp_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.FileHandler(log_file), logging.StreamHandler()])
    logger = logging.getLogger("sftp_local")
    ftp = client_cls(config["host"], config["username"], config["password"],
                     config.get("port", 22), config.get("use_sftp", True))
    if not ftp.connect(): return

    class Handler(FileSystemEventHandler):
        def _do_upload(self, src):
            if not os.path.exists(src): return
            fn = os.path.basename(src)
            rp = os.path.join(config["remote_folder"], fn).replace("\\", "/")
            time.sleep(1)
            ftp.upload_file(src, rp, logger, tqdm)
        def on_created(self, e):
            if not e.is_directory: self._do_upload(e.src_path)
        def on_modified(self, e):
            if not e.is_directory:
                threading.Timer(2.0, self._do_upload, [e.src_path]).start()
        def on_deleted(self, e):
            if not e.is_directory:
                fn = os.path.basename(e.src_path)
                rp = os.path.join(config["remote_folder"], fn).replace("\\", "/")
                try:
                    (ftp.sftp.remove if ftp.use_sftp else ftp.connection.delete)(rp)
                    info(f"Deleted remotely: {fn}"); logger.info(f"DELETED REMOTELY: {fn}")
                except Exception as ex:
                    err(f"Remote delete failed: {ex}")

    # Initial sync
    local_files = [f for f in os.listdir(config["local_folder"]) if os.path.isfile(os.path.join(config["local_folder"], f))]
    if local_files:
        info(f"Initial upload of {len(local_files)} file(s)…")
        for fn in local_files:
            lp = os.path.join(config["local_folder"], fn)
            rp = os.path.join(config["remote_folder"], fn).replace("\\", "/")
            ftp.upload_file(lp, rp, logger, tqdm)

    observer = Observer()
    observer.schedule(Handler(), config["local_folder"], recursive=False)
    observer.start()
    ok("Monitoring local folder. Press Ctrl+C to stop.")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        info("Monitoring stopped by user.")
    finally:
        observer.stop(); observer.join(); ftp.disconnect()


def menu_sftp():
    pm, Observer, FSH, tqdm = _sftp_load_heavy()
    if not pm:
        pause(); return

    def make_client(host, user, pw, port, use_sftp):
        return _FTPClient(host, user, pw, port, use_sftp, pm)

    while True:
        header("SFTP / FTP SYNC MONITOR")
        print()
        print(f"  {_c(C.CYAN,'[1]')} Start new monitor session")
        print(f"  {_c(C.RED, '[0]')} Back")
        divider()
        ch = prompt("Choice:").strip()
        if ch == "0": break
        if ch != "1": err("Invalid choice."); continue

        subheader("Connection Setup")
        use_sftp = not prompt("Use SFTP? (y/n, default y):").strip().lower().startswith("n")
        host     = prompt("Server host:").strip()
        default_port = 22 if use_sftp else 21
        raw_port = prompt(f"Port (default {default_port}):").strip()
        port     = int(raw_port) if raw_port.isdigit() else default_port
        username = prompt("Username:").strip()
        password = _sftp_get_pw_masked("Password: ")
        interval = _sftp_get_interval()

        spinner("Connecting to server…", 1.5)
        ftp = make_client(host, username, password, port, use_sftp)
        if not ftp.connect():
            err("Could not connect. Check credentials and try again.")
            pause(); continue

        info("Select remote folder…")
        remote_folder = _sftp_select_remote_folder(ftp)
        ftp.disconnect()
        if not remote_folder:
            err("No remote folder selected."); pause(); continue
        remote_folder = remote_folder.replace("\\", "/")

        info("Select local folder…")
        local_folder = pick_folder("Select Local Folder to Monitor")
        if not local_folder:
            err("No local folder selected."); pause(); continue

        print()
        print(f"  {_c(C.CYAN,'[1]')} REMOTE monitoring  {_c(C.DIM,'(server → local)')}")
        print(f"  {_c(C.CYAN,'[2]')} LOCAL monitoring   {_c(C.DIM,'(local → server)')}")
        direction = prompt("Direction [1/2]:").strip()

        cfg = {"host": host, "username": username, "password": password,
               "port": port, "use_sftp": use_sftp, "interval": interval,
               "remote_folder": remote_folder, "local_folder": local_folder}

        print()
        if direction == "2":
            _sftp_monitor_local(cfg, lambda *a: make_client(*a), Observer, FSH, tqdm)
        else:
            _sftp_monitor_remote(cfg, lambda *a: make_client(*a), tqdm)
        pause()


# ══════════════════════════════════════════════════════════════════
#  SECTION 8 — VAULT MIRROR
# ══════════════════════════════════════════════════════════════════
VM_BASE   = Path(os.environ.get("APPDATA", os.path.expanduser("~"))) / "VaultMirror"
VM_SCRI   = VM_BASE / "scripts"
VM_STAT   = VM_BASE / "sync-states"
VM_LOCK   = VM_BASE / "locks"
VM_GRACE  = 30

for _p in [VM_BASE, VM_SCRI, VM_STAT, VM_LOCK]:
    _p.mkdir(parents=True, exist_ok=True)


class VaultMirrorScheduler:
    def __init__(self):
        try:
            import win32com.client
            self.svc = win32com.client.Dispatch("Schedule.Service")
            self.svc.Connect()
        except Exception as e:
            warn(f"Task Scheduler COM: {e}")
        self.cfg_path = VM_BASE / "sync-config.json"
        self._load()

    def _load(self):
        if self.cfg_path.exists():
            try: self.config = json.loads(self.cfg_path.read_text()); return
            except: pass
        self.config = {"sync_jobs": {}}

    def _save(self):
        self.cfg_path.write_text(json.dumps(self.config, indent=2))

    def _make_script(self, case, src, dst, bidir, state_file):
        script_path = VM_SCRI / f"sync_{case}.py"
        lock_file   = VM_LOCK / f"{case}.lock"
        dest_drive  = Path(dst).drive if Path(dst).drive else Path(src).drive
        deleted_root = Path(f"{dest_drive}\\VaultMirror_Deleted\\{case}")

        tmpl = f'''import os, json, shutil, time
from pathlib import Path
from datetime import datetime

EXCLUSIONS = [".tmp"]
GRACE_DAYS = {VM_GRACE}
DELETED_ROOT = Path(r"{deleted_root}")
EXCL_PATHS = [DELETED_ROOT]

def accessible(p):
    try:
        pt = Path(p)
        if not pt.exists(): return False
        next(pt.iterdir(), None); return True
    except: return False

def excl(fp):
    try:
        for e in EXCL_PATHS:
            if e and e.exists() and Path(fp).is_relative_to(e): return True
    except: pass
    return False

def tree_state(p):
    pt = Path(p); s = {{}}
    if not pt.exists(): return s
    for f in pt.rglob("*"):
        if f.is_file() and not any(f.name.lower().endswith(x) for x in EXCLUSIONS) and not excl(f):
            try: s[str(f.relative_to(pt))] = {{"mtime": f.stat().st_mtime, "size": f.stat().st_size}}
            except: pass
    return s

def safe_del(fp, deleted_root, sid, direction):
    try:
        deleted_root.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            rp = Path(r"{src}") if "A_to_B" in direction else Path(r"{dst}")
            try: rel = str(fp.relative_to(rp))
            except: rel = fp.name
        except: rel = fp.name
        safe = rel.replace(os.sep,"_").replace("..","parent")[:200]
        d = deleted_root / direction / ts[:8]
        d.mkdir(parents=True, exist_ok=True)
        dest = d / f"{{ts}}_{{safe}}"
        c = 1
        while dest.exists(): dest = (d / f"{{ts}}_{{safe}}_{{c}}"); c += 1
        shutil.move(str(fp), str(dest))
        json.dump({{"orig": str(fp), "rel": rel, "ts": ts, "sid": sid, "dir": direction}},
                  open(str(dest)+".meta.json","w"), indent=2)
        return True
    except Exception as e:
        print(f"Safe-delete failed: {{e}}"); return False

def purge(deleted_root, days=GRACE_DAYS):
    if not deleted_root.exists(): return 0
    cutoff = time.time() - days*86400; n = 0
    for mf in deleted_root.rglob("*.meta.json"):
        try:
            if mf.stat().st_mtime < cutoff:
                df = mf.with_suffix("")
                if df.exists(): df.unlink()
                mf.unlink(); n += 1
                try: mf.parent.rmdir()
                except: pass
        except: continue
    return n

def sync():
    lk = Path(r"{lock_file}")
    if lk.exists(): print("Sync already running."); return
    lk.touch()
    try:
        a, b = Path(r"{src}"), Path(r"{dst}")
        sp = Path(r"{state_file}")
        sid = "{case}"
        DELETED_ROOT.mkdir(parents=True, exist_ok=True)
        a_ok, b_ok = accessible(a), accessible(b)
        if not a_ok and not b_ok: print("Both drives inaccessible."); return
        purged = purge(DELETED_ROOT)
        if purged: print(f"Purged {{purged}} old file(s).")
        last = {{}}
        if sp.exists():
            try: last = json.loads(sp.read_text())
            except: pass
        ca = tree_state(a) if a_ok else {{}}
        cb = tree_state(b) if b_ok else {{}}
        all_p = set(ca)|set(cb)|set(last)
        new_state = {{}}; dels = 0
        for rel in all_p:
            pa, pb = a/rel, b/rel
            in_a, in_b, in_l = rel in ca, rel in cb, rel in last
            if excl(pa) or excl(pb): continue
'''
        if bidir:
            tmpl += '''
            if in_l and not in_a and in_b:
                if b_ok and pb.exists():
                    if safe_del(pb, DELETED_ROOT, sid, "A_to_B"): dels += 1
                    continue
            elif in_l and not in_b and in_a:
                if a_ok and pa.exists():
                    if safe_del(pa, DELETED_ROOT, sid, "B_to_A"): dels += 1
                    continue
'''
        else:
            tmpl += '''
            if in_l and not in_a and in_b:
                if b_ok and pb.exists():
                    if safe_del(pb, DELETED_ROOT, sid, "one_way"): dels += 1
                    continue
'''
        tmpl += f'''
            if in_a and a_ok:
                if b_ok and (not in_b or ca[rel]["mtime"] > cb.get(rel,{{}}).get("mtime",0)):
                    pb.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(pa,pb)
                    new_state[rel] = {{"mtime":ca[rel]["mtime"],"size":ca[rel]["size"]}}
                elif not b_ok and in_a:
                    new_state[rel] = {{"mtime":ca[rel]["mtime"],"size":ca[rel]["size"]}}
'''
        if bidir:
            tmpl += '''
            elif in_b and b_ok:
                if a_ok and (not in_a or cb[rel]["mtime"] > ca.get(rel,{}).get("mtime",0)):
                    pa.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(pb,pa)
                    new_state[rel] = {"mtime":cb[rel]["mtime"],"size":cb[rel]["size"]}
                elif not a_ok and in_b:
                    new_state[rel] = {"mtime":cb[rel]["mtime"],"size":cb[rel]["size"]}
'''
        tmpl += f'''
        sp.write_text(json.dumps(new_state, indent=2))
        if dels: print(f"SAFE DELETE: Moved {{dels}} file(s) to {{DELETED_ROOT}} (purged after {VM_GRACE} days).")
    except Exception as e:
        print(f"Sync error: {{e}}")
    finally:
        if lk.exists(): lk.unlink()

if __name__ == "__main__":
    sync()
'''
        script_path.write_text(tmpl, encoding="utf-8")
        return script_path

    def create_task(self, case, src, dst, interval, bidir):
        task_name  = f"dfirvault-sync-{case}"
        state_file = VM_STAT / f"state_{task_name}.json"
        script     = self._make_script(case, src, dst, bidir, state_file)
        if bidir:
            dest_drive = Path(dst).drive if Path(dst).drive else Path(src).drive
            at         = f"{dest_drive}\\VaultMirror_Deleted\\{case}"
            print()
            warn("BIDIRECTIONAL sync — deletions propagate between both drives.")
            info(f"Deleted files held at: {at}  ({VM_GRACE}-day grace period)")
            pause("Press Enter to acknowledge and continue…")
        imap = {"1":("MINUTE","1","Every Minute"),"2":("HOURLY","1","Hourly"),
                "3":("DAILY","1","Daily"),"4":("WEEKLY","1","Weekly")}
        sch, mod, friendly = imap.get(interval, ("HOURLY","1","Hourly"))
        exe = sys.executable
        cmd = ["schtasks","/Create","/TN",task_name,
               "/TR",f'"{exe}" --run-task "{script}"',
               "/SC",sch,"/MO",mod,"/F"]
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        if res.returncode == 0:
            dest_drive = Path(dst).drive if Path(dst).drive else Path(src).drive
            self.config["sync_jobs"][task_name] = {
                "case_name": case, "source_path": str(src), "dest_path": str(dst),
                "bidirectional": bidir, "interval_desc": friendly,
                "script_path": str(script),
                "deleted_location": f"{dest_drive}\\VaultMirror_Deleted\\{case}",
            }
            self._save(); return True
        return False

    def delete_task(self, task_name):
        subprocess.run(f'schtasks /Delete /TN "{task_name}" /F', shell=True, capture_output=True)
        sf = VM_STAT / f"state_{task_name}.json"
        if sf.exists(): sf.unlink()
        d = self.config["sync_jobs"].get(task_name, {})
        sp = d.get("script_path")
        if sp and Path(sp).exists(): Path(sp).unlink()
        lf = VM_LOCK / f"{d.get('case_name','')}.lock"
        if lf.exists(): lf.unlink()
        self.config["sync_jobs"].pop(task_name, None); self._save()

    def run_now(self, task_name):
        subprocess.run(f'schtasks /Run /TN "{task_name}"', shell=True, capture_output=True)


def _vm_show_deleted():
    clear_screen()
    subheader("Deleted Files Management")
    info("Pattern:  Drive:\\VaultMirror_Deleted\\[CaseName]\\")
    print()
    print(f"  {_c(C.CYAN,'[1]')} Browse to a deleted-files folder")
    print(f"  {_c(C.RED, '[0]')} Back")
    ch = prompt("Choice:").strip()
    if ch != "1": return
    folder = pick_folder("Select VaultMirror_Deleted folder")
    if not folder: return
    dp = Path(folder)
    if not dp.exists(): warn("Folder not found."); return
    clear_screen()
    subheader(f"Deleted Files in: {dp}")
    total_f = 0; total_s = 0
    print()
    for mf in dp.rglob("*.meta.json"):
        try:
            meta = json.loads(mf.read_text())
            total_f += 1; total_s += meta.get("original_size", 0)
            print(f"  {_c(C.CYAN, str(total_f))}. {meta.get('original_rel_path','?')}")
            print(f"     {_c(C.DIM,'Deleted:')}   {meta.get('deleted_at','?')}")
            print(f"     {_c(C.DIM,'Direction:')} {meta.get('direction','?')}")
            print()
        except: continue
    if total_f == 0:
        warn("No deleted files found.")
    else:
        info(f"Total: {total_f:,} file(s)  |  Size: {total_s:,} bytes")
        print()
        print(f"  {_c(C.CYAN,'[1]')} Purge files older than {VM_GRACE} days")
        print(f"  {_c(C.RED, '[0]')} Back")
        if prompt("Choice:").strip() == "1":
            cutoff = time.time() - VM_GRACE * 86400; purged = 0
            for mf in dp.rglob("*.meta.json"):
                if mf.stat().st_mtime < cutoff:
                    df = mf.with_suffix("")
                    if df.exists(): df.unlink()
                    mf.unlink(); purged += 1
            ok(f"Purged {purged} file(s).")
    pause()


def menu_vault_mirror():
    if IS_WINDOWS:
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                err("VaultMirror requires administrator privileges.")
                pause(); return
        except: pass
    scheduler = VaultMirrorScheduler()
    while True:
        header("VAULT MIRROR  —  SAFE SYNC")
        print()
        print(f"  {_c(C.CYAN,'[1]')} Create new sync task")
        print(f"  {_c(C.CYAN,'[2]')} Manage existing tasks")
        print(f"  {_c(C.CYAN,'[3]')} View / manage deleted files")
        print(f"  {_c(C.RED, '[0]')} Back")
        print()
        print(f"  {_c(C.YELLOW, C.WARN+'  SAFE DELETE ENABLED:')}")
        print(f"     {C.BULLET} Files are NEVER permanently deleted immediately")
        print(f"     {C.BULLET} Deleted files → [DestDrive]:\\VaultMirror_Deleted\\")
        print(f"     {C.BULLET} Permanently purged after {VM_GRACE} days")
        divider()
        ch = prompt("Choice:").strip()
        if ch == "1":
            subheader("Create Sync Task")
            case = prompt("Case name:").strip()
            if not case: continue
            info("Select source folder…"); src = pick_folder("Source Folder")
            if not src: continue
            info("Select destination folder…"); dst = pick_folder("Destination Folder")
            if not dst: continue
            print()
            print(f"  {_c(C.CYAN,'[1]')} Minute  {_c(C.CYAN,'[2]')} Hourly  "
                  f"{_c(C.CYAN,'[3]')} Daily  {_c(C.CYAN,'[4]')} Weekly")
            itv = prompt("Sync interval [1-4]:").strip()
            bi  = prompt("Bi-directional? (y/n):").lower().startswith("y")
            spinner("Registering scheduled task…", 1.5)
            if scheduler.create_task(case, src, dst, itv, bi):
                print()
                ok(f"Task '{case}' created.")
                dest_drive = Path(dst).drive if Path(dst).drive else Path(src).drive
                info(f"Deleted files → {dest_drive}\\VaultMirror_Deleted\\{case}")
            else:
                err("Failed to create task. Check admin rights.")
            pause()
        elif ch == "2":
            tasks = list(scheduler.config["sync_jobs"].keys())
            if not tasks: warn("No tasks configured."); pause(); continue
            subheader("Existing Sync Tasks")
            print()
            for i, t in enumerate(tasks, 1):
                d = scheduler.config["sync_jobs"][t]
                mode = "Bi-Dir" if d.get("bidirectional") else "One-Way"
                print(f"  {_c(C.CYAN,f'[{i}]')} {t}  {_c(C.DIM,'|')}  {d.get('interval_desc','?')}  {_c(C.DIM,'|')}  {mode}")
            print(f"  {_c(C.RED,f'[{len(tasks)+1}]')} Back")
            print()
            raw = prompt("Select task:").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(tasks):
                tname = tasks[int(raw) - 1]
                d     = scheduler.config["sync_jobs"][tname]
                subheader(f"Task: {tname}")
                print(f"\n  {_c(C.DIM,'Source:   ')} {d.get('source_path')}")
                print(f"  {_c(C.DIM,'Dest:     ')} {d.get('dest_path')}")
                print(f"  {_c(C.DIM,'Interval: ')} {d.get('interval_desc','?')}")
                mode = "Bi-Directional" if d.get("bidirectional") else "One-Way"
                print(f"  {_c(C.DIM,'Mode:     ')} {mode}")
                print(f"  {_c(C.DIM,'Deleted → ')} {d.get('deleted_location','?')}")
                divider()
                print(f"  {_c(C.CYAN,'[1]')} Run now")
                print(f"  {_c(C.RED, '[2]')} Delete task")
                print(f"  {_c(C.DIM, '[0]')} Back")
                sub = prompt("Action:").strip()
                if sub == "1":
                    scheduler.run_now(tname); ok("Sync triggered.")
                elif sub == "2":
                    scheduler.delete_task(tname); ok(f"Task '{tname}' deleted.")
                pause()
        elif ch == "3":
            _vm_show_deleted()
        elif ch == "0":
            break
        else:
            err("Invalid choice.")


# ══════════════════════════════════════════════════════════════════
#  SECTION 9 — CSV LOG ENRICHER
# ══════════════════════════════════════════════════════════════════

LE_REG_SECTION = "LogEnricher"
LE_CACHE_DIR   = os.path.join(os.path.expanduser("~"), ".log_enricher_cache")


def _le_ensure_imports():
    """Ensure rich/requests are available, install if needed."""
    global _LE_IMPORTS_OK, _le_requests, _LE_Console, _LE_Progress, _LE_Panel
    if _LE_IMPORTS_OK:
        return True
    try:
        os.system("pip install rich requests")
        import requests as _le_requests
        from rich.console import Console as _LE_Console
        from rich.progress import Progress as _LE_Progress
        from rich.panel import Panel as _LE_Panel
        _LE_IMPORTS_OK = True
        return True
    except Exception as e:
        err(f"Could not install required packages: {e}")
        return False


# ── Registry helpers using DFIRVault's RegistryConfig ─────────────

def _le_load_config() -> dict:
    """Load LogEnricher config from registry under DFIRVault key."""
    return {
        "otx_key":            RegistryConfig.load_config(LE_REG_SECTION, "otx_key", ""),
        "ip2location_token":  RegistryConfig.load_config(LE_REG_SECTION, "ip2location_token", ""),
        "abuseipdb_key":      RegistryConfig.load_config(LE_REG_SECTION, "abuseipdb_key", ""),
        "otx_enabled":        bool(RegistryConfig.load_config(LE_REG_SECTION, "otx_enabled", 1)),
        "geolocation_enabled":bool(RegistryConfig.load_config(LE_REG_SECTION, "geolocation_enabled", 1)),
        "abuseipdb_enabled":  bool(RegistryConfig.load_config(LE_REG_SECTION, "abuseipdb_enabled", 1)),
        "tor_enabled":        bool(RegistryConfig.load_config(LE_REG_SECTION, "tor_enabled", 1)),
        "last_input_path":    RegistryConfig.load_config(LE_REG_SECTION, "last_input_path", ""),
        "last_output_path":   RegistryConfig.load_config(LE_REG_SECTION, "last_output_path", ""),
    }


def _le_save_config(config: dict):
    """Save LogEnricher config to registry under DFIRVault key."""
    for key, value in config.items():
        if value is None:
            value = ""
        RegistryConfig.save_config(LE_REG_SECTION, key, value)


# ── Indicator Extractor ───────────────────────────────────────────

import re as _re

class _LE_IndicatorExtractor:
    IP_PATTERN = _re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    HASH_PATTERNS = {
        'md5':    _re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1':   _re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': _re.compile(r'\b[a-fA-F0-9]{64}\b'),
    }
    DOMAIN_PATTERN = _re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    URL_PATTERN = _re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?::\d+)?'
        r'(?:/[-\w%!$&\'()*+,;=:@/~.]*)?(?:\?[-\w%!$&\'()*+,;=:@/~]*)?'
        r'(?:#[-\w%!$&\'()*+,;=:@/~]*)?'
    )

    @classmethod
    def extract(cls, text: str) -> dict:
        indicators = {'ips': [], 'hashes': [], 'domains': [], 'urls': []}
        if not text:
            return indicators
        text = str(text)
        indicators['ips']  = cls.IP_PATTERN.findall(text)
        for pattern in cls.HASH_PATTERNS.values():
            indicators['hashes'].extend(pattern.findall(text))
        indicators['urls'] = cls.URL_PATTERN.findall(text)
        domains = cls.DOMAIN_PATTERN.findall(text)
        common_tlds = {'.com','.org','.net','.gov','.edu','.io','.co','.uk',
                       '.us','.de','.jp','.fr','.au','.br','.ca','.cn','.ru',
                       '.in','.info','.biz'}
        for domain in domains:
            if any(domain.lower().endswith(t) for t in common_tlds):
                if not any(domain in u for u in indicators['urls']):
                    indicators['domains'].append(domain)
        return indicators


# ── OTX Enricher ─────────────────────────────────────────────────

class _LE_OTXEnricher:
    def __init__(self, api_key: str):
        self.api_key  = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers  = {"X-OTX-API-KEY": api_key}
        self.cache    = {}

    def enrich(self, indicator_type: str, indicator: str) -> dict:
        key = f"{indicator_type}:{indicator}"
        if key in self.cache:
            return self.cache[key]
        empty = {'otx_threat_score':0,'otx_pulse_count':0,'otx_malicious_pulses':0,
                 'otx_pulse_names':'','otx_tags':'','otx_malicious':False,'otx_found':False}
        try:
            url = f"{self.base_url}/indicators/{indicator_type}/{indicator}/general"
            r   = _le_requests.get(url, headers=self.headers, timeout=30)
            if r.status_code == 200:
                data   = r.json()
                pulses = data.get('pulse_info',{}).get('pulses',[])
                count  = data.get('pulse_info',{}).get('count',0)
                names, tags, mal = [], set(), 0
                for p in pulses[:10]:
                    n = p.get('name','')
                    if n: names.append(n[:100])
                    tags.update(p.get('tags',[]))
                    if p.get('is_malicious'): mal += 1
                result = {
                    'otx_threat_score':     min(100, count * 10),
                    'otx_pulse_count':      count,
                    'otx_malicious_pulses': mal,
                    'otx_pulse_names':      ' | '.join(names[:5]),
                    'otx_tags':             ', '.join(list(tags)[:15]),
                    'otx_malicious':        mal > 0,
                    'otx_found':            True,
                }
                self.cache[key] = result
                return result
            elif r.status_code == 404:
                self.cache[key] = empty
                return empty
        except Exception as e:
            pass
        return empty


# ── IP2Location PX12 Enricher ─────────────────────────────────────

class _LE_IP2LocationEnricher:
    def __init__(self, token: str):
        self.token       = token
        self.db_path     = None
        self.ip_ranges   = []
        self.cache       = {}
        self.cache_dir   = LE_CACHE_DIR
        self.db_cache    = os.path.join(self.cache_dir, "ip2location_px12_db.pkl")
        self.meta_file   = os.path.join(self.cache_dir, "ip2location_px12_metadata.json")
        os.makedirs(self.cache_dir, exist_ok=True)
        self._console    = _LE_Console()

    def check_cache(self):
        if os.path.exists(self.meta_file):
            try:
                with open(self.meta_file) as f:
                    meta = json.load(f)
                age = datetime.now() - datetime.fromisoformat(meta.get('download_date','2000-01-01'))
                if age.days < 30 and os.path.exists(self.db_cache):
                    return True, meta
            except:
                pass
        return False, None

    def load_cache(self):
        try:
            self._console.print("[cyan]Loading cached IP2Location PX12 database...[/cyan]")
            with open(self.db_cache,'rb') as f:
                self.ip_ranges = pickle.load(f)
            self._console.print(f"[green]Loaded {len(self.ip_ranges):,} IP ranges from cache[/green]")
            return True
        except Exception as e:
            self._console.print(f"[red]Failed to load cached database: {e}[/red]")
            return False

    def save_cache(self):
        try:
            with open(self.db_cache,'wb') as f:
                pickle.dump(self.ip_ranges, f, pickle.HIGHEST_PROTOCOL)
            meta = {
                'download_date': datetime.now().isoformat(),
                'record_count':  len(self.ip_ranges),
                'token_hash':    hashlib.md5(self.token.encode()).hexdigest()[:8]
            }
            with open(self.meta_file,'w') as f:
                json.dump(meta, f)
        except Exception as e:
            self._console.print(f"[yellow]Failed to cache database: {e}[/yellow]")

    def download(self, force=False):
        try:
            url = f"https://www.ip2location.com/download?token={self.token}&file=PX12LITECSV"
            self._console.print("[cyan]Downloading IP2Location PX12 LITE Proxy database...[/cyan]")
            r = _le_requests.get(url, stream=True, timeout=60)
            if r.status_code != 200:
                self._console.print(f"[red]Failed to download: HTTP {r.status_code}[/red]")
                return False
            tmp = tempfile.mkdtemp()
            zp  = os.path.join(tmp, "ip2location.zip")
            total = int(r.headers.get('content-length',0))
            with _LE_Progress() as progress:
                task = progress.add_task("[cyan]Downloading...", total=total)
                with open(zp,'wb') as f:
                    for chunk in r.iter_content(8192):
                        f.write(chunk)
                        progress.advance(task, len(chunk))
            with zipfile.ZipFile(zp,'r') as z:
                z.extractall(tmp)
            for root, dirs, files in os.walk(tmp):
                for fn in files:
                    if fn.endswith('.csv'):
                        self.db_path = os.path.join(root, fn)
                        break
                if self.db_path:
                    break
            if not self.db_path:
                return False
            self._load_db()
            self.save_cache()
            return True
        except Exception as e:
            self._console.print(f"[red]Error downloading database: {e}[/red]")
            return False

    @staticmethod
    def _ip_to_int(ip: str) -> int:
        try:
            return int(ipaddress.IPv4Address(ip))
        except:
            try:
                parts = ip.split('.')
                if len(parts) == 4:
                    return (int(parts[0])<<24)+(int(parts[1])<<16)+(int(parts[2])<<8)+int(parts[3])
            except:
                pass
        return 0

    def _load_db(self):
        self.ip_ranges = []
        self._console.print("[cyan]Parsing IP2Location PX12 database...[/cyan]")
        for enc in ['utf-8','latin-1','iso-8859-1','cp1252']:
            try:
                with open(self.db_path,'r',encoding=enc,errors='ignore') as f:
                    sample = [f.readline() for _ in range(5)]
                    f.seek(0)
                    has_hdr = any('ip_from' in l.lower() for l in sample)
                    if has_hdr:
                        next(f)
                    total = sum(1 for _ in f)
                    f.seek(0)
                    if has_hdr:
                        next(f)
                    reader = csv.reader(f)
                    with _LE_Progress() as progress:
                        task = progress.add_task("[cyan]Parsing...", total=total)
                        for row in reader:
                            progress.advance(task)
                            if len(row) >= 15:
                                try:
                                    ifs = row[0].strip().strip('"')
                                    its = row[1].strip().strip('"')
                                    ip_from = self._ip_to_int(ifs) if '.' in ifs else int(float(ifs))
                                    ip_to   = self._ip_to_int(its) if '.' in its else int(float(its))
                                    if ip_from > 0 and ip_to >= ip_from:
                                        self.ip_ranges.append({
                                            'ip_from': ip_from, 'ip_to': ip_to,
                                            'country_code': row[2].strip('"'),
                                            'country_name': row[3].strip('"'),
                                            'region_name':  row[4].strip('"'),
                                            'city_name':    row[5].strip('"'),
                                            'isp':          row[6].strip('"'),
                                            'domain':       row[7].strip('"'),
                                            'usage_type':   row[8].strip('"'),
                                            'asn':          row[9].strip('"'),
                                            'as_name':      row[10].strip('"'),
                                            'proxy_type':   row[11].strip('"'),
                                            'threat':       row[12].strip('"'),
                                            'provider':     row[13].strip('"'),
                                            'fraud_score':  row[14].strip('"'),
                                        })
                                except (ValueError, IndexError):
                                    pass
                if self.ip_ranges:
                    self.ip_ranges.sort(key=lambda x: x['ip_from'])
                    self._console.print(f"[green]Database ready: {len(self.ip_ranges):,} ranges[/green]")
                    return
            except Exception:
                continue

    def lookup(self, ip: str) -> dict:
        if ip in self.cache:
            return self.cache[ip]
        empty = {
            'geo_country_code':'','geo_country_name':'','geo_region':'','geo_city':'',
            'geo_isp':'','geo_domain':'','proxy_usage_type':'','proxy_asn':'',
            'proxy_as_name':'','proxy_type':'','proxy_threat':'','proxy_provider':'',
            'proxy_fraud_score':'','geo_found':False,'is_proxy':False,'is_vpn':False,
            'is_hosting':False,'is_tor':False
        }
        if not self.ip_ranges:
            self.cache[ip] = empty
            return empty
        try:
            ip_int = self._ip_to_int(ip)
            if not ip_int:
                self.cache[ip] = empty
                return empty
            lo, hi = 0, len(self.ip_ranges)-1
            while lo <= hi:
                mid = (lo+hi)//2
                r   = self.ip_ranges[mid]
                if r['ip_from'] <= ip_int <= r['ip_to']:
                    result = {
                        'geo_country_code': r['country_code'],
                        'geo_country_name': r['country_name'],
                        'geo_region':       r['region_name'],
                        'geo_city':         r['city_name'],
                        'geo_isp':          r['isp'],
                        'geo_domain':       r['domain'],
                        'proxy_usage_type': r['usage_type'],
                        'proxy_asn':        r['asn'],
                        'proxy_as_name':    r['as_name'],
                        'proxy_type':       r['proxy_type'],
                        'proxy_threat':     r['threat'],
                        'proxy_provider':   r['provider'],
                        'proxy_fraud_score':r['fraud_score'],
                        'geo_found':        True,
                        'is_proxy':  r['proxy_type'] not in ['','-','NON-PROXY'],
                        'is_vpn':    'VPN' in r['usage_type'].upper() if r['usage_type'] else False,
                        'is_hosting':'DCH' in r['usage_type'].upper() if r['usage_type'] else False,
                        'is_tor':    'TOR' in r['proxy_type'].upper() if r['proxy_type'] else False,
                    }
                    self.cache[ip] = result
                    return result
                elif ip_int < r['ip_from']:
                    hi = mid-1
                else:
                    lo = mid+1
        except Exception:
            pass
        self.cache[ip] = empty
        return empty


# ── AbuseIPDB Enricher ────────────────────────────────────────────

class _LE_AbuseIPDBEnricher:
    def __init__(self, api_key: str):
        self.api_key  = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.cache    = {}

    def check(self, ip: str) -> dict:
        if ip in self.cache:
            return self.cache[ip]
        empty = {'abuse_confidence_score':0,'abuse_total_reports':0,'abuse_last_reported':'',
                 'abuse_country':'','abuse_usage_type':'','abuse_isp':'','abuse_domain':'',
                 'abuse_is_whitelisted':False,'abuse_found':False}
        try:
            r = _le_requests.get(
                f"{self.base_url}/check",
                headers={'Key': self.api_key, 'Accept': 'application/json'},
                params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json().get('data',{})
                result = {
                    'abuse_confidence_score': d.get('abuseConfidenceScore',0),
                    'abuse_total_reports':    d.get('totalReports',0),
                    'abuse_last_reported':    (d.get('lastReportedAt','') or '')[:10],
                    'abuse_country':          d.get('countryCode',''),
                    'abuse_usage_type':       d.get('usageType',''),
                    'abuse_isp':              d.get('isp',''),
                    'abuse_domain':           d.get('domain',''),
                    'abuse_is_whitelisted':   d.get('isWhitelisted',False),
                    'abuse_found':            d.get('totalReports',0) > 0,
                }
                self.cache[ip] = result
                return result
        except Exception:
            pass
        self.cache[ip] = empty
        return empty


# ── Tor Exit Node Checker ─────────────────────────────────────────

class _LE_TorChecker:
    def __init__(self):
        self._console  = _LE_Console()
        self.exit_nodes: set = set()
        self._cache_file = os.path.join(LE_CACHE_DIR, "tor_exit_nodes.pkl")
        self._load()

    def _load(self):
        if os.path.exists(self._cache_file):
            try:
                if time.time() - os.path.getmtime(self._cache_file) < 86400:
                    with open(self._cache_file,'rb') as f:
                        self.exit_nodes = pickle.load(f)
                    self._console.print(f"[green]Loaded {len(self.exit_nodes):,} Tor exit nodes from cache[/green]")
                    return
            except:
                pass
        try:
            r = _le_requests.get("https://check.torproject.org/exit-addresses", timeout=10)
            if r.status_code == 200:
                for line in r.text.split('\n'):
                    if line.startswith('ExitAddress'):
                        parts = line.split()
                        if len(parts) >= 2:
                            self.exit_nodes.add(parts[1])
                os.makedirs(LE_CACHE_DIR, exist_ok=True)
                with open(self._cache_file,'wb') as f:
                    pickle.dump(self.exit_nodes, f)
                self._console.print(f"[green]Downloaded {len(self.exit_nodes):,} Tor exit nodes[/green]")
        except Exception as e:
            self._console.print(f"[yellow]Could not load Tor exit nodes: {e}[/yellow]")

    def is_tor(self, ip: str) -> bool:
        return ip in self.exit_nodes


# ── CSV Log Enricher Engine ───────────────────────────────────────

class _LE_Enricher:
    def __init__(self, config: dict):
        self._console  = _LE_Console()
        self.config    = config
        self.otx       = _LE_OTXEnricher(config['otx_key'])      if config.get('otx_enabled') and config.get('otx_key') else None
        self.abuseipdb = _LE_AbuseIPDBEnricher(config['abuseipdb_key']) if config.get('abuseipdb_enabled') and config.get('abuseipdb_key') else None
        self.tor       = _LE_TorChecker()                         if config.get('tor_enabled') else None
        self.ip2loc    = None

        if config.get('geolocation_enabled') and config.get('ip2location_token'):
            self.ip2loc = _LE_IP2LocationEnricher(config['ip2location_token'])
            has_cache, meta = self.ip2loc.check_cache()
            if has_cache:
                info(f"Cached IP2Location database found  (downloaded: {meta.get('download_date','?')[:10]}, records: {meta.get('record_count',0):,})")
                ch = prompt("Update IP2Location database now? (y/n, recommended every 30 days):").strip().lower()
                if ch.startswith('y'):
                    if not self.ip2loc.download():
                        warn("Update failed — using cached version.")
                        if not self.ip2loc.load_cache():
                            err("Failed to load any database. Geolocation disabled.")
                            self.ip2loc = None
                else:
                    if not self.ip2loc.load_cache():
                        err("Failed to load cached database. Geolocation disabled.")
                        self.ip2loc = None
            else:
                warn("No cached database found — downloading now...")
                if not self.ip2loc.download():
                    err("Download failed. Geolocation disabled.")
                    self.ip2loc = None

    def process(self, input_path: str, output_path: str) -> bool:
        try:
            self._console.print(f"\n[bold cyan]Processing: {Path(input_path).name}[/bold cyan]")
            rows, fieldnames = self._read_csv(input_path)
            if not rows:
                self._console.print("[yellow]No data found[/yellow]")
                return False
            self._console.print(f"[dim]Read {len(rows)} rows, {len(fieldnames)} columns[/dim]")
            unique = self._extract_unique(rows)
            enriched = self._enrich_all(unique)
            out_rows = self._apply(rows, enriched)
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            self._write_csv(output_path, out_rows, fieldnames)
            if os.path.exists(output_path):
                self._console.print(f"[green]✓ Saved: {output_path} ({os.path.getsize(output_path):,} bytes)[/green]")
                return True
            return False
        except Exception as e:
            self._console.print(f"[red]Error: {e}[/red]")
            import traceback; traceback.print_exc()
            return False

    def _read_csv(self, path: str):
        for enc in ['utf-8','utf-8-sig','latin-1','iso-8859-1','cp1252']:
            try:
                with open(path,'r',encoding=enc,errors='ignore') as f:
                    sample = f.read(4096); f.seek(0)
                    try:
                        dialect  = csv.Sniffer().sniff(sample)
                        has_hdr  = csv.Sniffer().has_header(sample)
                    except:
                        dialect = 'excel'; has_hdr = True
                    if has_hdr:
                        reader = csv.DictReader(f, dialect=dialect)
                        fieldnames = list(reader.fieldnames) if reader.fieldnames else []
                        rows = list(reader)
                    else:
                        reader = csv.reader(f, dialect=dialect)
                        try:
                            first = next(reader)
                            fieldnames = [f"Column_{i+1}" for i in range(len(first))]
                            f.seek(0)
                            reader = csv.DictReader(f, fieldnames=fieldnames, dialect=dialect)
                            rows = list(reader)
                        except StopIteration:
                            rows = []
                    if rows:
                        return rows, fieldnames
            except:
                continue
        return [], []

    def _extract_unique(self, rows):
        unique = {'ips':set(),'hashes':set(),'domains':set(),'urls':set()}
        self._console.print("[cyan]Extracting indicators...[/cyan]")
        with _LE_Progress() as progress:
            task = progress.add_task("[cyan]Scanning rows...", total=len(rows))
            for row in rows:
                txt = ' '.join(str(v) for v in row.values() if v)
                ind = _LE_IndicatorExtractor.extract(txt)
                for k in unique:
                    unique[k].update(ind[k])
                progress.advance(task)
        self._console.print(f"[green]Unique indicators — IPs:{len(unique['ips'])} "
                             f"Hashes:{len(unique['hashes'])} "
                             f"Domains:{len(unique['domains'])} "
                             f"URLs:{len(unique['urls'])}[/green]")
        return unique

    def _enrich_all(self, unique):
        enriched = {}
        if unique['ips']:
            self._console.print(f"\n[cyan]Enriching {len(unique['ips'])} IPs...[/cyan]")
            with _LE_Progress() as progress:
                task = progress.add_task("[cyan]IPs...", total=len(unique['ips']))
                for ip in unique['ips']:
                    enriched[ip] = self._enrich_ip(ip)
                    progress.advance(task)
                    time.sleep(0.05)
        for kind, otype in [('domains','domain'),('urls','url'),('hashes','file')]:
            if unique[kind] and self.otx:
                self._console.print(f"\n[cyan]Enriching {len(unique[kind])} {kind} via OTX...[/cyan]")
                with _LE_Progress() as progress:
                    task = progress.add_task(f"[cyan]{kind}...", total=len(unique[kind]))
                    for val in unique[kind]:
                        enriched[val] = self.otx.enrich(otype, val)
                        progress.advance(task)
                        time.sleep(0.05)
        return enriched

    def _enrich_ip(self, ip: str) -> dict:
        data = {'ip': ip}
        if self.ip2loc:
            data.update(self.ip2loc.lookup(ip))
        if self.otx:
            data.update(self.otx.enrich('IPv4', ip))
        if self.abuseipdb:
            data.update(self.abuseipdb.check(ip))
        if self.tor:
            data['is_tor_exit_node'] = self.tor.is_tor(ip)
        score = 0
        if data.get('otx_malicious'):               score += 30
        if data.get('abuse_confidence_score',0)>50: score += 30
        if data.get('is_proxy'):                    score += 20
        if data.get('is_tor') or data.get('is_tor_exit_node'): score += 20
        if data.get('is_vpn'):                      score += 15
        if data.get('is_hosting'):                  score += 10
        data['combined_threat_score'] = min(100, score)
        return data

    def _apply(self, rows, enriched):
        self._console.print("\n[cyan]Applying enrichments to rows...[/cyan]")
        out = []
        with _LE_Progress() as progress:
            task = progress.add_task("[cyan]Rows...", total=len(rows))
            for row in rows:
                er   = row.copy()
                txt  = ' '.join(str(v) for v in row.values() if v)
                ind  = _LE_IndicatorExtractor.extract(txt)
                cnt  = defaultdict(int)
                for ip in ind['ips']:
                    if ip in enriched:
                        cnt['ip'] += 1
                        sfx = f"_{cnt['ip']}" if cnt['ip'] > 1 else ""
                        for k,v in enriched[ip].items():
                            if k != 'ip': er[f"{k}{sfx}"] = v
                for domain in ind['domains']:
                    if domain in enriched:
                        cnt['domain'] += 1
                        sfx = f"_{cnt['domain']}" if cnt['domain'] > 1 else ""
                        for k,v in enriched[domain].items():
                            er[f"{k}_domain{sfx}"] = v
                for url in ind['urls']:
                    if url in enriched:
                        cnt['url'] += 1
                        sfx = f"_{cnt['url']}" if cnt['url'] > 1 else ""
                        for k,v in enriched[url].items():
                            er[f"{k}_url{sfx}"] = v
                for h in ind['hashes']:
                    if h in enriched:
                        cnt['hash'] += 1
                        sfx = f"_{cnt['hash']}" if cnt['hash'] > 1 else ""
                        for k,v in enriched[h].items():
                            er[f"{k}_hash{sfx}"] = v
                out.append(er)
                progress.advance(task)
        return out

    def _write_csv(self, path, rows, orig_fields):
        all_fields = set()
        for f in orig_fields:
            if f is not None: all_fields.add(str(f))
        for row in rows:
            for k in row:
                if k is not None: all_fields.add(str(k))
        orig_set  = {str(f) for f in orig_fields if f is not None}
        new_fields = sorted([f for f in all_fields if f not in orig_set])
        final     = [f for f in orig_fields if f is not None] + new_fields
        with open(path,'w',encoding='utf-8',newline='') as f:
            writer = csv.DictWriter(f, fieldnames=final, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(rows)
        self._console.print(f"[dim]Output: {len(final)} columns[/dim]")


# ── Menu Entry Point ──────────────────────────────────────────────

def menu_log_enricher():
    if not _le_ensure_imports():
        pause(); return

    header("CSV LOG ENRICHER")

    # Load existing config from registry
    saved = _le_load_config()
    has_config = bool(saved.get('otx_key') or saved.get('ip2location_token') or saved.get('abuseipdb_key'))

    config = dict(saved)  # start with saved values

    if has_config:
        subheader("Saved API Configuration Found")
        info(f"OTX key:           {'[set]' if saved.get('otx_key') else '[not set]'}")
        info(f"IP2Location token: {'[set]' if saved.get('ip2location_token') else '[not set]'}")
        info(f"AbuseIPDB key:     {'[set]' if saved.get('abuseipdb_key') else '[not set]'}")
        info(f"Enrichments:       OTX={saved.get('otx_enabled',True)}  "
             f"Geo={saved.get('geolocation_enabled',True)}  "
             f"AbuseIPDB={saved.get('abuseipdb_enabled',True)}  "
             f"Tor={saved.get('tor_enabled',True)}")
        print()
        ch = prompt("Keep existing API configuration? (y=keep / n=update):").strip().lower()
        update_config = ch.startswith('n')
    else:
        update_config = True

    if update_config:
        subheader("API Configuration")

        # OTX
        default_otx = saved.get('otx_key','')
        raw = prompt(f"AlienVault OTX API key [{('****' + default_otx[-4:]) if default_otx else 'not set'}] (Enter to keep):").strip()
        if raw:
            config['otx_key'] = raw
        elif not config.get('otx_key'):
            config['otx_key'] = ''

        # IP2Location
        default_ip2l = saved.get('ip2location_token','')
        raw = prompt(f"IP2Location download token [{('****' + default_ip2l[-4:]) if default_ip2l else 'not set'}] (Enter to keep, 'none' to clear):").strip()
        if raw.lower() == 'none':
            config['ip2location_token'] = ''
        elif raw:
            config['ip2location_token'] = raw

        # AbuseIPDB
        default_abuse = saved.get('abuseipdb_key','')
        raw = prompt(f"AbuseIPDB API key [{('****' + default_abuse[-4:]) if default_abuse else 'not set'}] (Enter to keep, 'none' to clear):").strip()
        if raw.lower() == 'none':
            config['abuseipdb_key'] = ''
        elif raw:
            config['abuseipdb_key'] = raw

        # Enrichment toggles
        subheader("Enrichment Options")
        otx_on = prompt(f"Enable OTX threat intelligence? (y/n) [current: {'y' if config.get('otx_enabled',True) else 'n'}]:").strip().lower()
        if otx_on in ('y','n'):
            config['otx_enabled'] = otx_on == 'y'

        if config.get('ip2location_token'):
            geo_on = prompt(f"Enable IP2Location geolocation + proxy? (y/n) [current: {'y' if config.get('geolocation_enabled',True) else 'n'}]:").strip().lower()
            if geo_on in ('y','n'):
                config['geolocation_enabled'] = geo_on == 'y'
        else:
            config['geolocation_enabled'] = False

        if config.get('abuseipdb_key'):
            abuse_on = prompt(f"Enable AbuseIPDB reputation? (y/n) [current: {'y' if config.get('abuseipdb_enabled',True) else 'n'}]:").strip().lower()
            if abuse_on in ('y','n'):
                config['abuseipdb_enabled'] = abuse_on == 'y'
        else:
            config['abuseipdb_enabled'] = False

        tor_on = prompt(f"Enable Tor exit node detection? (y/n) [current: {'y' if config.get('tor_enabled',True) else 'n'}]:").strip().lower()
        if tor_on in ('y','n'):
            config['tor_enabled'] = tor_on == 'y'

        _le_save_config(config)
        ok("Configuration saved to registry.")

    if not config.get('otx_key') and not config.get('ip2location_token') and not config.get('abuseipdb_key'):
        warn("No API keys configured. At least one enrichment source is recommended.")
        if not prompt("Continue anyway? (y/n):").strip().lower().startswith('y'):
            return

    # File selection
    subheader("File Selection")
    print(f"  {_c(C.CYAN,'[1]')} Single CSV file")
    print(f"  {_c(C.CYAN,'[2]')} Folder with multiple CSV files")
    print(f"  {_c(C.RED, '[0]')} Back")
    divider()
    ch = prompt("Choice:").strip()
    if ch == '0':
        return
    elif ch == '1':
        info("Select CSV file to enrich…")
        input_path = pick_file("Select CSV file", [("CSV files", "*.csv"), ("All files", "*.*")])
        if not input_path:
            warn("No file selected."); return
        files_to_process = [input_path]
        save_input = input_path
    elif ch == '2':
        info("Select folder containing CSV files…")
        input_path = pick_folder("Select folder with CSV files")
        if not input_path:
            warn("No folder selected."); return
        files_to_process = [str(f) for f in Path(input_path).glob("*.csv")]
        if not files_to_process:
            err("No CSV files found in selected folder."); pause(); return
        ok(f"Found {len(files_to_process)} CSV file(s).")
        save_input = input_path
    else:
        err("Invalid choice."); return

    # Output directory
    subheader("Output Configuration")
    default_out = config.get('last_output_path','')
    info("Select output directory…")
    output_path = pick_folder("Select output directory")
    if not output_path:
        warn("No output directory selected."); return

    # Save paths to registry
    config['last_input_path']  = save_input
    config['last_output_path'] = output_path
    _le_save_config(config)

    os.makedirs(LE_CACHE_DIR, exist_ok=True)
    os.makedirs(output_path, exist_ok=True)

    # Initialise enricher
    subheader("Initialising Enricher")
    enricher = _LE_Enricher(config)

    # Process files
    subheader("Enrichment Processing")
    successful = failed = 0
    for fpath in files_to_process:
        stem      = Path(fpath).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file  = os.path.join(output_path, f"{stem}_enriched_{timestamp}.csv")
        if enricher.process(fpath, out_file):
            successful += 1
        else:
            failed += 1

    print()
    ok(f"Processing complete — {successful} succeeded, {failed} failed.")
    info(f"Output directory: {output_path}")
    if IS_WINDOWS:
        try: os.startfile(os.path.abspath(output_path))
        except: pass
    pause()


# ══════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
#  SECTION 10 — BODYFILE → CSV + FORENSIC EXPLORER
# ══════════════════════════════════════════════════════════════════
# Merged from bodyfile_to_csv_with_report_lightweight_enhanced.py
# Original: Jacob Wilson  •  dfirvault@gmail.com

def __PLACEHOLDER_bf_bf_convert_epoch_to_str(epoch):
    """Convert epoch to dd/mm/yyyy HH:MM:SS (UTC), or blank if 0/invalid."""
    try:
        epoch = int(epoch)
        if epoch > 0:
            return datetime.utcfromtimestamp(epoch).strftime('%d/%m/%Y %H:%M:%S')
    except Exception:
        pass
    return ""

def __PLACEHOLDER_bf_bf_assess_noteworthy(name, mode, atime, mtime, ctime, crtime):
    """
    Return comma-separated noteworthy flags based on heuristics.
    Also return file type category.
    Added timestamp anomalies and cross-platform flags.
    """
    name_lower = (name or "").lower()
    flags = []
    file_type = "other"

    # File type detection
    if any(name_lower.endswith(ext) for ext in (".exe", ".dll", ".bin", ".elf", ".so", ".dylib")):
        file_type = "executable"
    elif any(name_lower.endswith(ext) for ext in (".py", ".sh", ".pl", ".rb", ".ps1", ".bat", ".cmd")):
        file_type = "script"
    elif any(name_lower.endswith(ext) for ext in (".conf", ".config", ".ini", ".cfg", ".xml", ".json", ".yaml", ".yml")):
        file_type = "config"
    elif any(name_lower.endswith(ext) for ext in (".log", ".txt", ".out", ".err")):
        file_type = "log"
    elif any(name_lower.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff")):
        file_type = "image"
    elif any(name_lower.endswith(ext) for ext in (".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx")):
        file_type = "document"

    # Temp locations
    temp_dirs = ["/tmp/", "/var/tmp/", "/dev/shm/", "c:\\temp\\", "c:\\windows\\temp\\"]
    for t in temp_dirs:
        if name_lower.startswith(t):
            flags.append("Temp location")

    # Executables
    try:
        if isinstance(mode, str) and len(mode) > 3:
            if mode[3] == 'x' or mode[3] == 's':
                flags.append("Executable (mode)")
    except Exception:
        pass

    exec_exts = (".sh", ".py", ".pl", ".elf", ".bin", ".run", ".deb", ".exe", ".dll")
    if any(name_lower.endswith(ext) for ext in exec_exts):
        flags.append("Executable (ext)")

    # Hidden file
    last = name_lower.split("/")[-1] if "/" in name_lower else name_lower
    if last.startswith("."):
        flags.append("Hidden")

    # Sensitive files
    if name_lower.startswith("/root/"):
        flags.append("Root-owned location")
    if "/.ssh/" in name_lower or name_lower.endswith("/.ssh"):
        flags.append("SSH artifact")
    if name_lower.endswith("/shadow") or "/shadow" in name_lower and name_lower.startswith("/etc"):
        flags.append("Possible /etc/shadow")

    # Cross-platform
    windows_sensitive = ["c:\\programdata\\", "c:\\users\\appdata\\", "c:\\$recycle.bin\\"]
    for w in windows_sensitive:
        if name_lower.startswith(w):
            flags.append("Windows sensitive")

    mac_artifacts = [".ds_store", "launchagents/"]
    for m in mac_artifacts:
        if m in name_lower:
            flags.append("macOS artifact")

    linux_artifacts = ["/proc/", "/sys/"]
    for l in linux_artifacts:
        if name_lower.startswith(l):
            flags.append("Linux artifact")

    # Timestamp anomalies
    current_time = int(time.time())
    at = int(atime) if atime and atime.isdigit() else 0
    mt = int(mtime) if mtime and mtime.isdigit() else 0
    ct = int(ctime) if ctime and ctime.isdigit() else 0
    cr = int(crtime) if crtime and crtime.isdigit() else 0

    if cr > mt:
        flags.append("Create after modify")
    if any(t > current_time + 3600 for t in [at, mt, ct, cr] if t > 0):
        flags.append("Future timestamp")
    # Simple skew detection: large negative diffs
    if mt > 0 and cr > 0 and mt - cr < -86400 * 30:  # Modify 30 days before create
        flags.append("Time skew suspected")

    # Basic file signature (extension-based for now)
    known_malware_ext = [".wannacry", ".locky"]  # Example
    if any(name_lower.endswith(ext) for ext in known_malware_ext):
        flags.append("Known malware ext")

    return ", ".join(flags) if flags else "", file_type

def __PLACEHOLDER_bf_bf_get_available_port(start_port=8000, max_port=8100):
    """Find an available port starting from start_port up to max_port"""
    for port in range(start_port, max_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    raise Exception(f"No available ports found between {start_port} and {max_port}")

def __PLACEHOLDER_bf_bf_ask_date_range_filter():
    """Ask user if they want to apply date range filtering"""
    root = tk.Tk()
    root.title("Date Range Filter")
    root.geometry("520x650")  # Even larger to ensure everything fits
    root.resizable(False, False)
    
    # Create a main frame to hold everything
    main_frame = tk.Frame(root)
    main_frame.pack(fill='both', expand=True, padx=20, pady=10)
    
    result = {
        "apply_filter": False,
        "date_type": "mtime",
        "start_date": None,
        "end_date": None
    }
    
    def validate_and_confirm():
        """Validate dates and confirm selection"""
        start_text = start_date_entry.get().strip()
        end_text = end_date_entry.get().strip()
        
        # Validate dates
        errors = []
        
        if start_text:
            try:
                start_date = datetime.strptime(start_text, '%Y-%m-%d')
                result["start_date"] = start_date
            except ValueError:
                errors.append("Start date must be in YYYY-MM-DD format")
        
        if end_text:
            try:
                end_date = datetime.strptime(end_text, '%Y-%m-%d')
                result["end_date"] = end_date
            except ValueError:
                errors.append("End date must be in YYYY-MM-DD format")
        
        # Check if start date is before end date
        if start_text and end_text and not errors:
            if result["start_date"] > result["end_date"]:
                errors.append("Start date cannot be after end date")
        
        if errors:
            error_message = "\n".join(errors)
            messagebox.showerror("Invalid Dates", error_message)
            return
        
        result["apply_filter"] = True
        result["date_type"] = date_type_var.get()
        root.quit()
        root.destroy()
    
    def on_skip():
        """Skip date filtering"""
        result["apply_filter"] = False
        root.quit()
        root.destroy()
    
    def on_clear():
        """Clear all date fields"""
        start_date_entry.delete(0, tk.END)
        end_date_entry.delete(0, tk.END)
    
    def on_preset_days(days):
        """Set date range to last N days"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        start_date_entry.delete(0, tk.END)
        start_date_entry.insert(0, start_date.strftime('%Y-%m-%d'))
        
        end_date_entry.delete(0, tk.END)
        end_date_entry.insert(0, end_date.strftime('%Y-%m-%d'))
    
    # Center the window
    root.eval('tk::PlaceWindow . center')
    
    # Main title
    tk.Label(main_frame, text="Date Range Filter", font=("Arial", 16, "bold")).pack(pady=(0, 10))
    
    # Description
    desc_text = "Filter files by date range to reduce file size and focus analysis"
    tk.Label(main_frame, text=desc_text, wraplength=480, justify="center").pack(pady=(0, 15))
    
    # Date type selection frame
    type_frame = tk.LabelFrame(main_frame, text="1. Select Time Type to Filter", padx=15, pady=10)
    type_frame.pack(fill='x', pady=(0, 15))
    
    date_type_var = tk.StringVar(value="mtime")
    date_types = [
        ("Modified Time (mtime)", "mtime"),
        ("Access Time (atime)", "atime"), 
        ("Change Time (ctime)", "ctime"),
        ("Creation Time (crtime)", "crtime")
    ]
    
    for text, value in date_types:
        tk.Radiobutton(type_frame, text=text, variable=date_type_var, value=value, 
                      font=("Arial", 10)).pack(anchor='w', pady=2)
    
    # Date inputs frame
    date_frame = tk.LabelFrame(main_frame, text="2. Set Date Range", padx=15, pady=10)
    date_frame.pack(fill='x', pady=(0, 15))
    
    # Start date
    start_frame = tk.Frame(date_frame)
    start_frame.pack(fill='x', pady=8)
    tk.Label(start_frame, text="Start Date (YYYY-MM-DD):", width=22, anchor='w', 
             font=("Arial", 10)).pack(side=tk.LEFT)
    start_date_entry = tk.Entry(start_frame, width=15, font=("Arial", 10))
    start_date_entry.pack(side=tk.LEFT, padx=5)
    
    # End date
    end_frame = tk.Frame(date_frame)
    end_frame.pack(fill='x', pady=8)
    tk.Label(end_frame, text="End Date (YYYY-MM-DD):", width=22, anchor='w', 
             font=("Arial", 10)).pack(side=tk.LEFT)
    end_date_entry = tk.Entry(end_frame, width=15, font=("Arial", 10))
    end_date_entry.pack(side=tk.LEFT, padx=5)
    
    # Quick preset buttons
    preset_frame = tk.Frame(date_frame)
    preset_frame.pack(fill='x', pady=10)
    tk.Label(preset_frame, text="Quick Presets:", font=("Arial", 10, "bold")).pack(anchor='w')
    
    preset_btn_frame = tk.Frame(preset_frame)
    preset_btn_frame.pack(fill='x', pady=8)
    
    presets = [("Last 7 days", 7), ("Last 30 days", 30), ("Last 90 days", 90)]
    for text, days in presets:
        btn = tk.Button(preset_btn_frame, text=text, command=lambda d=days: on_preset_days(d),
                       width=12, font=("Arial", 9))
        btn.pack(side=tk.LEFT, padx=5)
    
    # Help text
    help_frame = tk.Frame(date_frame)
    help_frame.pack(fill='x', pady=10)
    tk.Label(help_frame, text="💡 Leave both blank for no date filtering", 
             font=("Arial", 9), fg='gray', justify='left').pack(anchor='w')
    tk.Label(help_frame, text="💡 Fill only start date to filter from that date forward", 
             font=("Arial", 9), fg='gray', justify='left').pack(anchor='w')
    tk.Label(help_frame, text="💡 Fill only end date to filter up to that date", 
             font=("Arial", 9), fg='gray', justify='left').pack(anchor='w')
    
    # Action buttons frame
    btn_frame = tk.Frame(main_frame)
    btn_frame.pack(pady=20)
    
    clear_btn = tk.Button(btn_frame, text="Clear Dates", command=on_clear, 
                         width=14, height=2, font=("Arial", 10))
    clear_btn.pack(side=tk.LEFT, padx=10)
    
    skip_btn = tk.Button(btn_frame, text="Skip Filter", command=on_skip, 
                        width=14, height=2, font=("Arial", 10))
    skip_btn.pack(side=tk.LEFT, padx=10)
    
    apply_btn = tk.Button(btn_frame, text="APPLY FILTER", command=validate_and_confirm, 
                         width=14, height=2, bg="#4CAF50", fg="white", 
                         font=("Arial", 10, "bold"))
    apply_btn.pack(side=tk.LEFT, padx=10)
    
    # Force window to be visible
    root.deiconify()
    root.lift()
    root.focus_force()
    
    root.mainloop()
    return result

def __PLACEHOLDER_bf_bf_filter_rows_by_date_range(rows, date_filter):
    """Filter rows based on date range criteria"""
    if not date_filter["apply_filter"]:
        return rows
    
    date_type = date_filter["date_type"]
    start_date = date_filter["start_date"]
    end_date = date_filter["end_date"]
    
    if not start_date and not end_date:
        return rows
    
    filtered_rows = []
    
    for row in rows:
        # Get the appropriate epoch timestamp based on date_type
        epoch_key = f"_{date_type}_epoch"
        epoch_value = row.get(epoch_key, 0)
        
        if epoch_value == 0:
            continue
            
        # Convert epoch to datetime for comparison
        try:
            file_dt = datetime.utcfromtimestamp(epoch_value)
            
            # Apply date filters
            if start_date and file_dt < start_date:
                continue
            if end_date and file_dt > end_date:
                continue
                
            filtered_rows.append(row)
        except (ValueError, OSError):
            continue
    
    print(f"📅 Date filtering: {len(filtered_rows)} of {len(rows)} records match the criteria")
    return filtered_rows

# -------------------------------------------------------------------
# Database Storage for Fast Access
# -------------------------------------------------------------------

def __PLACEHOLDER_bf_bf_create_database(rows, db_path, bodyfile_name="default"):
    """Create SQLite database for fast querying with multiple bodyfile support"""
    conn = sqlite3.connect(db_path)
    
    # Fixed regex function with error handling
    def regexp(expr, item):
        if item is None:
            return False
        try:
            return re.search(expr, item) is not None
        except re.error:
            return False
    
    conn.create_function("REGEXP", 2, regexp)
    cursor = conn.cursor()
    
    # Create table with bodyfile source
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            md5 TEXT,
            name TEXT,
            inode TEXT,
            mode TEXT,
            uid TEXT,
            gid TEXT,
            size INTEGER,
            atime TEXT,
            mtime TEXT,
            ctime TEXT,
            crtime TEXT,
            noteworthy TEXT,
            file_type TEXT,
            atime_epoch INTEGER,
            mtime_epoch INTEGER,
            ctime_epoch INTEGER,
            crtime_epoch INTEGER,
            bodyfile_source TEXT
        )
    ''')
    
    # Create indexes for fast searching
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_name ON files(name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_mtime ON files(mtime_epoch)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_atime ON files(atime_epoch)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ctime ON files(ctime_epoch)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_crtime ON files(crtime_epoch)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_noteworthy ON files(noteworthy)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_type ON files(file_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_bodyfile ON files(bodyfile_source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_md5 ON files(md5)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uid ON files(uid)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_gid ON files(gid)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_size ON files(size)')
    
    # Insert data
    for row in rows:
        cursor.execute('''
            INSERT INTO files (md5, name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime, noteworthy, file_type, atime_epoch, mtime_epoch, ctime_epoch, crtime_epoch, bodyfile_source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            row["MD5"], row["Name"], row["Inode"], row["Mode"], row["UID"], row["GID"],
            int(row["Size"]) if row["Size"].isdigit() else 0,
            row["Atime"], row["Mtime"], row["Ctime"], row["Crtime"], row["Noteworthy"],
            row["FileType"],
            row["_atime_epoch"], row["_mtime_epoch"], row["_ctime_epoch"], row["_crtime_epoch"],
            bodyfile_name
        ))
    
    conn.commit()
    conn.close()
    print(f"📊 Database updated with {len(rows):,} records from {bodyfile_name}")

def __PLACEHOLDER_bf_bf_add_bodyfile_to_database(bodyfile_path, db_path):
    """Add a new bodyfile to existing database"""
    rows = []
    processed = 0
    bodyfile_name = os.path.basename(bodyfile_path)

    # Read and parse bodyfile
    with open(bodyfile_path, "r", encoding="utf-8", errors="ignore") as infile:
        reader = csv.reader(infile, delimiter="|")
        for row in reader:
            processed += 1
            if len(row) not in (10, 11):
                continue

            if len(row) == 11:
                md5, name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime = row
            else:
                md5, name, inode, mode, uid, gid, size, atime, mtime, ctime = row
                crtime = ""

            noteworthy, file_type = bf_assess_noteworthy(name, mode, atime, mtime, ctime, crtime)

            row_dict = {
                "MD5": md5,
                "Name": name,
                "Inode": inode,
                "Mode": mode,
                "UID": uid,
                "GID": gid,
                "Size": size,
                "Atime": bf_convert_epoch_to_str(atime),
                "Mtime": bf_convert_epoch_to_str(mtime),
                "Ctime": bf_convert_epoch_to_str(ctime),
                "Crtime": bf_convert_epoch_to_str(crtime),
                "Noteworthy": noteworthy,
                "FileType": file_type,
                "_atime_epoch": int(atime) if atime and atime.isdigit() else 0,
                "_mtime_epoch": int(mtime) if mtime and mtime.isdigit() else 0,
                "_ctime_epoch": int(ctime) if ctime and ctime.isdigit() else 0,
                "_crtime_epoch": int(crtime) if crtime and crtime.isdigit() else 0,
            }

            rows.append(row_dict)

    # Add to database
    conn = sqlite3.connect(db_path)
    
    # Fixed regex function with error handling
    def regexp(expr, item):
        if item is None:
            return False
        try:
            return re.search(expr, item) is not None
        except re.error:
            return False
    
    conn.create_function("REGEXP", 2, regexp)
    cursor = conn.cursor()
    
    for row in rows:
        cursor.execute('''
            INSERT INTO files (md5, name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime, noteworthy, file_type, atime_epoch, mtime_epoch, ctime_epoch, crtime_epoch, bodyfile_source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            row["MD5"], row["Name"], row["Inode"], row["Mode"], row["UID"], row["GID"],
            int(row["Size"]) if row["Size"].isdigit() else 0,
            row["Atime"], row["Mtime"], row["Ctime"], row["Crtime"], row["Noteworthy"],
            row["FileType"],
            row["_atime_epoch"], row["_mtime_epoch"], row["_ctime_epoch"], row["_crtime_epoch"],
            bodyfile_name
        ))
    
    conn.commit()
    conn.close()
    print(f"📊 Database updated with {len(rows):,} additional records from {bodyfile_name}")
    return len(rows)

def __PLACEHOLDER_bf_bf_verify_database_contents(db_path):
    """Verify the database has the expected data"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check total count
        cursor.execute("SELECT COUNT(*) FROM files")
        total = cursor.fetchone()[0]
        print(f"📊 Database contains {total:,} records")
        
        # Check if we have any data with the expected columns
        cursor.execute("SELECT name, file_type FROM files LIMIT 5")
        sample_data = cursor.fetchall()
        print(f"📊 Sample data: {sample_data}")
        
        # Check bodyfile sources
        cursor.execute("SELECT DISTINCT bodyfile_source FROM files")
        sources = cursor.fetchall()
        print(f"📊 Bodyfile sources: {sources}")
        
        conn.close()
        return total > 0
        
    except Exception as e:
        print(f"❌ Database verification failed: {e}")
        return False

def __PLACEHOLDER_bf_bf_check_database_schema(db_path):
    """Check the database schema and contents"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print(f"📊 Database tables: {tables}")
        
        # Check files table structure
        cursor.execute("PRAGMA table_info(files)")
        columns = cursor.fetchall()
        print("📊 Files table columns:")
        for col in columns:
            print(f"   - {col[1]} ({col[2]})")
        
        # Check a few records with all fields
        cursor.execute("SELECT * FROM files LIMIT 3")
        sample_records = cursor.fetchall()
        print("📊 Sample full records:")
        for i, record in enumerate(sample_records):
            print(f"   Record {i}: {record}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Database schema check failed: {e}")

def __PLACEHOLDER_bf_bf_test_database_query(db_path):
    """Test a simple database query"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Simple test query
        cursor.execute("SELECT COUNT(*) FROM files WHERE name LIKE '%/%'")
        count = cursor.fetchone()[0]
        print(f"✅ Test query found {count} files with '/' in name")
        
        # Test with no WHERE clause
        cursor.execute("SELECT COUNT(*) FROM files")
        total = cursor.fetchone()[0]
        print(f"✅ Total files in database: {total}")
        
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def __PLACEHOLDER_bf_bf_get_summary_stats(db_path, timeline_type="mtime"):
    """Get summary statistics from database with configurable timeline type"""
    conn = sqlite3.connect(db_path)
    
    # Fixed regex function with error handling
    def regexp(expr, item):
        if item is None:
            return False
        try:
            return re.search(expr, item) is not None
        except re.error:
            return False
    
    conn.create_function("REGEXP", 2, regexp)
    cursor = conn.cursor()
    
    stats = {}
    
    # Basic counts
    cursor.execute("SELECT COUNT(*) FROM files")
    stats['total_files'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy != ''")
    stats['noteworthy_count'] = cursor.fetchone()[0]
    
    # File type breakdown
    cursor.execute('''
        SELECT 
            SUM(CASE WHEN file_type = 'executable' THEN 1 ELSE 0 END) as executables,
            SUM(CASE WHEN file_type = 'script' THEN 1 ELSE 0 END) as scripts,
            SUM(CASE WHEN file_type = 'config' THEN 1 ELSE 0 END) as configs,
            SUM(CASE WHEN file_type = 'log' THEN 1 ELSE 0 END) as logs,
            SUM(CASE WHEN file_type = 'image' THEN 1 ELSE 0 END) as images,
            SUM(CASE WHEN file_type = 'document' THEN 1 ELSE 0 END) as documents,
            SUM(CASE WHEN file_type = 'other' THEN 1 ELSE 0 END) as other,
            SUM(CASE WHEN name LIKE '/tmp/%' OR name LIKE '/var/tmp/%' OR name LIKE '/dev/shm/%' THEN 1 ELSE 0 END) as temp_files,
            SUM(CASE WHEN name LIKE '%/.ssh/%' OR name LIKE '%/.ssh' THEN 1 ELSE 0 END) as ssh_files
        FROM files
    ''')
    result = cursor.fetchone()
    stats.update({
        'executables': result[0],
        'scripts': result[1],
        'configs': result[2],
        'logs': result[3],
        'images': result[4],
        'documents': result[5],
        'other': result[6],
        'temp_files': result[7],
        'ssh_files': result[8]
    })
    
    # Get available bodyfiles
    cursor.execute("SELECT DISTINCT bodyfile_source FROM files")
    stats['bodyfiles'] = [row[0] for row in cursor.fetchall()]
    
    # Timeline data based on selected type (last 30 days)
    time_columns = {
        "atime": "atime_epoch",
        "mtime": "mtime_epoch",
        "ctime": "ctime_epoch",
        "crtime": "crtime_epoch"
    }
    if timeline_type == "macb":
        # Combined MACB
        cursor.execute('''
            SELECT date(datetime(ts, 'unixepoch')), COUNT(*) 
            FROM (
                SELECT atime_epoch AS ts FROM files WHERE atime_epoch > 0
                UNION ALL
                SELECT mtime_epoch AS ts FROM files WHERE mtime_epoch > 0
                UNION ALL
                SELECT ctime_epoch AS ts FROM files WHERE ctime_epoch > 0
                UNION ALL
                SELECT crtime_epoch AS ts FROM files WHERE crtime_epoch > 0
            )
            GROUP BY date(datetime(ts, 'unixepoch'))
            ORDER BY date(datetime(ts, 'unixepoch')) DESC 
            LIMIT 30
        ''')
    else:
        time_column = time_columns.get(timeline_type, "mtime_epoch")
        cursor.execute(f'''
            SELECT date(datetime({time_column}, 'unixepoch')), COUNT(*) 
            FROM files 
            WHERE {time_column} > 0 
            GROUP BY date(datetime({time_column}, 'unixepoch'))
            ORDER BY date(datetime({time_column}, 'unixepoch')) DESC 
            LIMIT 30
        ''')
    timeline_data = cursor.fetchall()
    stats['timeline'] = timeline_data
    
    # Flag statistics
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy LIKE '%Temp location%'")
    stats['temp_count'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy LIKE '%Executable%'")
    stats['executable_count'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy LIKE '%Hidden%'")
    stats['hidden_count'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy LIKE '%SSH%'")
    stats['ssh_count'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM files WHERE noteworthy LIKE '%Root-owned%'")
    stats['root_count'] = cursor.fetchone()[0]
    
    # Anomaly counts
    current_time = int(time.time())
    cursor.execute(f'''
        SELECT COUNT(*) FROM files 
        WHERE crtime_epoch > mtime_epoch 
        OR atime_epoch > {current_time} OR mtime_epoch > {current_time} 
        OR ctime_epoch > {current_time} OR crtime_epoch > {current_time}
    ''')
    stats['anomaly_count'] = cursor.fetchone()[0]
    
    conn.close()
    return stats

# -------------------------------------------------------------------
# Lightweight HTML Generation
# -------------------------------------------------------------------

def __PLACEHOLDER_bf_bf_generate_lightweight_html(db_path, csv_path, port):
    """Generate a small HTML file that uses AJAX to load data"""
    out_dir = os.path.dirname(os.path.abspath(csv_path)) or "."
    base = os.path.splitext(os.path.basename(csv_path))[0]
    html_path = os.path.join(out_dir, f"{base}_report.html")
    
    stats = bf_get_summary_stats(db_path)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{base} - Forensic Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@1.2.1/dist/chartjs-plugin-zoom.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --primary: #4A90E2;
            --secondary: #7B68EE;
            --dark: #2C3E50;
            --sidebar-bg: #F8F9FA;
        }}
        
        * {{
            margin: 0; padding: 0; box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #f5f7fa; color: #333;
        }}
        
        .container {{
            display: flex; min-height: 100vh;
        }}
        
        .sidebar {{
            width: 320px; background: var(--sidebar-bg);
            border-right: 1px solid #dee2e6; padding: 20px;
            position: fixed; height: 100vh; overflow-y: auto;
        }}
        
        .main-content {{
            flex: 1; margin-left: 320px; padding: 20px;
        }}
        
        .card {{
            background: white; border-radius: 8px; padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;
        }}
        
        .btn {{
            padding: 8px 16px; border: none; border-radius: 4px;
            cursor: pointer; display: inline-flex; align-items: center; gap: 6px;
        }}
        
        .btn-primary {{
            background: var(--primary); color: white;
        }}
        
        table {{
            width: 100%; border-collapse: collapse; font-size: 13px;
        }}
        
        th, td {{
            padding: 10px 8px; text-align: left; border-bottom: 1px solid #dee2e6;
        }}
        
        th {{
            background: #f8f9fa; font-weight: 600; cursor: pointer;
        }}
        
        .badge {{
            display: inline-block; padding: 2px 8px; border-radius: 12px;
            font-size: 11px; font-weight: 600; margin-right: 4px;
        }}
        
        .badge-warning {{ background: #fff3cd; color: #856404; }}
        .badge-danger {{ background: #f8d7da; color: #721c24; }}
        .badge-info {{ background: #d1ecf1; color: #0c5460; }}
        
        .loading {{
            text-align: center; padding: 20px; color: #6c757d;
        }}
        
        .pagination {{
            display: flex; justify-content: space-between; align-items: center;
            margin-top: 15px; padding-top: 15px; border-top: 1px solid #dee2e6;
        }}
        
        .search-box {{
            position: relative; margin-bottom: 15px;
        }}
        
        .search-box input {{
            width: 100%; padding: 10px 35px 10px 35px;
            border: 1px solid #ced4da; border-radius: 4px;
        }}
        
        .search-box i {{
            position: absolute; left: 12px; top: 50%;
            transform: translateY(-50%); color: #6c757d;
        }}
        
        .chart-container {{
            height: 200px; position: relative;
        }}
        
        .filter-toggle {{
            display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 15px;
        }}
        
        .filter-btn {{
            padding: 6px 12px; border: 1px solid #dee2e6; border-radius: 20px;
            background: white; cursor: pointer; font-size: 12px;
            transition: all 0.2s;
        }}
        
        .filter-btn.active {{
            background: var(--primary); color: white; border-color: var(--primary);
        }}
        
        .search-controls {{
            display: flex; gap: 10px; margin-bottom: 15px;
        }}
        
        .search-controls input {{
            flex: 1;
        }}
        
        .bodyfile-selector {{
            margin-bottom: 15px;
        }}
        
        .bodyfile-selector select {{
            width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ced4da;
        }}
        
        .date-range {{
            margin-bottom: 15px;
        }}
        
        .date-range input {{
            width: 100%; padding: 8px; margin-bottom: 8px;
            border: 1px solid #ced4da; border-radius: 4px;
        }}
        
        .date-range label {{
            font-size: 12px; color: #6c757d; margin-bottom: 4px; display: block;
        }}
        
        .timeline-radio {{
            margin-bottom: 15px;
        }}
        
        .radio-group {{
            display: flex; flex-wrap: wrap; gap: 10px; margin-top: 8px;
        }}
        
        .radio-option {{
            display: flex; align-items: center; gap: 5px; font-size: 12px;
        }}
        
        .radio-option input {{
            margin: 0;
        }}
        
        .advanced-filters {{
            margin-bottom: 15px;
        }}
        
        .advanced-filters input {{
            width: 100%; padding: 8px; margin-bottom: 8px;
            border: 1px solid #ced4da; border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div style="padding-bottom: 20px; border-bottom: 1px solid #dee2e6; margin-bottom: 20px;">
                <h2><i class="fas fa-search"></i> Forensic Explorer</h2>
                <div style="font-size: 12px; color: #6c757d;">{base}</div>
            </div>

            <div class="search-controls">
                <div class="search-box" style="flex: 1;">
                    <i class="fas fa-search"></i>
                    <input type="text" id="globalSearch" placeholder="Search files...">
                </div>
                <label for="regexSearch" style="white-space: nowrap; display: flex; align-items: center; gap: 5px;">
                    <input type="checkbox" id="regexSearch"> Regex
                </label>
                <button class="btn btn-primary" onclick="searchFiles()" style="white-space: nowrap;">
                    <i class="fas fa-search"></i> Search
                </button>
            </div>

            <div class="advanced-filters">
                <label for="hashSearch">MD5 Hash:</label>
                <input id="hashSearch" placeholder="Full or partial hash">
                
                <label for="minSize">Min Size (bytes):</label>
                <input id="minSize" type="number">
                
                <label for="uidFilter">UID:</label>
                <input id="uidFilter">
                
                <label for="gidFilter">GID:</label>
                <input id="gidFilter">
                
                <label for="dirFilter">Directory Pattern:</label>
                <input id="dirFilter" placeholder="e.g., /etc/*">
            </div>

            <div class="bodyfile-selector">
                <h3 style="font-size: 14px; margin-bottom: 10px;"><i class="fas fa-database"></i> Bodyfile Source</h3>
                <select id="bodyfileFilter" onchange="searchFiles()">
                    <option value="all">All Bodyfiles</option>
                    {''.join([f'<option value="{bf}">{bf}</option>' for bf in stats['bodyfiles']])}
                </select>
            </div>

            <div style="margin-bottom: 20px;">
                <h3 style="font-size: 14px; margin-bottom: 10px;"><i class="fas fa-filter"></i> File Type Filters</h3>
                <div class="filter-toggle">
                    <button class="filter-btn active" data-type="all" onclick="toggleFilter(this, 'file_type')">All</button>
                    <button class="filter-btn" data-type="executable" onclick="toggleFilter(this, 'file_type')">Executables</button>
                    <button class="filter-btn" data-type="script" onclick="toggleFilter(this, 'file_type')">Scripts</button>
                    <button class="filter-btn" data-type="config" onclick="toggleFilter(this, 'file_type')">Configs</button>
                    <button class="filter-btn" data-type="log" onclick="toggleFilter(this, 'file_type')">Logs</button>
                    <button class="filter-btn" data-type="image" onclick="toggleFilter(this, 'file_type')">Images</button>
                    <button class="filter-btn" data-type="document" onclick="toggleFilter(this, 'file_type')">Documents</button>
                </div>
                
                <h3 style="font-size: 14px; margin-bottom: 10px; margin-top: 15px;"><i class="fas fa-flag"></i> Flag Filters</h3>
                <div class="filter-toggle">
                    <button class="filter-btn active" data-type="all" onclick="toggleFilter(this, 'flag')">All</button>
                    <button class="filter-btn" data-type="Temp location" onclick="toggleFilter(this, 'flag')">Temp ({stats['temp_count']})</button>
                    <button class="filter-btn" data-type="Executable" onclick="toggleFilter(this, 'flag')">Executable ({stats['executable_count']})</button>
                    <button class="filter-btn" data-type="Hidden" onclick="toggleFilter(this, 'flag')">Hidden ({stats['hidden_count']})</button>
                    <button class="filter-btn" data-type="SSH" onclick="toggleFilter(this, 'flag')">SSH ({stats['ssh_count']})</button>
                    <button class="filter-btn" data-type="Root-owned" onclick="toggleFilter(this, 'flag')">Root-owned ({stats['root_count']})</button>
                </div>
            </div>

            <div class="date-range">
                <h3 style="font-size: 14px; margin-bottom: 10px;"><i class="fas fa-calendar"></i> Date Range Filters</h3>
                
                <div>
                    <label for="mtimeStart">Modified From:</label>
                    <input type="date" id="mtimeStart" onchange="searchFiles()">
                </div>
                <div>
                    <label for="mtimeEnd">Modified To:</label>
                    <input type="date" id="mtimeEnd" onchange="searchFiles()">
                </div>
                
                <div style="margin-top: 10px;">
                    <label for="atimeStart">Accessed From:</label>
                    <input type="date" id="atimeStart" onchange="searchFiles()">
                </div>
                <div>
                    <label for="atimeEnd">Accessed To:</label>
                    <input type="date" id="atimeEnd" onchange="searchFiles()">
                </div>
            </div>

            <div class="card">
                <h3 style="margin-bottom: 15px;"><i class="fas fa-chart-bar"></i> Quick Stats</h3>
                <div style="font-size: 12px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Total Files:</span>
                        <span style="font-weight: 600;">{stats['total_files']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Noteworthy:</span>
                        <span style="font-weight: 600;">{stats['noteworthy_count']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Executables:</span>
                        <span style="font-weight: 600;">{stats['executables']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Scripts:</span>
                        <span style="font-weight: 600;">{stats['scripts']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Configs:</span>
                        <span style="font-weight: 600;">{stats['configs']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Anomalies:</span>
                        <span style="font-weight: 600;">{stats['anomaly_count']:,}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Bodyfiles:</span>
                        <span style="font-weight: 600;">{len(stats['bodyfiles'])}</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="main-content">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h1>Forensic Analysis Dashboard</h1>
                <div>
                    <button class="btn" onclick="addBodyfile()" style="margin-right: 10px;">
                        <i class="fas fa-plus"></i> Add Bodyfile
                    </button>
                    <button class="btn btn-primary" onclick="exportResults('csv')" style="margin-right: 10px;">
                        <i class="fas fa-download"></i> Export CSV
                    </button>
                    <button class="btn btn-primary" onclick="exportResults('json')">
                        <i class="fas fa-download"></i> Export JSON
                    </button>
                </div>
            </div>

            <!-- Charts -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">
                <div class="card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                        <h3 style="margin: 0;">Timeline Activity</h3>
                        <div class="timeline-radio">
                            <div class="radio-group">
                                <label class="radio-option">
                                    <input type="radio" name="timelineType" value="mtime" checked onchange="updateTimelineChart()"> Modified
                                </label>
                                <label class="radio-option">
                                    <input type="radio" name="timelineType" value="atime" onchange="updateTimelineChart()"> Accessed
                                </label>
                                <label class="radio-option">
                                    <input type="radio" name="timelineType" value="ctime" onchange="updateTimelineChart()"> Changed
                                </label>
                                <label class="radio-option">
                                    <input type="radio" name="timelineType" value="crtime" onchange="updateTimelineChart()"> Created
                                </label>
                                <label class="radio-option">
                                    <input type="radio" name="timelineType" value="macb" onchange="updateTimelineChart()"> MACB
                                </label>
                            </div>
                        </div>
                    </div>
                    <div class="chart-container">
                        <canvas id="timelineChart"></canvas>
                    </div>
                </div>
                <div class="card">
                    <h3 style="margin-bottom: 15px;">File Types</h3>
                    <div class="chart-container">
                        <canvas id="fileTypeChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Results -->
            <div class="card">
                <h3 style="margin-bottom: 15px;">Search Results</h3>
                <div id="resultsInfo" style="font-size: 12px; color: #6c757d; margin-bottom: 15px;">
                    Loading...
                </div>
                <div style="overflow-x: auto; max-height: 500px; overflow-y: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th onclick="sortTable('name')">Name</th>
                                <th onclick="sortTable('size')">Size</th>
                                <th onclick="sortTable('atime_epoch')">Access</th>
                                <th onclick="sortTable('mtime_epoch')">Modified</th>
                                <th onclick="sortTable('crtime_epoch')">Created</th>
                                <th>File Type</th>
                                <th>Bodyfile</th>
                                <th>Flags</th>
                            </tr>
                        </thead>
                        <tbody id="resultsBody">
                            <tr><td colspan="8" class="loading">Loading data...</td></tr>
                        </tbody>
                    </table>
                </div>
                <div class="pagination">
                    <div id="pageInfo" style="font-size: 12px; color: #6c757d;">Page 1</div>
                    <div>
                        <button class="btn" onclick="changePage(-1)" id="prevBtn" disabled>Previous</button>
                        <button class="btn" onclick="changePage(1)" id="nextBtn">Next</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentPage = 1;
        let pageSize = 50;
        let currentSort = 'name';
        let currentSortDir = 'asc';
        let currentSearch = '';
        let currentFileTypes = ['all'];
        let currentFlags = ['all'];
        let currentBodyfile = 'all';
        let searchTimeout = null;
        let timelineChart = null;

        // Initialize charts
        function initCharts() {{
            updateTimelineChart();
            initFileTypeChart();
        }}

        function updateTimelineChart() {{
            const timelineType = document.querySelector('input[name="timelineType"]:checked').value;
            
            // Fetch updated timeline data from server
            fetch(`http://localhost:{port}/api/timeline?type=${{timelineType}}`)
                .then(response => response.json())
                .then(data => {{
                    renderTimelineChart(data);
                }})
                .catch(error => {{
                    console.error('Error loading timeline data:', error);
                }});
        }}

        function renderTimelineChart(timelineData) {{
            const timelineCtx = document.getElementById('timelineChart').getContext('2d');
            
            // Destroy existing chart if it exists
            if (timelineChart) {{
                timelineChart.destroy();
            }}
            
            timelineChart = new Chart(timelineCtx, {{
                type: 'line',
                data: {{
                    labels: timelineData.labels,
                    datasets: [{{
                        label: 'File Activity',
                        data: timelineData.data,
                        borderColor: '#4A90E2',
                        backgroundColor: 'rgba(74, 144, 226, 0.1)',
                        tension: 0.4,
                        fill: true
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ 
                        legend: {{ display: false }},
                        title: {{
                            display: true,
                            text: timelineData.title
                        }},
                        zoom: {{
                            zoom: {{
                                wheel: {{ enabled: true }},
                                pinch: {{ enabled: true }},
                                mode: 'xy'
                            }},
                            pan: {{
                                enabled: true,
                                mode: 'xy'
                            }}
                        }}
                    }},
                    scales: {{
                        y: {{ beginAtZero: true }},
                        x: {{ ticks: {{ maxRotation: 45 }} }}
                    }}
                }}
            }});
        }}

        function initFileTypeChart() {{
            const fileTypeCtx = document.getElementById('fileTypeChart').getContext('2d');
            new Chart(fileTypeCtx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Executables', 'Scripts', 'Configs', 'Logs', 'Images', 'Documents', 'Other'],
                    datasets: [{{
                        data: {json.dumps([
                            stats['executables'], stats['scripts'], stats['configs'], 
                            stats['logs'], stats['images'], stats['documents'], stats['other']
                        ])},
                        backgroundColor: ['#4A90E2', '#7B68EE', '#32CD32', '#FFA500', '#DC143C', '#9370DB', '#6c757d']
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ position: 'bottom' }} }}
                }}
            }});
        }}

        // Auto-search with debouncing
        function setupAutoSearch() {{
            document.getElementById('globalSearch').addEventListener('input', function() {{
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(searchFiles, 300);
            }});
            // Add listeners for advanced filters
            ['hashSearch', 'minSize', 'uidFilter', 'gidFilter', 'dirFilter'].forEach(id => {{
                document.getElementById(id).addEventListener('input', function() {{
                    clearTimeout(searchTimeout);
                    searchTimeout = setTimeout(searchFiles, 300);
                }});
            }});
            document.getElementById('regexSearch').addEventListener('change', searchFiles);
        }}

        // Toggle file type and flag filters
        function toggleFilter(button, filterType) {{
            const filterValue = button.getAttribute('data-type');
            
            if (filterType === 'file_type') {{
                if (filterValue === 'all') {{
                    document.querySelectorAll('.filter-btn[data-filter-type="file_type"]').forEach(btn => {{
                        btn.classList.remove('active');
                    }});
                    button.classList.add('active');
                    currentFileTypes = ['all'];
                }} else {{
                    button.classList.toggle('active');
                    const allBtn = document.querySelector('.filter-btn[data-type="all"][data-filter-type="file_type"]');
                    allBtn.classList.remove('active');
                    currentFileTypes = Array.from(document.querySelectorAll('.filter-btn.active[data-filter-type="file_type"]'))
                        .map(btn => btn.getAttribute('data-type'))
                        .filter(type => type !== 'all');
                    if (currentFileTypes.length === 0) {{
                        allBtn.classList.add('active');
                        currentFileTypes = ['all'];
                    }}
                }}
            }} else if (filterType === 'flag') {{
                if (filterValue === 'all') {{
                    document.querySelectorAll('.filter-btn[data-filter-type="flag"]').forEach(btn => {{
                        btn.classList.remove('active');
                    }});
                    button.classList.add('active');
                    currentFlags = ['all'];
                }} else {{
                    button.classList.toggle('active');
                    const allBtn = document.querySelector('.filter-btn[data-type="all"][data-filter-type="flag"]');
                    allBtn.classList.remove('active');
                    currentFlags = Array.from(document.querySelectorAll('.filter-btn.active[data-filter-type="flag"]'))
                        .map(btn => btn.getAttribute('data-type'))
                        .filter(type => type !== 'all');
                    if (currentFlags.length === 0) {{
                        allBtn.classList.add('active');
                        currentFlags = ['all'];
                    }}
                }}
            }}
            
            searchFiles();
        }}

        // Load data from server
        async function loadData() {{
            try {{
                const fileTypesParam = currentFileTypes.includes('all') ? '' : currentFileTypes.join(',');
                const flagsParam = currentFlags.includes('all') ? '' : currentFlags.join(',');
                const mtimeStart = document.getElementById('mtimeStart').value;
                const mtimeEnd = document.getElementById('mtimeEnd').value;
                const atimeStart = document.getElementById('atimeStart').value;
                const atimeEnd = document.getElementById('atimeEnd').value;
                const regex = document.getElementById('regexSearch').checked ? 1 : 0;
                const hashSearch = document.getElementById('hashSearch').value;
                const minSize = document.getElementById('minSize').value;
                const uidFilter = document.getElementById('uidFilter').value;
                const gidFilter = document.getElementById('gidFilter').value;
                const dirFilter = document.getElementById('dirFilter').value.replace('*', '%');
                
                const response = await fetch(`http://localhost:{port}/api/data?page=${{currentPage}}&size=${{pageSize}}&search=${{encodeURIComponent(currentSearch)}}&sort=${{currentSort}}&dir=${{currentSortDir}}&file_types=${{fileTypesParam}}&flags=${{flagsParam}}&bodyfile=${{currentBodyfile}}&mtime_start=${{mtimeStart}}&mtime_end=${{mtimeEnd}}&atime_start=${{atimeStart}}&atime_end=${{atimeEnd}}&regex=${{regex}}&hash=${{encodeURIComponent(hashSearch)}}&min_size=${{minSize}}&uid=${{uidFilter}}&gid=${{gidFilter}}&dir=${{encodeURIComponent(dirFilter)}}`);
                const data = await response.json();
                displayResults(data);
            }} catch (error) {{
                console.error('Error loading data:', error);
                document.getElementById('resultsBody').innerHTML = '<tr><td colspan="8">Error loading data</td></tr>';
            }}
        }}

        // Display results
        function displayResults(data) {{
            const tbody = document.getElementById('resultsBody');
            const info = document.getElementById('resultsInfo');
            
            info.textContent = `Showing ${{data.start}}-${{data.end}} of ${{data.total}} files`;
            document.getElementById('pageInfo').textContent = `Page ${{data.page}} of ${{Math.ceil(data.total / pageSize)}}`;
            
            document.getElementById('prevBtn').disabled = data.page <= 1;
            document.getElementById('nextBtn').disabled = data.page >= Math.ceil(data.total / pageSize);
            
            if (data.files.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="8">No files found</td></tr>';
                return;
            }}
            
            let html = '';
            data.files.forEach(file => {{
                let badges = '';
                if (file.noteworthy) {{
                    if (file.noteworthy.includes('Temp')) badges += '<span class="badge badge-warning">Temp</span>';
                    if (file.noteworthy.includes('Executable')) badges += '<span class="badge badge-danger">Exec</span>';
                    if (file.noteworthy.includes('Hidden')) badges += '<span class="badge badge-warning">Hidden</span>';
                    if (file.noteworthy.includes('SSH')) badges += '<span class="badge badge-info">SSH</span>';
                    if (file.noteworthy.includes('Root-owned')) badges += '<span class="badge badge-danger">Root</span>';
                    if (file.noteworthy.includes('Create after modify')) badges += '<span class="badge badge-danger">Timestamp Anomaly</span>';
                    if (file.noteworthy.includes('Future timestamp')) badges += '<span class="badge badge-danger">Future TS</span>';
                    if (file.noteworthy.includes('Time skew')) badges += '<span class="badge badge-warning">Skew</span>';
                }}
                
                html += `
                    <tr>
                        <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;" title="${{file.name}}">${{file.name}}</td>
                        <td>${{formatBytes(file.size)}}</td>
                        <td>${{file.atime || '-'}}</td>
                        <td>${{file.mtime || '-'}}</td>
                        <td>${{file.crtime || '-'}}</td>
                        <td><span class="badge badge-info">${{file.file_type || 'other'}}</span></td>
                        <td>${{file.bodyfile_source}}</td>
                        <td>${{badges}}</td>
                    </tr>
                `;
            }});
            
            tbody.innerHTML = html;
        }}

        // Utility functions
        function formatBytes(bytes) {{
            if (!bytes) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }}

        function searchFiles() {{
            currentSearch = document.getElementById('globalSearch').value;
            currentBodyfile = document.getElementById('bodyfileFilter').value;
            currentPage = 1;
            loadData();
        }}

        function sortTable(column) {{
            if (currentSort === column) {{
                currentSortDir = currentSortDir === 'asc' ? 'desc' : 'asc';
            }} else {{
                currentSort = column;
                currentSortDir = 'asc';
            }}
            loadData();
        }}

        function changePage(direction) {{
            currentPage += direction;
            loadData();
        }}

        function exportResults(format) {{
            const fileTypesParam = currentFileTypes.includes('all') ? '' : currentFileTypes.join(',');
            const flagsParam = currentFlags.includes('all') ? '' : currentFlags.join(',');
            const mtimeStart = document.getElementById('mtimeStart').value;
            const mtimeEnd = document.getElementById('mtimeEnd').value;
            const atimeStart = document.getElementById('atimeStart').value;
            const atimeEnd = document.getElementById('atimeEnd').value;
            const regex = document.getElementById('regexSearch').checked ? 1 : 0;
            const hashSearch = document.getElementById('hashSearch').value;
            const minSize = document.getElementById('minSize').value;
            const uidFilter = document.getElementById('uidFilter').value;
            const gidFilter = document.getElementById('gidFilter').value;
            const dirFilter = document.getElementById('dirFilter').value.replace('*', '%');
            
            window.open(`http://localhost:{port}/api/export?format=${{format}}&search=${{encodeURIComponent(currentSearch)}}&file_types=${{fileTypesParam}}&flags=${{flagsParam}}&bodyfile=${{currentBodyfile}}&mtime_start=${{mtimeStart}}&mtime_end=${{mtimeEnd}}&atime_start=${{atimeStart}}&atime_end=${{atimeEnd}}&regex=${{regex}}&hash=${{encodeURIComponent(hashSearch)}}&min_size=${{minSize}}&uid=${{uidFilter}}&gid=${{gidFilter}}&dir=${{encodeURIComponent(dirFilter)}}`, '_blank');
        }}

        function addBodyfile() {{
            if (confirm('This will open a file dialog to add a new bodyfile. Continue?')) {{
                fetch(`http://localhost:{port}/api/add_bodyfile`, {{ method: 'POST' }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        alert('Bodyfile added successfully! Refreshing page...');
                        location.reload();
                    }} else {{
                        alert('Error adding bodyfile: ' + data.error);
                    }}
                }})
                .catch(error => {{
                    alert('Error communicating with server: ' + error);
                }});
            }}
        }}

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {{
            // Set data-filter-type attributes for filter buttons
            document.querySelectorAll('.filter-btn').forEach(btn => {{
                const isFileType = btn.closest('div').previousElementSibling.textContent.includes('File Type');
                btn.setAttribute('data-filter-type', isFileType ? 'file_type' : 'flag');
            }});
            
            initCharts();
            setupAutoSearch();
            loadData();
        }});
    </script>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return html_path

# -------------------------------------------------------------------
# Enhanced Web Server for Data API
# -------------------------------------------------------------------

class BfBfForensicRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.db_path = kwargs.pop('db_path')
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        if self.path.startswith('/api/'):
            self.handle_api()
        else:
            super().do_GET()
    
    def do_POST(self):
        if self.path.startswith('/api/add_bodyfile'):
            self.handle_add_bodyfile()
        else:
            self.send_error(404)
    
    def handle_api(self):
        if self.path.startswith('/api/data'):
            self.handle_data_api()
        elif self.path.startswith('/api/export'):
            self.handle_export_api()
        elif self.path.startswith('/api/timeline'):
            self.handle_timeline_api()
        elif self.path.startswith('/api/add_bodyfile'):
            self.handle_add_bodyfile()
        else:
            self.send_error(404)
    
    def handle_timeline_api(self):
        """Handle timeline data requests with different time types"""
        import urllib.parse
        from urllib.parse import parse_qs
        
        query = urllib.parse.urlparse(self.path).query
        params = parse_qs(query)
        timeline_type = params.get('type', ['mtime'])[0]
        
        print(f"📈 Timeline API request: type={timeline_type}")
        
        stats = bf_get_summary_stats(self.db_path, timeline_type)
        
        # Prepare timeline data for chart
        labels = [item[0] for item in stats['timeline']]
        data = [item[1] for item in stats['timeline']]
        
        print(f"📈 Timeline data: {len(labels)} points")
        
        timeline_titles = {
            'mtime': 'File Modifications Timeline',
            'atime': 'File Access Timeline', 
            'ctime': 'File Changes Timeline',
            'crtime': 'File Creation Timeline',
            'macb': 'Combined MACB Timeline'
        }
        
        response = {
            'labels': labels,
            'data': data,
            'title': timeline_titles.get(timeline_type, 'Timeline Activity')
        }
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def handle_data_api(self):
        import urllib.parse
        from urllib.parse import parse_qs
        
        # Parse query parameters
        query = urllib.parse.urlparse(self.path).query
        params = parse_qs(query)
        
        # DEBUG: Show raw parameter parsing
        print(f"🔍 RAW URL: {self.path}")
        print(f"🔍 RAW QUERY: {query}")
        print(f"🔍 RAW PARAMS: {params}")
        
        page = int(params.get('page', [1])[0])
        size = int(params.get('size', [50])[0])
        search = params.get('search', [''])[0]
        sort = params.get('sort', ['name'])[0]
        sort_dir = params.get('dir', ['asc'])[0]
        
        # FIX: Use a different parameter name for directory filter
        # Check if 'dir_filter' exists, otherwise use empty string
        if 'dir_filter' in params:
            dir_filter = params.get('dir_filter', [''])[0]
        else:
            # Fallback for old parameter name
            dir_filter = params.get('dir', [''])[0]
            # If we got 'asc' (sort direction), it's wrong - set to empty
            if dir_filter == 'asc':
                dir_filter = ''
        
        file_types = params.get('file_types', [''])[0]
        flags = params.get('flags', [''])[0]
        bodyfile = params.get('bodyfile', ['all'])[0]
        mtime_start = params.get('mtime_start', [''])[0]
        mtime_end = params.get('mtime_end', [''])[0]
        atime_start = params.get('atime_start', [''])[0]
        atime_end = params.get('atime_end', [''])[0]
        regex = int(params.get('regex', [0])[0])
        hash_search = params.get('hash', [''])[0]
        min_size = params.get('min_size', [''])[0]
        uid_filter = params.get('uid', [''])[0]
        gid_filter = params.get('gid', [''])[0]
        
        # Debug output
        print(f"🔍 API Request Parameters:")
        print(f"   search='{search}', page={page}, file_types='{file_types}'")
        print(f"   sort='{sort}', sort_dir='{sort_dir}'")
        print(f"   bodyfile='{bodyfile}', regex={regex}")
        print(f"   hash='{hash_search}', min_size='{min_size}'")
        print(f"   uid='{uid_filter}', gid='{gid_filter}', dir_filter='{dir_filter}'")
        
        # Calculate pagination
        offset = (page - 1) * size
        
        # Build SQL query
        conn = sqlite3.connect(self.db_path)
        
        # Fixed regex function with error handling
        def regexp(expr, item):
            if item is None:
                return False
            try:
                return re.search(expr, item) is not None
            except re.error:
                return False
        
        conn.create_function("REGEXP", 2, regexp)
        cursor = conn.cursor()
        
        # Build WHERE clause
        where_clauses = []
        query_params = []
        
        # Only add search condition if search is not empty
        if search and search.strip():
            if regex:
                where_clauses.append("name REGEXP ?")
                query_params.append(search)
            else:
                where_clauses.append("name LIKE ?")
                query_params.append(f'%{search}%')
        
        if hash_search and hash_search.strip():
            where_clauses.append("md5 LIKE ?")
            query_params.append(f'%{hash_search}%')
        
        if min_size and min_size.isdigit():
            where_clauses.append("size >= ?")
            query_params.append(int(min_size))
        
        if uid_filter and uid_filter.strip():
            where_clauses.append("uid = ?")
            query_params.append(uid_filter)
        
        if gid_filter and gid_filter.strip():
            where_clauses.append("gid = ?")
            query_params.append(gid_filter)
        
        # FIX: Use the corrected dir_filter
        if dir_filter and dir_filter.strip():
            where_clauses.append("name LIKE ?")
            query_params.append(dir_filter)
        
        if file_types and file_types != 'all' and file_types.strip():
            file_type_list = file_types.split(',')
            placeholders = ','.join(['?'] * len(file_type_list))
            where_clauses.append(f"file_type IN ({placeholders})")
            query_params.extend(file_type_list)
        
        if flags and flags != 'all' and flags.strip():
            flag_list = flags.split(',')
            flag_conditions = []
            for flag in flag_list:
                flag_conditions.append("noteworthy LIKE ?")
                query_params.append(f'%{flag}%')
            where_clauses.append(f"({' OR '.join(flag_conditions)})")
        
        if bodyfile and bodyfile != 'all' and bodyfile.strip():
            where_clauses.append("bodyfile_source = ?")
            query_params.append(bodyfile)
            
        # Date range filters
        if mtime_start and mtime_start.strip():
            where_clauses.append("mtime_epoch >= ?")
            query_params.append(int(datetime.strptime(mtime_start, '%Y-%m-%d').timestamp()))
        if mtime_end and mtime_end.strip():
            where_clauses.append("mtime_epoch <= ?")
            query_params.append(int(datetime.strptime(mtime_end, '%Y-%m-%d').timestamp()) + 86399)
            
        if atime_start and atime_start.strip():
            where_clauses.append("atime_epoch >= ?")
            query_params.append(int(datetime.strptime(atime_start, '%Y-%m-%d').timestamp()))
        if atime_end and atime_end.strip():
            where_clauses.append("atime_epoch <= ?")
            query_params.append(int(datetime.strptime(atime_end, '%Y-%m-%d').timestamp()) + 86399)
        
        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        # Get total count
        count_query = f"SELECT COUNT(*) FROM files {where_sql}"
        print(f"📊 Count query: {count_query}")
        print(f"📊 Query params: {query_params}")
        
        cursor.execute(count_query, query_params)
        total = cursor.fetchone()[0]
        print(f"📊 Total records found: {total}")
        
        # Build ORDER BY - use epoch timestamps for date columns
        if sort == 'mtime_epoch':
            order_column = 'mtime_epoch'
        elif sort == 'atime_epoch':
            order_column = 'atime_epoch'
        elif sort == 'crtime_epoch':
            order_column = 'crtime_epoch'
        else:
            order_column = sort
            
        order_sql = f"ORDER BY {order_column} {sort_dir.upper()}"
        
        # Get paginated data
        data_query = f"""
            SELECT name, size, atime, mtime, crtime, noteworthy, file_type, bodyfile_source 
            FROM files 
            {where_sql}
            {order_sql}
            LIMIT {size} OFFSET {offset}
        """
        
        print(f"📊 Data query: {data_query}")
        
        cursor.execute(data_query, query_params)
        
        files = []
        for row in cursor.fetchall():
            files.append({
                'name': row[0],
                'size': row[1],
                'atime': row[2],
                'mtime': row[3],
                'crtime': row[4],
                'noteworthy': row[5],
                'file_type': row[6],
                'bodyfile_source': row[7]
            })
        
        conn.close()
        
        print(f"📊 Returning {len(files)} files")
        
        # Prepare response
        response = {
            'files': files,
            'page': page,
            'size': size,
            'total': total,
            'start': offset + 1,
            'end': min(offset + size, total)
        }
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def handle_export_api(self):
        import urllib.parse
        from urllib.parse import parse_qs
        
        query = urllib.parse.urlparse(self.path).query
        params = parse_qs(query)
        format = params.get('format', ['csv'])[0]
        search = params.get('search', [''])[0]
        file_types = params.get('file_types', [''])[0]
        flags = params.get('flags', [''])[0]
        bodyfile = params.get('bodyfile', ['all'])[0]
        mtime_start = params.get('mtime_start', [''])[0]
        mtime_end = params.get('mtime_end', [''])[0]
        atime_start = params.get('atime_start', [''])[0]
        atime_end = params.get('atime_end', [''])[0]
        regex = int(params.get('regex', [0])[0])
        hash_search = params.get('hash', [''])[0]
        min_size = params.get('min_size', [''])[0]
        uid_filter = params.get('uid', [''])[0]
        gid_filter = params.get('gid', [''])[0]
        dir_filter = params.get('dir', [''])[0]
        
        conn = sqlite3.connect(self.db_path)
        
        # Fixed regex function with error handling
        def regexp(expr, item):
            if item is None:
                return False
            try:
                return re.search(expr, item) is not None
            except re.error:
                return False
        
        conn.create_function("REGEXP", 2, regexp)
        cursor = conn.cursor()
        
        # Build WHERE clause (same as data_api)
        where_clauses = []
        query_params = []
        
        if search:
            if regex:
                where_clauses.append("name REGEXP ?")
                query_params.append(search)
            else:
                where_clauses.append("name LIKE ?")
                query_params.append(f'%{search}%')
        
        if hash_search:
            where_clauses.append("md5 LIKE ?")
            query_params.append(f'%{hash_search}%')
        
        if min_size and min_size.isdigit():
            where_clauses.append("size >= ?")
            query_params.append(int(min_size))
        
        if uid_filter:
            where_clauses.append("uid = ?")
            query_params.append(uid_filter)
        
        if gid_filter:
            where_clauses.append("gid = ?")
            query_params.append(gid_filter)
        
        if dir_filter:
            where_clauses.append("name LIKE ?")
            query_params.append(dir_filter)
        
        if file_types and file_types != 'all':
            file_type_list = file_types.split(',')
            placeholders = ','.join(['?'] * len(file_type_list))
            where_clauses.append(f"file_type IN ({placeholders})")
            query_params.extend(file_type_list)
        
        if flags and flags != 'all':
            flag_list = flags.split(',')
            flag_conditions = []
            for flag in flag_list:
                flag_conditions.append("noteworthy LIKE ?")
                query_params.append(f'%{flag}%')
            where_clauses.append(f"({' OR '.join(flag_conditions)})")
        
        if bodyfile and bodyfile != 'all':
            where_clauses.append("bodyfile_source = ?")
            query_params.append(bodyfile)
            
        if mtime_start:
            where_clauses.append("mtime_epoch >= ?")
            query_params.append(int(datetime.strptime(mtime_start, '%Y-%m-%d').timestamp()))
        if mtime_end:
            where_clauses.append("mtime_epoch <= ?")
            query_params.append(int(datetime.strptime(mtime_end, '%Y-%m-%d').timestamp()) + 86399)
            
        if atime_start:
            where_clauses.append("atime_epoch >= ?")
            query_params.append(int(datetime.strptime(atime_start, '%Y-%m-%d').timestamp()))
        if atime_end:
            where_clauses.append("atime_epoch <= ?")
            query_params.append(int(datetime.strptime(atime_end, '%Y-%m-%d').timestamp()) + 86399)
        
        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        cursor.execute(f"SELECT * FROM files {where_sql} LIMIT 10000", query_params)
        rows = cursor.fetchall()
        
        conn.close()
        
        if format == 'json':
            files = []
            for row in rows:
                files.append({
                    'md5': row[1],
                    'name': row[2],
                    'inode': row[3],
                    'mode': row[4],
                    'uid': row[5],
                    'gid': row[6],
                    'size': row[7],
                    'atime': row[8],
                    'mtime': row[9],
                    'ctime': row[10],
                    'crtime': row[11],
                    'noteworthy': row[12],
                    'file_type': row[13],
                    'bodyfile_source': row[18]
                })
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Content-Disposition', 'attachment; filename="forensic_export.json"')
            self.end_headers()
            self.wfile.write(json.dumps(files).encode())
        else:  # CSV
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Name', 'Size', 'Accessed', 'Modified', 'Created', 'File Type', 'Bodyfile', 'Flags'])
            
            for row in rows:
                writer.writerow([row[2], row[7], row[8], row[9], row[11], row[13], row[18], row[12]])
            
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header('Content-Disposition', 'attachment; filename="forensic_export.csv"')
            self.end_headers()
            self.wfile.write(output.getvalue().encode())
    
    def handle_add_bodyfile(self):
        """Handle adding new bodyfile while server is running"""
        try:
            flag_file = os.path.join(os.path.dirname(self.db_path), "ADD_BODYFILE.flag")
            with open(flag_file, "w") as f:
                f.write("1")
            
            response = {"success": True, "message": "File dialog should open shortly"}
        except Exception as e:
            response = {"success": False, "error": str(e)}
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

def __PLACEHOLDER_bf_bf_start_server(db_path, port=8000):
    """Start the local web server with bodyfile addition support"""
    handler = lambda *args: BfForensicRequestHandler(*args, db_path=db_path)
    
    try:
        server = HTTPServer(('localhost', port), handler)
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"⚠️  Port {port} is in use, looking for next available port...")
            port = bf_get_available_port(port + 1)
            server = HTTPServer(('localhost', port), handler)
            print(f"✅ Using port {port} instead")
        else:
            raise
    
    print(f"🚀 Starting local server on http://localhost:{port}")
    print("💡 The HTML report will load data on-demand for fast performance")
    
    # Check for add bodyfile flag
    flag_file = os.path.join(os.path.dirname(db_path), "ADD_BODYFILE.flag")
    
    def check_for_new_bodyfile():
        while True:
            time.sleep(2)
            if os.path.exists(flag_file):
                try:
                    os.remove(flag_file)
                    print("\n📁 Add Bodyfile request detected...")
                    root = tk.Tk()
                    root.withdraw()
                    
                    bodyfile_paths = filedialog.askopenfilenames(
                        title="Select Additional Bodyfile(s)",
                        filetypes=[("Bodyfile", "*.txt *.body *.log"), ("All files", "*.*")]
                    )
                    
                    if bodyfile_paths:
                        for bodyfile_path in bodyfile_paths:
                            print(f"→ Adding bodyfile: {bodyfile_path}")
                            count = bf_add_bodyfile_to_database(bodyfile_path, db_path)
                            print(f"✅ Added {count:,} records from {os.path.basename(bodyfile_path)}")
                        
                        # Update the HTML to reflect new data
                        try:
                            csv_path = db_path.replace('.db', '.csv')
                            bf_generate_lightweight_html(db_path, csv_path, port)
                            print("✅ HTML report updated with new data")
                        except Exception as e:
                            print(f"⚠️  Could not update HTML: {e}")
                    else:
                        print("❌ No bodyfile selected")
                        
                    root.destroy()
                except Exception as e:
                    print(f"❌ Error adding bodyfile: {e}")
    
    # Start the flag checker in background
    flag_thread = threading.Thread(target=check_for_new_bodyfile, daemon=True)
    flag_thread.start()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")

# -------------------------------------------------------------------
# Initial Setup Dialog
# -------------------------------------------------------------------

def bf_show_initial_dialog():
    """Show initial dialog to open existing or create new database"""
    root = tk.Tk()
    root.title("Forensic Explorer - Setup")
    root.geometry("400x200")
    root.resizable(False, False)
    
    result = {"action": None, "db_path": None, "html_path": None}
    
    def create_new():
        result["action"] = "new"
        root.quit()
        root.destroy()
    
    def open_existing():
        db_file = filedialog.askopenfilename(
            title="Select Existing Database",
            filetypes=[("Database files", "*.db"), ("All files", "*.*")]
        )
        if db_file:
            result["action"] = "open"
            result["db_path"] = db_file
            # Look for corresponding HTML file
            html_file = db_file.replace('.db', '_report.html')
            if os.path.exists(html_file):
                result["html_path"] = html_file
            root.quit()
            root.destroy()
    
    # Center the window
    root.eval('tk::PlaceWindow . center')
    
    tk.Label(root, text="Forensic Explorer", font=("Arial", 16, "bold")).pack(pady=20)
    tk.Label(root, text="Start with new analysis or open existing database?").pack(pady=10)
    
    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=20)
    
    tk.Button(btn_frame, text="Create New Analysis", command=create_new, width=20, height=2).pack(side=tk.LEFT, padx=10)
    tk.Button(btn_frame, text="Open Existing Database", command=open_existing, width=20, height=2).pack(side=tk.LEFT, padx=10)
    
    root.mainloop()
    return result

# -------------------------------------------------------------------
# Main Conversion Function
# -------------------------------------------------------------------

def bf_convert_and_generate_report(bodyfile_paths, output_csv_path, date_filter=None):
    rows = []
    processed = 0

    for bodyfile_path in bodyfile_paths:
        bodyfile_name = os.path.basename(bodyfile_path)
        with open(bodyfile_path, "r", encoding="utf-8", errors="ignore") as infile:
            reader = csv.reader(infile, delimiter="|")
            for row in reader:
                processed += 1
                if len(row) not in (10, 11):
                    continue

                if len(row) == 11:
                    md5, name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime = row
                else:
                    md5, name, inode, mode, uid, gid, size, atime, mtime, ctime = row
                    crtime = ""

                noteworthy, file_type = bf_assess_noteworthy(name, mode, atime, mtime, ctime, crtime)

                row_dict = {
                    "MD5": md5,
                    "Name": name,
                    "Inode": inode,
                    "Mode": mode,
                    "UID": uid,
                    "GID": gid,
                    "Size": size,
                    "Atime": bf_convert_epoch_to_str(atime),
                    "Mtime": bf_convert_epoch_to_str(mtime),
                    "Ctime": bf_convert_epoch_to_str(ctime),
                    "Crtime": bf_convert_epoch_to_str(crtime),
                    "Noteworthy": noteworthy,
                    "FileType": file_type,
                    "_atime_epoch": int(atime) if atime and atime.isdigit() else 0,
                    "_mtime_epoch": int(mtime) if mtime and mtime.isdigit() else 0,
                    "_ctime_epoch": int(ctime) if ctime and ctime.isdigit() else 0,
                    "_crtime_epoch": int(crtime) if crtime and crtime.isdigit() else 0,
                }

                rows.append(row_dict)

    # Apply date range filtering if requested
    if date_filter and date_filter["apply_filter"]:
        rows = bf_filter_rows_by_date_range(rows, date_filter)

    # Ensure output files have proper extensions
    if not output_csv_path.endswith('.csv'):
        output_csv_path += '.csv'
    
    # Write CSV
    csv_headers = ["MD5","Name","Inode","Mode","UID","GID","Size",
                   "Atime (Accessed)","Mtime (Modified)","Ctime (Changed)","Crtime (Created)",
                   "Noteworthy","FileType"]
    with open(output_csv_path, "w", newline="", encoding="utf-8") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(csv_headers)
        for r in rows:
            writer.writerow([
                r["MD5"], r["Name"], r["Inode"], r["Mode"], r["UID"], r["GID"], r["Size"],
                r["Atime"], r["Mtime"], r["Ctime"], r["Crtime"], r["Noteworthy"], r["FileType"]
            ])

    print(f"\n✅ CSV written: {output_csv_path}")
    print(f"→ Processed records: {len(rows):,}")

    # Create database for fast access - ensure .db extension
    db_path = output_csv_path.replace('.csv', '.db')
    bf_create_database(rows, db_path, bodyfile_name)

    # Verify the database contents
    print("🔍 Verifying database contents...")
    if not bf_verify_database_contents(db_path):
        print("❌ Database verification failed - no data found")
        return

    # Check database schema
    bf_check_database_schema(db_path)
    
    # Test database queries
    bf_test_database_query(db_path)

    # Get available port (starting from 8000)
    port = bf_get_available_port(8000)
    
    # Generate lightweight HTML and start server
    html_path = bf_generate_lightweight_html(db_path, output_csv_path, port)
    
    print(f"✅ Lightweight HTML report: {html_path}")
    print(f"📊 HTML file size: {os.path.getsize(html_path) / 1024:.1f} KB")
    print(f"🌐 Opening browser on port {port}...")
    
    # Start server in background thread
    server_thread = threading.Thread(target=start_server, args=(db_path, port), daemon=True)
    server_thread.start()
    
    # Wait a moment for server to start, then open browser
    time.sleep(2)
    webbrowser.open(f'http://localhost:{port}/{os.path.basename(html_path)}')
    
    print("\n💡 The server is running in the background. Press Ctrl+C to stop when done.")
    print("💡 You can add more bodyfiles using the 'Add Bodyfile' button in the web interface.")
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")

# -------------------------------------------------------------------
# Main Function
# -------------------------------------------------------------------


def menu_bodyfile_explorer():
    """Menu for Bodyfile → CSV + Forensic Explorer tool"""
    header("BODYFILE → CSV + FORENSIC EXPLORER")
    info("Convert bodyfiles to CSV and launch interactive web-based Forensic Explorer")
    print()

    while True:
        print(f"  {_c(C.CYAN, '[1]')} New Analysis  {_c(C.DIM, 'convert bodyfile(s) → CSV + HTML report')}")
        print(f"  {_c(C.CYAN, '[2]')} Open Existing Database  {_c(C.DIM, 'reload a previous .db file')}")
        print(f"  {_c(C.RED,  '[0]')} Back")
        divider()
        ch = prompt("Choice:").strip()

        if ch == "1":
            clear_screen()
            header("NEW BODYFILE ANALYSIS")
            root = tk.Tk()
            root.withdraw()

            info("Select input bodyfile(s)...")
            bodyfile_paths = filedialog.askopenfilenames(
                title="Select Bodyfile (v2/v3)",
                filetypes=[("Bodyfile", "*.txt *.body *.log"), ("All files", "*.*")]
            )
            root.destroy()
            if not bodyfile_paths:
                warn("No input file selected.")
                pause()
                continue

            ok(f"Selected {len(bodyfile_paths)} bodyfile(s)")

            root2 = tk.Tk()
            root2.withdraw()
            info("Choose output CSV location...")
            output_csv = filedialog.asksaveasfilename(
                title="Save CSV As",
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            root2.destroy()
            if not output_csv:
                warn("No output file selected.")
                pause()
                continue

            ok(f"CSV will be saved to: {output_csv}")

            info("Configuring date range filter...")
            date_filter = bf_ask_date_range_filter()

            if date_filter["apply_filter"]:
                date_type_names = {
                    "mtime": "Modified Time", "atime": "Access Time",
                    "ctime": "Change Time",   "crtime": "Creation Time"
                }
                dtype = date_type_names.get(date_filter["date_type"], date_filter["date_type"])
                s = date_filter["start_date"].strftime('%Y-%m-%d') if date_filter["start_date"] else "Beginning"
                e = date_filter["end_date"].strftime('%Y-%m-%d')   if date_filter["end_date"]   else "Now"
                ok(f"Date filter: {dtype} from {s} to {e}")
            else:
                info("No date filtering applied")

            info("Converting bodyfile(s)...")
            try:
                bf_convert_and_generate_report(bodyfile_paths, output_csv, date_filter)
            except Exception as exc:
                err(f"Conversion error: {exc}")
                import traceback; traceback.print_exc()
                pause()

        elif ch == "2":
            clear_screen()
            header("OPEN EXISTING DATABASE")
            root = tk.Tk()
            root.withdraw()
            db_file = filedialog.askopenfilename(
                title="Select Existing Database",
                filetypes=[("Database files", "*.db"), ("All files", "*.*")]
            )
            root.destroy()
            if not db_file:
                warn("No file selected.")
                pause()
                continue

            if not bf_verify_database_contents(db_file):
                err("Database is empty or corrupted.")
                pause()
                continue

            html_file = db_file.replace('.db', '_report.html')
            if not os.path.exists(html_file):
                err("Corresponding HTML file not found. Please create a new analysis.")
                pause()
                continue

            port = bf_get_available_port(8000)
            srv_thread = threading.Thread(
                target=bf_start_server, args=(db_file, port), daemon=True
            )
            srv_thread.start()
            time.sleep(2)
            webbrowser.open(f'http://localhost:{port}/{os.path.basename(html_file)}')
            ok("Existing database loaded. Press Ctrl+C or close terminal tab to stop server.")

            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            break

        elif ch == "0":
            break
        else:
            err("Invalid choice.")

BANNER = f"""
{_c(C.CYAN, '━' * 62)}
{_c(C.BOLD + C.CYAN, '  ██████╗ ███████╗██╗██████╗ ██╗  ██╗ █████╗ ██╗     ██╗██╗  ████████╗')}
{_c(C.BOLD + C.CYAN, '  ██╔══██╗██╔════╝██║██╔══██╗██║  ██║██╔══██╗██║     ██║██║  ╚══██╔══╝')}
{_c(C.BOLD + C.CYAN, '  ██║  ██║█████╗  ██║██████╔╝██║  ██║███████║██║     ██║██║     ██║   ')}
{_c(C.BOLD + C.CYAN, '  ██║  ██║██╔══╝  ██║██╔══██╗╚██╗██╔╝██╔══██║╚██╗   ██╔╝██║     ██║   ')}
{_c(C.BOLD + C.CYAN, '  ██████╔╝██║     ██║██║  ██║ ╚███╔╝ ██║  ██║ ╚██████╔╝ ███████╗██║   ')}
{_c(C.BOLD + C.CYAN, '  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝  ╚══╝  ╚═╝  ╚═╝  ╚═════╝  ╚══════╝╚═╝   ')}
{_c(C.DIM,   '  DFIR Operations Console                        ')}
{_c(C.DIM,   '  Developed by Jacob Wilson  •  dfirvault@gmail.com      ')}
{_c(C.CYAN, '━' * 62)}
"""


def main():
    if not IS_WINDOWS:
        err("This tool is designed for Windows systems only.")
        sys.exit(1)
    
    clear_screen()
    print(BANNER)
    while True:
        print(f"\n  {_c(C.BOLD+C.WHITE, '─── DFIR CASE MANAGEMENT ─────────────────')}")
        print(f"  {_c(C.CYAN,'[1]')} DFIR Case Manager")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── SCANNING TOOLS ────────────────────────')}")
        print(f"  {_c(C.CYAN,'[2]')} Hayabusa  {_c(C.DIM,'EVTX log scanner — CSV + HTML reports')}")
        print(f"  {_c(C.CYAN,'[3]')} Chainsaw  {_c(C.DIM,'EVTX hunting with Sigma rules')}")
        print(f"  {_c(C.CYAN,'[4]')} Thor      {_c(C.DIM,'Drive / filesystem IOC scanner')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── SPLUNK ─────────────────────────────────')}")
        print(f"  {_c(C.CYAN,'[5]')} Splunk Index Manager")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── ELASTICSEARCH ──────────────────────────')}")
        print(f"  {_c(C.CYAN,'[6]')} CSV → ELK  {_c(C.DIM,'upload CSV data to Elasticsearch')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── FILE SYNC & TRANSFER ───────────────────')}")
        print(f"  {_c(C.CYAN,'[7]')} SFTP / FTP Monitor")
        print(f"  {_c(C.CYAN,'[8]')} VaultMirror  {_c(C.DIM,'safe scheduled sync')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── THREAT INTELLIGENCE ────────────────────')}")
        print(f"  {_c(C.CYAN,'[9]')} CSV Log Enricher  {_c(C.DIM,'enrich logs with OTX / AbuseIPDB / IP2Location / Tor')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── FORENSIC TIMELINE ──────────────────────')}")
        print(f"  {_c(C.CYAN,'[10]')} Bodyfile Explorer  {_c(C.DIM,'bodyfile → CSV + interactive forensic analysis')}")
        print()
        print(f"  {_c(C.RED,'[0]')} Exit")
        divider()
        choice = prompt("Select section:").strip()
        if   choice == "1": clear_screen(); menu_case_manager()
        elif choice == "2": clear_screen(); menu_hayabusa()
        elif choice == "3": clear_screen(); menu_chainsaw()
        elif choice == "4": clear_screen(); menu_thor()
        elif choice == "5": clear_screen(); menu_splunk()
        elif choice == "6": clear_screen(); menu_csv2elk()
        elif choice == "7": clear_screen(); menu_sftp()
        elif choice == "8": clear_screen(); menu_vault_mirror()
        elif choice == "9": clear_screen(); menu_log_enricher()
        elif choice == "10": clear_screen(); menu_bodyfile_explorer()
        elif choice == "0":
            print(); ok("Goodbye. Stay forensically sound."); print(); sys.exit(0)
        else:
            err("Invalid choice. Enter 1-10 or 0.")
        clear_screen()
        print(BANNER)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--run-task":
        script = sys.argv[2]
        if os.path.exists(script):
            code = open(script, encoding="utf-8").read()
            exec(compile(code, script, "exec"), {
                "os": os, "json": json, "shutil": shutil, "Path": Path, "__name__": "__main__"
            })
    else:
        try:
            main()
        except KeyboardInterrupt:
            print(); warn("Interrupted."); sys.exit(0)
