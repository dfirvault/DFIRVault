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
  11. CSV Splitter           — split large CSV files by size or line count
  12. CSV Timestamp Cleaner  — normalise timestamps to DD/MM/YYYY HH:MM:SS
  13. Qemu menu              — convert forensic image formats
  14. VolMenu                — Volatility3 menu wrapper
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
import sqlite3
import threading
import subprocess
import webbrowser
from pathlib import Path
from datetime import datetime, timedelta
from http.server import HTTPServer, SimpleHTTPRequestHandler
import tkinter as tk
from tkinter import filedialog, messagebox, Listbox, Scrollbar, ttk

IS_WINDOWS = platform.system() == "Windows"
CURRENT_VERSION  = "v0.6.3"
_GH_RELEASES_API = "https://api.github.com/repos/dfirvault/DFIRVault/releases/latest"
_UPDATE_REG_SECTION = "AutoUpdate"

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

try:
    import pandas as _pd
    _PANDAS_OK = True
except ImportError:
    _PANDAS_OK = False

try:
    from tqdm import tqdm as _tqdm
    _TQDM_OK = True
except ImportError:
    _TQDM_OK = False

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
# AUTO-UPDATE SYSTEM
# Checks GitHub Releases API on startup and self-replaces the .exe
# Registry key: HKCU\Software\DFIRVault\AutoUpdate
#   SkipVersion  REG_SZ  — version tag to skip (e.g. "v0.7")
#
# Update flow (frozen .exe only):
#   1. Fetch latest release metadata from GitHub API
#   2. Compare versions — bail out if already current
#   3. Prompt user: Update now / Skip this version / Remind me later
#   4. Download asset to <exe_dir>\DFIRVault_update_<tag>.exe
#   5. Ask user to confirm close; user confirms
#   6. Write %TEMP%\dfirvault_update.bat that:
#        a. taskkill /F all DFIRVault*.exe instances
#        b. Loop until old exe file-lock is released
#        c. move /Y new → old (atomic replace on same volume)
#        d. start "" <old path>   (launch updated exe)
#        e. del "%~f0"            (self-delete batch)
#   7. Launch batch detached, sys.exit(0) current process
# ──────────────────────────────────────────────────────────────────

def _upd_parse_version(tag: str):
    """Convert a tag like 'v0.6' → (0, 6, 0) or 'v0.6.1' → (0, 6, 1).
    Returns (0, 0, 0) on failure."""
    try:
        nums = re.findall(r'\d+', tag)
        while len(nums) < 3:
            nums.append('0')
        return tuple(int(n) for n in nums[:3])
    except Exception:
        return (0, 0, 0)


def _upd_newer(remote_tag: str, local_tag: str) -> bool:
    """Return True if remote_tag is strictly newer than local_tag."""
    return _upd_parse_version(remote_tag) > _upd_parse_version(local_tag)


def _upd_show_error_dialog(message: str):
    """Show a tkinter error popup."""
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        messagebox.showerror("DFIRVault — Update Failed", message)
        root.destroy()
    except Exception:
        pass


def _upd_download_with_progress(url: str, dest_path: str) -> bool:
    """Stream-download url to dest_path with a console progress bar.
    Downloads to a .part file first; renames on success."""
    part_path = dest_path + ".part"
    try:
        import urllib.request as _ureq

        req = _ureq.Request(url, headers={"User-Agent": f"DFIRVault/{CURRENT_VERSION}"})
        with _ureq.urlopen(req, timeout=120) as resp:
            total      = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 65536
            print()
            with open(part_path, "wb") as fout:
                while True:
                    data = resp.read(chunk_size)
                    if not data:
                        break
                    fout.write(data)
                    downloaded += len(data)
                    if total:
                        progress_bar(downloaded, total,
                                     label=f"{downloaded/1_048_576:.1f} / {total/1_048_576:.1f} MB")
        print()
        os.replace(part_path, dest_path)
        return True
    except Exception as e:
        err(f"Download error: {e}")
        if os.path.exists(part_path):
            try:
                os.remove(part_path)
            except Exception:
                pass
        return False


def _upd_write_and_launch_bat(own_exe: Path, new_exe: Path):
    """
    Write a self-replacing batch file to %TEMP% then launch it detached.
    The batch:
      1. taskkill /F /IM <exe_name> — kill all running instances
      2. Loop until file lock is released (robust replace)
      3. move /Y <new_exe> <own_exe>
      4. start "" <own_exe>
      5. del "%~f0"
    """
    bat_path = Path(os.environ.get("TEMP", str(own_exe.parent))) / "dfirvault_update.bat"
    exe_name = own_exe.name

    bat = (
        "@echo off\n"
        "setlocal\n"
        "\n"
        f'set "TARGET={own_exe}"\n'
        f'set "NEWFILE={new_exe}"\n'
        'set "SELF=%~f0"\n'
        "\n"
        ":: ── Kill all running DFIRVault instances ──────────────────\n"
        f'taskkill /F /IM "{exe_name}" /T >nul 2>&1\n'
        "\n"
        ":: ── Wait until the old exe file-lock is released ──────────\n"
        ":waitloop\n"
        "timeout /t 1 /nobreak >nul\n"
        '2>nul (\n'
        '    >>"%TARGET%" echo off\n'
        ') || goto waitloop\n'
        "\n"
        ":: ── Replace the exe ────────────────────────────────────────\n"
        'move /Y "%NEWFILE%" "%TARGET%" >nul\n'
        "if errorlevel 1 (\n"
        "    echo Update failed: could not replace executable.\n"
        "    pause\n"
        "    goto cleanup\n"
        ")\n"
        "\n"
        ":: ── Start updated DFIRVault ─────────────────────────────────\n"
        'start "" "%TARGET%"\n'
        "\n"
        ":cleanup\n"
        ":: ── Delete this batch file ──────────────────────────────────\n"
        'del /F /Q "%SELF%"\n'
    )

    bat_path.write_text(bat, encoding="ascii")

    subprocess.Popen(
        ["cmd.exe", "/c", str(bat_path)],
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        close_fds=True,
    )


def check_for_updates():
    """
    Entry-point called from main() before the menu loop.
    Silently returns if:
      • not running as a frozen .exe
      • no internet / GitHub unreachable
      • already on latest version
      • user previously chose to skip this version
    """
    if not getattr(sys, "frozen", False):
        return  # .py script — no auto-update

    own_exe = Path(sys.executable)

    # ── 1. Fetch latest release from GitHub ───────────────────────
    try:
        import urllib.request as _ureq

        req = _ureq.Request(
            _GH_RELEASES_API,
            headers={
                "User-Agent": f"DFIRVault/{CURRENT_VERSION}",
                "Accept":     "application/vnd.github+json",
            }
        )
        with _ureq.urlopen(req, timeout=8) as resp:
            release = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return  # network unavailable or rate-limited — silently skip

    remote_tag = release.get("tag_name", "").strip()
    if not remote_tag:
        return

    # ── 2. Compare versions ───────────────────────────────────────
    if not _upd_newer(remote_tag, CURRENT_VERSION):
        return  # already up to date — nothing to do

    # ── 3. Check skip-version registry preference ─────────────────
    skip_ver = RegistryConfig.load_config(_UPDATE_REG_SECTION, "SkipVersion", "")
    if skip_ver and skip_ver.strip().lower() == remote_tag.lower():
        return  # user previously skipped this exact version

    # ── 4. Find the .exe asset in the release ─────────────────────
    exe_asset = None
    for asset in release.get("assets", []):
        if asset.get("name", "").lower().endswith(".exe"):
            exe_asset = asset
            break

    if not exe_asset:
        return  # no .exe published yet for this release

    dl_url   = exe_asset["browser_download_url"]
    new_size = exe_asset.get("size", 0)
    body     = (release.get("body") or "").strip()

    # ── 5. Prompt the user ────────────────────────────────────────
    clear_screen()
    header("UPDATE AVAILABLE")
    print()
    info(f"Current version : {_c(C.YELLOW, CURRENT_VERSION)}")
    info(f"Latest version  : {_c(C.GREEN + C.BOLD, remote_tag)}")
    if new_size:
        info(f"Download size   : {new_size / 1_048_576:.1f} MB")
    if body:
        print()
        print(f"  {_c(C.DIM, 'Release notes:')}")
        for line in body.splitlines()[:8]:
            print(f"    {_c(C.DIM, line)}")
    print()
    print(f"  {_c(C.CYAN,   '[1]')} Update now")
    print(f"  {_c(C.YELLOW, '[2]')} Skip this version")
    print(f"  {_c(C.RED,    '[3]')} Remind me later")
    divider()
    choice = prompt("Choice:").strip()

    if choice == "2":
        RegistryConfig.save_config(_UPDATE_REG_SECTION, "SkipVersion", remote_tag)
        info(f"Version {remote_tag} will be skipped.")
        time.sleep(1)
        return

    if choice != "1":
        return  # "3" or anything else → remind me later

    # ── 6. Download the new .exe to the same folder as current ────
    subheader("Downloading Update")
    # Download sits next to the current exe so move /Y is same-volume (atomic)
    new_exe = own_exe.parent / f"DFIRVault_update_{remote_tag.lstrip('v')}.exe"

    info(f"Downloading {exe_asset['name']} …")
    if not _upd_download_with_progress(dl_url, str(new_exe)):
        _upd_show_error_dialog(
            f"DFIRVault could not download the update.\n\n"
            f"Please download {remote_tag} manually from:\n"
            f"https://github.com/dfirvault/DFIRVault/releases"
        )
        return

    ok(f"Download complete → {new_exe.name}")

    # ── 7. Final confirmation before closing ──────────────────────
    print()
    warn("DFIRVault will close so the updater can replace the executable.")
    warn("It will relaunch automatically once the update is complete.")
    print()
    print(f"  {_c(C.CYAN, '[1]')} Confirm — close and apply update")
    print(f"  {_c(C.RED,  '[0]')} Cancel")
    divider()
    if prompt("Choice:").strip() != "1":
        warn("Update cancelled.")
        try:
            new_exe.unlink()
        except Exception:
            pass
        return

    # ── 8. Write batch + detach, then exit ───────────────────────
    subheader("Applying Update")
    info("Launching updater — DFIRVault will restart automatically…")
    time.sleep(1)

    try:
        _upd_write_and_launch_bat(own_exe, new_exe)
    except Exception as exc:
        err(f"Could not launch updater batch: {exc}")
        _upd_show_error_dialog(
            f"DFIRVault could not launch the updater.\n\nError: {exc}\n\n"
            f"You can install the update manually:\n{new_exe}"
        )
        return

    sys.exit(0)  # hand over to the batch file



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
#  SECTION 6 — CSV → ELASTICSEARCH (CSV2ELK)  v0.3
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
        "url":      RegistryConfig.load_config("Elasticsearch", "url",      ""),
        "username": RegistryConfig.load_config("Elasticsearch", "username", ""),
        "password": RegistryConfig.load_config("Elasticsearch", "password", "")
    }
    return config

def _elk_save_config(url, user, pw):
    """Save ELK config to registry"""
    RegistryConfig.save_config("Elasticsearch", "url",      url)
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
        return [i for i in r.json()
                if not (i["index"].startswith(".") or i["index"].startswith("log"))]
    err("Error retrieving index info."); return []

def _elk_create_index(url, user, pw, base_name, req):
    base_name  = _elk_sanitize_index(base_name)
    today      = datetime.today().strftime("%Y%m%d")
    index_name = f"{base_name}_{today}"
    mapping    = {"mappings": {"properties": {"timestamp_field": {"type": "date"}}}}
    r = req.put(f"{url}/{index_name}", auth=(user, pw),
                headers={"Content-Type": "application/json"},
                data=json.dumps(mapping), verify=False)
    if r.status_code == 200:
        ok(f"Index '{index_name}' created.")
    else:
        err(f"Failed to create index: {r.status_code} — {r.text}")
    return index_name

def _elk_ensure_index_exists(url, user, pw, index_name, req):
    """Create the index if it does not already exist. Returns True on success."""
    r = req.head(f"{url}/{index_name}", auth=(user, pw), verify=False)
    if r.status_code == 200:
        return True
    mapping = {"mappings": {"properties": {"timestamp_field": {"type": "date"}}}}
    r2 = req.put(f"{url}/{index_name}", auth=(user, pw),
                 headers={"Content-Type": "application/json"},
                 data=json.dumps(mapping), verify=False)
    if r2.status_code in (200, 201):
        ok(f"Index '{index_name}' created.")
        return True
    err(f"Could not create index '{index_name}': {r2.status_code} — {r2.text}")
    return False

def _elk_guess_ts(columns):
    priority = ["timestamp", "@timestamp", "time", "datetime", "date"]
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
        seen = {}; dedup_cols = []
        for col in df.columns:
            if col not in seen:
                seen[col] = 0; dedup_cols.append(col)
            else:
                seen[col] += 1; dedup_cols.append(f"{col}_{seen[col]}")
        df.columns = dedup_cols
        df.columns = [_elk_sanitize_col(c) for c in df.columns]

        def clean(obj):
            if isinstance(obj, dict):  return {k: clean(v) for k, v in obj.items()}
            if isinstance(obj, list):  return [clean(v) for v in obj]
            if isinstance(obj, float):
                if pd.isna(obj) or obj in (float("inf"), float("-inf")): return None
            return obj

        json_path = csv_path.replace(".csv", ".json")
        total = len(df)
        print()
        with open(json_path, "w", encoding="utf-8") as f:
            for i, (_, row) in enumerate(df.iterrows(), 1):
                action   = {"index": {"_index": index_name}}
                f.write(json.dumps(action, ensure_ascii=False) + "\n")
                row_dict = row.to_dict()
                if ts_col and ts_col in row_dict:
                    tv = row_dict[ts_col]
                    if pd.notna(tv) and str(tv).strip():
                        try:
                            tf  = float(tv)
                            iso = (datetime.utcfromtimestamp(tf / 1000 if tf > 1e12 else tf)
                                   .isoformat() + "Z")
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
    chunk_size = 10_000
    def chunks():
        with open(json_path, "r", encoding="utf-8") as f:
            chunk = []
            for i, line in enumerate(f, 1):
                chunk.append(line)
                if i % chunk_size == 0:
                    yield "".join(chunk); chunk = []
            if chunk: yield "".join(chunk)
    all_chunks = list(chunks())
    total      = len(all_chunks)
    print()
    success = True
    for i, chunk in enumerate(all_chunks, 1):
        progress_bar(i, total, label="Uploading chunks")
        for attempt in range(1, 31):
            try:
                r = req.post(f"{url}/{index_name}/_bulk", auth=(user, pw),
                             headers={"Content-Type": "application/x-ndjson"},
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
        print(f"  {_c(C.CYAN,f'[{i}]')} {e['index']}  "
              f"{_c(C.DIM, docs + ' docs  ' + e['store.size'])}")
    print()
    raw = prompt("Select index:").strip()
    if raw == "0": return None
    try: return indices[int(raw) - 1]["index"]
    except (ValueError, IndexError):
        err("Invalid selection."); return None


# ──────────────────────────────────────────────────────────────────
#  NEW ①  EXPORT INDEX → NDJSON ZIP
# ──────────────────────────────────────────────────────────────────
def _elk_export_index(url, user, pw, req):
    """
    Scroll through every document in a chosen index and write them as
    NDJSON, then compress into a ZIP the user picks the destination for.

    Output filename:  <index>_export_<YYYYMMDD_HHMMSS>.ndjson.zip
    The ZIP contains a single file:  <index>_export.ndjson
    """
    subheader("Export Index → NDJSON ZIP")

    # ── pick index ────────────────────────────────────────────────
    idx = _elk_pick_index(url, user, pw, req)
    if not idx:
        return

    # ── count docs so we can show a proper progress bar ──────────
    count_r = req.get(f"{url}/{idx}/_count", auth=(user, pw), verify=False)
    total_docs = 0
    if count_r.status_code == 200:
        total_docs = count_r.json().get("count", 0)
    info(f"Index '{idx}' contains {total_docs:,} document(s).")

    # ── pick destination folder ───────────────────────────────────
    info("Select destination folder for the export…")
    dest_folder = pick_folder("Select export destination")
    if not dest_folder:
        warn("Cancelled."); return

    stamp      = datetime.now().strftime("%Y%m%d_%H%M%S")
    ndjson_name = f"{idx}_export.ndjson"
    zip_name    = f"{idx}_export_{stamp}.ndjson.zip"
    zip_path    = os.path.join(dest_folder, zip_name)
    tmp_ndjson  = os.path.join(dest_folder, ndjson_name)

    # ── scroll API ───────────────────────────────────────────────
    BATCH   = 1000
    scroll  = "2m"
    payload = {"query": {"match_all": {}}, "size": BATCH}

    try:
        info("Initialising scroll…")
        r = req.post(f"{url}/{idx}/_search?scroll={scroll}",
                     auth=(user, pw), verify=False,
                     headers={"Content-Type": "application/json"},
                     data=json.dumps(payload))
        if r.status_code != 200:
            err(f"Scroll init failed: {r.status_code} — {r.text}"); return

        data      = r.json()
        scroll_id = data.get("_scroll_id")
        hits      = data.get("hits", {}).get("hits", [])
        written   = 0
        print()

        with open(tmp_ndjson, "w", encoding="utf-8") as ndf:
            while hits:
                for doc in hits:
                    ndf.write(json.dumps(doc["_source"], ensure_ascii=False) + "\n")
                    written += 1
                if total_docs:
                    progress_bar(written, total_docs, label="Exporting docs")
                else:
                    print(f"\r  Exported {written:,} docs…", end="", flush=True)

                # next scroll page
                scroll_r = req.post(f"{url}/_search/scroll",
                                    auth=(user, pw), verify=False,
                                    headers={"Content-Type": "application/json"},
                                    data=json.dumps({"scroll": scroll,
                                                     "scroll_id": scroll_id}))
                if scroll_r.status_code != 200:
                    break
                scroll_data = scroll_r.json()
                scroll_id   = scroll_data.get("_scroll_id", scroll_id)
                hits        = scroll_data.get("hits", {}).get("hits", [])

        print()

        # clear the scroll context (best-effort)
        try:
            req.delete(f"{url}/_search/scroll",
                       auth=(user, pw), verify=False,
                       headers={"Content-Type": "application/json"},
                       data=json.dumps({"scroll_id": scroll_id}))
        except: pass

        # ── compress to zip ───────────────────────────────────────
        info(f"Compressing {written:,} documents → {zip_name}…")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(tmp_ndjson, ndjson_name)

        # clean up temp file
        try: os.remove(tmp_ndjson)
        except: pass

        ok(f"Export complete: {written:,} docs → {zip_path}")
        if IS_WINDOWS:
            try: os.startfile(dest_folder)
            except: pass

    except Exception as e:
        err(f"Export failed: {e}")
        try: os.remove(tmp_ndjson)
        except: pass


# ──────────────────────────────────────────────────────────────────
#  NEW ②  IMPORT NDJSON ZIP → INDEX
# ──────────────────────────────────────────────────────────────────
def _elk_import_index(url, user, pw, req):
    """
    Import documents from an NDJSON ZIP (or raw .ndjson) into an
    Elasticsearch index chosen by the user. The target index is
    created automatically if it does not already exist.

    Expected file formats
    ---------------------
      • A .zip containing exactly one *.ndjson file  (produced by the
        Export function above, or by any other Scroll-API dump)
      • A plain .ndjson file where every line is one JSON document
    """
    subheader("Import NDJSON → Elasticsearch Index")

    # ── pick source file ─────────────────────────────────────────
    info("Select the NDJSON ZIP or plain NDJSON file to import…")
    src_file = pick_file(
        "Select NDJSON export file",
        filetypes=[("NDJSON / ZIP", "*.zip *.ndjson"), ("All", "*.*")]
    )
    if not src_file:
        warn("Cancelled."); return

    # ── resolve the NDJSON content ────────────────────────────────
    ndjson_path  = None
    tmp_dir      = None
    is_zip       = src_file.lower().endswith(".zip")

    try:
        if is_zip:
            import tempfile as _tmp
            tmp_dir = _tmp.mkdtemp(prefix="dfirvault_elk_import_")
            with zipfile.ZipFile(src_file, "r") as zf:
                ndjson_members = [n for n in zf.namelist() if n.endswith(".ndjson")]
                if not ndjson_members:
                    err("ZIP contains no .ndjson file."); return
                if len(ndjson_members) > 1:
                    print()
                    for i, n in enumerate(ndjson_members, 1):
                        print(f"  {_c(C.CYAN,f'[{i}]')} {n}")
                    raw = prompt("Multiple NDJSON files found — select one:").strip()
                    try:   member = ndjson_members[int(raw) - 1]
                    except: err("Invalid selection."); return
                else:
                    member = ndjson_members[0]
                info(f"Extracting '{member}'…")
                zf.extract(member, tmp_dir)
            ndjson_path = os.path.join(tmp_dir, member)
        else:
            ndjson_path = src_file

        # count lines for the progress bar
        info("Counting records…")
        total_lines = sum(1 for _ in open(ndjson_path, "r", encoding="utf-8")
                          if _.strip())
        info(f"Found {total_lines:,} document(s) to import.")

        # ── choose / create index ─────────────────────────────────
        subheader("Target Index")
        indices = _elk_get_indices(url, user, pw, req)
        print()
        print(f"  {_c(C.CYAN,'[N]')} Create a NEW index")
        for i, e in enumerate(indices, 1):
            docs = f"{int(e['docs.count']):,}"
            print(f"  {_c(C.CYAN,f'[{i}]')} {e['index']}  "
                  f"{_c(C.DIM, docs + ' docs  ' + e['store.size'])}")
        print()

        raw = prompt("Select existing index or 'N' for new:").strip().lower()
        if raw == "n":
            base = prompt("New index name:").strip()
            if not base:
                err("Index name cannot be empty."); return
            index_name = _elk_sanitize_index(base)
            # Offer to append today's date (matches the create-index convention)
            if prompt(f"Append today's date? → '{index_name}_{datetime.today().strftime('%Y%m%d')}' (y/n):") \
                    .lower().startswith("y"):
                index_name = f"{index_name}_{datetime.today().strftime('%Y%m%d')}"
        else:
            try:
                index_name = indices[int(raw) - 1]["index"]
            except (ValueError, IndexError):
                err("Invalid selection."); return

        # ensure index exists (create if needed)
        if not _elk_ensure_index_exists(url, user, pw, index_name, req):
            return

        info(f"Importing into index '{index_name}'…")

        # ── bulk-upload in chunks ─────────────────────────────────
        CHUNK_DOCS = 1000          # documents per bulk request
        CHUNK_BYTES = 5 * 1024 * 1024  # 5 MB safety cap

        imported = 0
        errors   = 0
        print()

        def _flush_chunk(lines_buf):
            nonlocal errors
            # Build NDJSON bulk body: action + source per doc
            bulk_body = ""
            for line in lines_buf:
                line = line.strip()
                if not line: continue
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    errors += 1; continue
                action = {"index": {"_index": index_name}}
                bulk_body += json.dumps(action, ensure_ascii=False) + "\n"
                bulk_body += json.dumps(doc,    ensure_ascii=False) + "\n"
            if not bulk_body:
                return

            for attempt in range(1, 11):
                try:
                    r = req.post(f"{url}/_bulk",
                                 auth=(user, pw),
                                 headers={"Content-Type": "application/x-ndjson"},
                                 data=bulk_body.encode("utf-8"),
                                 verify=False, timeout=30)
                    if r.status_code in (200, 201):
                        resp = r.json()
                        if resp.get("errors"):
                            # count item-level errors but keep going
                            for item in resp.get("items", []):
                                if item.get("index", {}).get("error"):
                                    errors += 1
                        break
                    if attempt == 10:
                        errors += len(lines_buf)
                    else:
                        time.sleep(min(2 ** attempt, 30))
                except Exception:
                    if attempt == 10:
                        errors += len(lines_buf)
                    else:
                        time.sleep(min(2 ** attempt, 30))

        chunk_buf = []
        chunk_bytes = 0

        with open(ndjson_path, "r", encoding="utf-8") as ndf:
            for line in ndf:
                if not line.strip():
                    continue
                chunk_buf.append(line)
                chunk_bytes += len(line.encode("utf-8"))
                imported += 1

                if len(chunk_buf) >= CHUNK_DOCS or chunk_bytes >= CHUNK_BYTES:
                    _flush_chunk(chunk_buf)
                    chunk_buf  = []
                    chunk_bytes = 0

                if imported % 500 == 0 or imported == total_lines:
                    progress_bar(imported, total_lines, label="Importing")

        # flush remainder
        if chunk_buf:
            _flush_chunk(chunk_buf)
            progress_bar(imported, total_lines, label="Importing")

        print()
        if errors:
            warn(f"Import finished: {imported:,} docs processed, "
                 f"{errors:,} error(s). Check Elasticsearch logs for details.")
        else:
            ok(f"Import complete: {imported:,} documents → '{index_name}'")

    finally:
        # always clean up the temp extraction directory
        if tmp_dir:
            try: shutil.rmtree(tmp_dir, ignore_errors=True)
            except: pass


# ──────────────────────────────────────────────────────────────────
#  UPDATED MAIN MENU  (option 4 = Export, option 5 = Import)
# ──────────────────────────────────────────────────────────────────
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
        header("ELASTICSEARCH INDEX MANAGER")
        print(f"\n  {_c(C.DIM,'Endpoint:')} {_c(C.YELLOW, url)}\n")
        print(f"  {_c(C.CYAN,'[1]')} Create new index + upload CSV")
        print(f"  {_c(C.CYAN,'[2]')} Upload CSV to existing index")
        print(f"  {_c(C.CYAN,'[3]')} Delete index")
        print(f"  {_c(C.CYAN,'[4]')} Export index → NDJSON ZIP")
        print(f"  {_c(C.CYAN,'[5]')} Import NDJSON ZIP → index")
        print(f"  {_c(C.RED, '[0]')} Back")
        divider()
        ch = prompt("Choice:").strip()

        if ch == "1":
            base  = prompt("New index name (case/project name):").strip()
            idx   = _elk_create_index(url, user, pw, base, req)
            fpath = pick_file("Select CSV file", [("CSV","*.csv")])
            if not fpath: warn("No file selected."); continue
            df     = pd.read_csv(fpath, encoding="utf-8", low_memory=False, on_bad_lines="warn")
            df     = df.where(pd.notnull(df), None)
            ts_col = _elk_select_ts(df)
            jpath  = _elk_convert_csv(fpath, idx, ts_col, pd)
            if jpath: _elk_upload(url, user, pw, idx, jpath, req)

        elif ch == "2":
            idx = _elk_pick_index(url, user, pw, req)
            if not idx: continue
            fpath = pick_file("Select CSV file", [("CSV","*.csv")])
            if not fpath: warn("No file selected."); continue
            df     = pd.read_csv(fpath, encoding="utf-8", low_memory=False, on_bad_lines="warn")
            df     = df.where(pd.notnull(df), None)
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

        elif ch == "4":
            _elk_export_index(url, user, pw, req)

        elif ch == "5":
            _elk_import_index(url, user, pw, req)

        elif ch == "0":
            break
        else:
            err("Invalid choice.")
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



# ── SFTP background-sync infrastructure ──────────────────────────
SFTP_BASE  = Path(os.environ.get("APPDATA", os.path.expanduser("~"))) / "DFIRVault" / "SFTPMonitor"
SFTP_SCRI  = SFTP_BASE / "scripts"
SFTP_LOGS  = SFTP_BASE / "logs"
SFTP_JOBS  = SFTP_BASE / "jobs.json"
for _sp in [SFTP_BASE, SFTP_SCRI, SFTP_LOGS]:
    _sp.mkdir(parents=True, exist_ok=True)


def _sftp_jobs_load():
    if SFTP_JOBS.exists():
        try: return json.loads(SFTP_JOBS.read_text(encoding="utf-8"))
        except: pass
    return {}


def _sftp_jobs_save(jobs):
    SFTP_JOBS.write_text(json.dumps(jobs, indent=2), encoding="utf-8")


def _sftp_make_sync_script(job_name, cfg):
    """Generate a self-contained Python sync script for Task Scheduler to run."""
    script_path   = SFTP_SCRI / f"sftp_sync_{job_name}.py"
    log_file      = str(SFTP_LOGS / f"{job_name}.log")
    direction     = cfg["direction"]
    h             = cfg["host"]
    p             = cfg["port"]
    u             = cfg["username"]
    pw            = cfg["password"]
    use_sftp      = cfg["use_sftp"]
    rf            = cfg["remote_folder"]
    lf            = cfg["local_folder"]
    ts            = datetime.now().isoformat(timespec="seconds")
    dir_desc      = "server -> local" if direction == "remote" else "local -> server"

    lines = []
    lines.append('#!/usr/bin/env python3')
    lines.append(f'"""DFIRVault SFTP background sync -- {job_name}  Generated: {ts}  Direction: {dir_desc}"""')
    lines.append('import os, sys, logging, json, stat as _stat')
    lines.append('from pathlib import Path')
    lines.append(f'LOG_FILE     = {repr(log_file)}')
    lines.append(f'HOST         = {repr(h)}')
    lines.append(f'PORT         = {p}')
    lines.append(f'USERNAME     = {repr(u)}')
    lines.append(f'PASSWORD     = {repr(pw)}')
    lines.append(f'USE_SFTP     = {use_sftp}')
    lines.append(f'REMOTE_DIR   = {repr(rf)}')
    lines.append(f'LOCAL_DIR    = {repr(lf)}')
    lines.append(f'DIRECTION    = {repr(direction)}')
    lines.append(f'LOCK_FILE    = {repr(str(SFTP_SCRI / (job_name + ".lock")))}')
    lines.append('')
    lines.append('logging.basicConfig(')
    lines.append('    level=logging.INFO,')
    lines.append('    format="%(asctime)s  %(levelname)-8s  %(message)s",')
    lines.append('    datefmt="%Y-%m-%d %H:%M:%S",')
    lines.append('    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8")],')
    lines.append(')')
    lines.append('log = logging.getLogger("sftp_sync")')
    lines.append('')
    lines.append('def connect_sftp():')
    lines.append('    import paramiko')
    lines.append('    t = paramiko.Transport((HOST, PORT))')
    lines.append('    t.connect(username=USERNAME, password=PASSWORD)')
    lines.append('    return t, paramiko.SFTPClient.from_transport(t)')
    lines.append('')
    lines.append('def remote_walk_sftp(sftp, remote_path):')
    lines.append('    def _walk(rdir, rel_prefix):')
    lines.append('        try: items = sftp.listdir_attr(rdir)')
    lines.append('        except Exception as exc: log.warning(f"Cannot list {rdir}: {exc}"); return')
    lines.append('        for attr in items:')
    lines.append('            name = attr.filename')
    lines.append('            if name in (".", ".."): continue')
    lines.append('            abs_path = rdir.rstrip("/") + "/" + name')
    lines.append('            rel_path = (rel_prefix + "/" + name).lstrip("/")')
    lines.append('            if _stat.S_ISDIR(attr.st_mode): yield from _walk(abs_path, rel_path)')
    lines.append('            else: yield rel_path, abs_path, attr.st_size')
    lines.append('    yield from _walk(remote_path, "")')
    lines.append('')
    lines.append('def sftp_mkdir_p(sftp, remote_dir):')
    lines.append('    parts = remote_dir.strip("/").split("/")')
    lines.append('    cur = ""')
    lines.append('    for part in parts:')
    lines.append('        cur += "/" + part')
    lines.append('        try: sftp.stat(cur)')
    lines.append('        except IOError:')
    lines.append('            try: sftp.mkdir(cur)')
    lines.append('            except: pass')
    lines.append('')
    lines.append('def sync_remote_to_local():')
    lines.append('    """Sync from remote server to local machine - checks file sizes for changes"""')
    lines.append('    log.info("=== sync_remote_to_local START ===")')
    lines.append('    changed = 0')
    lines.append('    try:')
    lines.append('        transport, sftp = connect_sftp()')
    lines.append('    except Exception as exc:')
    lines.append('        log.error(f"Connection failed: {exc}")')
    lines.append('        return')
    lines.append('    ')
    lines.append('    # State file stores file sizes from last sync')
    lines.append('    state_file = Path(LOCAL_DIR) / ".sftp_state.json"')
    lines.append('    state = {}')
    lines.append('    if state_file.exists():')
    lines.append('        try:')
    lines.append('            state = json.loads(state_file.read_text())')
    lines.append('            log.info(f"Loaded previous state with {len(state)} files")')
    lines.append('        except Exception as exc:')
    lines.append('            log.warning(f"Could not load state file: {exc}")')
    lines.append('    ')
    lines.append('    new_state = {}')
    lines.append('    files_checked = 0')
    lines.append('    files_downloaded = 0')
    lines.append('    files_deleted = 0')
    lines.append('    ')
    lines.append('    try:')
    lines.append('        # First, collect all remote files and their sizes')
    lines.append('        remote_files = {}')
    lines.append('        log.info(f"Scanning remote directory: {REMOTE_DIR}")')
    lines.append('        ')
    lines.append('        for rel, abs_remote, size in remote_walk_sftp(sftp, REMOTE_DIR):')
    lines.append('            remote_files[rel] = size')
    lines.append('            files_checked += 1')
    lines.append('            ')
    lines.append('            # Get local file path')
    lines.append('            local_path = Path(LOCAL_DIR) / rel')
    lines.append('            ')
    lines.append('            # Check if file needs to be downloaded')
    lines.append('            should_download = False')
    lines.append('            ')
    lines.append('            if rel not in state:')
    lines.append('                # New file on remote')
    lines.append('                log.info(f"New remote file detected: {rel} ({size} bytes)")')
    lines.append('                should_download = True')
    lines.append('            elif state.get(rel, {}).get("size") != size:')
    lines.append('                # File size has changed')
    lines.append('                old_size = state.get(rel, {}).get("size", 0)')
    lines.append('                log.info(f"Changed remote file: {rel} ({old_size} -> {size} bytes)")')
    lines.append('                should_download = True')
    lines.append('            elif not local_path.exists():')
    lines.append('                # File exists in state but missing locally')
    lines.append('                log.info(f"Missing local file, re-downloading: {rel}")')
    lines.append('                should_download = True')
    lines.append('            ')
    lines.append('            if should_download:')
    lines.append('                try:')
    lines.append('                    local_path.parent.mkdir(parents=True, exist_ok=True)')
    lines.append('                    sftp.get(abs_remote, str(local_path))')
    lines.append('                    log.info(f"DOWNLOADED {rel} ({size} bytes)")')
    lines.append('                    files_downloaded += 1')
    lines.append('                    changed += 1')
    lines.append('                except Exception as exc:')
    lines.append('                    log.error(f"DOWNLOAD FAILED {rel}: {exc}")')
    lines.append('                    continue')
    lines.append('            ')
    lines.append('            # Store current file info in new state')
    lines.append('            new_state[rel] = {"size": size}')
    lines.append('        ')
    lines.append('        log.info(f"Remote scan complete: {files_checked} files checked, {files_downloaded} downloaded")')
    lines.append('        ')
    lines.append('        # Check for files that exist locally but not on remote (should be deleted)')
    lines.append('        for rel in list(state.keys()):')
    lines.append('            if rel not in remote_files:')
    lines.append('                local_path = Path(LOCAL_DIR) / rel')
    lines.append('                if local_path.exists():')
    lines.append('                    try:')
    lines.append('                        local_path.unlink()')
    lines.append('                        log.info(f"DELETED LOCAL (no longer on remote): {rel}")')
    lines.append('                        files_deleted += 1')
    lines.append('                        changed += 1')
    lines.append('                        # Clean up empty directories')
    lines.append('                        parent = local_path.parent')
    lines.append('                        while parent != Path(LOCAL_DIR) and parent.exists() and not any(parent.iterdir()):')
    lines.append('                            parent.rmdir()')
    lines.append('                            parent = parent.parent')
    lines.append('                    except Exception as exc:')
    lines.append('                        log.warning(f"Could not delete local file {rel}: {exc}")')
    lines.append('        ')
    lines.append('        # Save the new state')
    lines.append('        state_file.write_text(json.dumps(new_state, indent=2))')
    lines.append('        log.info(f"State saved: {len(new_state)} files tracked")')
    lines.append('        ')
    lines.append('        if files_deleted > 0:')
    lines.append('            log.info(f"Deleted {files_deleted} local files no longer on remote")')
    lines.append('            ')
    lines.append('    except Exception as exc:')
    lines.append('        log.error(f"Sync error: {exc}")')
    lines.append('        import traceback')
    lines.append('        log.error(traceback.format_exc())')
    lines.append('    finally:')
    lines.append('        try:')
    lines.append('            sftp.close()')
    lines.append('            transport.close()')
    lines.append('        except:')
    lines.append('            pass')
    lines.append('    ')
    lines.append('    log.info(f"=== sync_remote_to_local END -- {changed} change(s) (downloaded: {files_downloaded}, deleted: {files_deleted}) ===")')
    lines.append('')
    lines.append('def sync_local_to_remote():')
    lines.append('    """Sync from local machine to remote server - checks file sizes and modification times for changes"""')
    lines.append('    log.info("=== sync_local_to_remote START ===")')
    lines.append('    changed = 0')
    lines.append('    try:')
    lines.append('        transport, sftp = connect_sftp()')
    lines.append('    except Exception as exc:')
    lines.append('        log.error(f"Connection failed: {exc}")')
    lines.append('        return')
    lines.append('    ')
    lines.append('    # State file stores file mtime and size from last sync')
    lines.append('    state_file = Path(LOCAL_DIR) / ".sftp_state.json"')
    lines.append('    state = {}')
    lines.append('    if state_file.exists():')
    lines.append('        try:')
    lines.append('            state = json.loads(state_file.read_text())')
    lines.append('            log.info(f"Loaded previous state with {len(state)} files")')
    lines.append('        except Exception as exc:')
    lines.append('            log.warning(f"Could not load state file: {exc}")')
    lines.append('    ')
    lines.append('    new_state = {}')
    lines.append('    files_checked = 0')
    lines.append('    files_uploaded = 0')
    lines.append('    files_deleted = 0')
    lines.append('    ')
    lines.append('    try:')
    lines.append('        local_root = Path(LOCAL_DIR)')
    lines.append('        ')
    lines.append('        # First, collect all local files with their mtime and size')
    lines.append('        local_files = {}')
    lines.append('        for local_path in local_root.rglob("*"):')
    lines.append('            if not local_path.is_file():')
    lines.append('                continue')
    lines.append('            if local_path.name == ".sftp_state.json":')
    lines.append('                continue')
    lines.append('            ')
    lines.append('            rel = local_path.relative_to(local_root).as_posix()')
    lines.append('            mtime = local_path.stat().st_mtime')
    lines.append('            size = local_path.stat().st_size')
    lines.append('            local_files[rel] = {"mtime": mtime, "size": size}')
    lines.append('            files_checked += 1')
    lines.append('            ')
    lines.append('            # Check if file needs to be uploaded')
    lines.append('            should_upload = False')
    lines.append('            ')
    lines.append('            if rel not in state:')
    lines.append('                # New file locally')
    lines.append('                log.info(f"New local file detected: {rel} ({size} bytes)")')
    lines.append('                should_upload = True')
    lines.append('            elif state[rel].get("mtime") != mtime or state[rel].get("size") != size:')
    lines.append('                # File has changed')
    lines.append('                old_mtime = state[rel].get("mtime", 0)')
    lines.append('                old_size = state[rel].get("size", 0)')
    lines.append('                log.info(f"Changed local file: {rel} (mtime: {old_mtime}->{mtime}, size: {old_size}->{size})")')
    lines.append('                should_upload = True')
    lines.append('            ')
    lines.append('            if should_upload:')
    lines.append('                remote_path = REMOTE_DIR.rstrip("/") + "/" + rel')
    lines.append('                remote_parent = remote_path.rsplit("/", 1)[0]')
    lines.append('                ')
    lines.append('                try:')
    lines.append('                    # Ensure remote directory exists')
    lines.append('                    sftp_mkdir_p(sftp, remote_parent)')
    lines.append('                    ')
    lines.append('                    # Upload the file')
    lines.append('                    sftp.put(str(local_path), remote_path)')
    lines.append('                    log.info(f"UPLOADED {rel} ({size} bytes)")')
    lines.append('                    files_uploaded += 1')
    lines.append('                    changed += 1')
    lines.append('                except Exception as exc:')
    lines.append('                    log.error(f"UPLOAD FAILED {rel}: {exc}")')
    lines.append('            ')
    lines.append('            # Store current file info in new state')
    lines.append('            new_state[rel] = {"mtime": mtime, "size": size}')
    lines.append('        ')
    lines.append('        log.info(f"Local scan complete: {files_checked} files checked, {files_uploaded} uploaded")')
    lines.append('        ')
    lines.append('        # Check for files that exist remotely but not locally (should be deleted)')
    lines.append('        remote_files = set()')
    lines.append('        ')
    lines.append('        # Get all remote files to compare')
    lines.append('        try:')
    lines.append('            for rel, abs_remote, size in remote_walk_sftp(sftp, REMOTE_DIR):')
    lines.append('                remote_files.add(rel)')
    lines.append('        except Exception as exc:')
    lines.append('            log.warning(f"Could not scan remote files for cleanup: {exc}")')
    lines.append('        ')
    lines.append('        # Delete remote files that no longer exist locally')
    lines.append('        for rel in list(state.keys()):')
    lines.append('            if rel not in local_files and rel in remote_files:')
    lines.append('                remote_path = REMOTE_DIR.rstrip("/") + "/" + rel')
    lines.append('                try:')
    lines.append('                    sftp.remove(remote_path)')
    lines.append('                    log.info(f"DELETED REMOTE (no longer local): {rel}")')
    lines.append('                    files_deleted += 1')
    lines.append('                    changed += 1')
    lines.append('                except Exception as exc:')
    lines.append('                    log.warning(f"Could not delete remote file {rel}: {exc}")')
    lines.append('        ')
    lines.append('        # Save the new state')
    lines.append('        state_file.write_text(json.dumps(new_state, indent=2))')
    lines.append('        log.info(f"State saved: {len(new_state)} files tracked")')
    lines.append('        ')
    lines.append('        if files_deleted > 0:')
    lines.append('            log.info(f"Deleted {files_deleted} remote files no longer local")')
    lines.append('            ')
    lines.append('    except Exception as exc:')
    lines.append('        log.error(f"Sync error: {exc}")')
    lines.append('        import traceback')
    lines.append('        log.error(traceback.format_exc())')
    lines.append('    finally:')
    lines.append('        try:')
    lines.append('            sftp.close()')
    lines.append('            transport.close()')
    lines.append('        except:')
    lines.append('            pass')
    lines.append('    ')
    lines.append('    log.info(f"=== sync_local_to_remote END -- {changed} change(s) (uploaded: {files_uploaded}, deleted: {files_deleted}) ===")')
    lines.append('')
    lines.append('if __name__ == "__main__":')
    lines.append('    import time as _time')
    lines.append('    lk = Path(LOCK_FILE)')
    lines.append('    # Stale lock guard: if lock is older than 4 hours, consider it abandoned')
    lines.append('    STALE_HOURS = 4')
    lines.append('    if lk.exists():')
    lines.append('        age = _time.time() - lk.stat().st_mtime')
    lines.append('        if age < STALE_HOURS * 3600:')
    lines.append('            log.info(f"SKIPPED -- sync already running (lock age {age:.0f}s)")')
    lines.append('            sys.exit(0)')
    lines.append('        else:')
    lines.append('            log.warning(f"Stale lock detected ({age/3600:.1f}h old) -- removing and proceeding")')
    lines.append('            lk.unlink()')
    lines.append('    try:')
    lines.append('        lk.write_text(str(os.getpid()))')
    lines.append('        if DIRECTION == "remote": sync_remote_to_local()')
    lines.append('        else: sync_local_to_remote()')
    lines.append('    finally:')
    lines.append('        if lk.exists(): lk.unlink()')

    script_path.write_text('\n'.join(lines), encoding="utf-8")
    return script_path

def _sftp_register_task(job_name, script_path, interval_key):
    task_name = f"dfirvault-sftp-{job_name}"
    imap = {
        "1": ("MINUTE", "1",  "Every minute"),
        "2": ("MINUTE", "5",  "Every 5 minutes"),
        "3": ("MINUTE", "15", "Every 15 minutes"),
        "4": ("HOURLY", "1",  "Hourly"),
        "5": ("DAILY",  "1",  "Daily"),
    }
    sch, mod, _ = imap.get(interval_key, ("MINUTE", "5", "Every 5 minutes"))
    exe = sys.executable
    cmd = [
        "schtasks", "/Create", "/TN", task_name,
        "/TR", f'"{exe}" "{script_path}"',
        "/SC", sch, "/MO", mod, "/F",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return res.returncode == 0


def _sftp_delete_task(job_name):
    task_name = f"dfirvault-sftp-{job_name}"
    subprocess.run(f'schtasks /Delete /TN "{task_name}" /F',
                   shell=True, capture_output=True)
    sp = SFTP_SCRI / f"sftp_sync_{job_name}.py"
    lp = SFTP_LOGS / f"{job_name}.log"
    if sp.exists(): sp.unlink()
    if lp.exists(): lp.unlink()


def _sftp_run_task_now(job_name):
    task_name = f"dfirvault-sftp-{job_name}"
    subprocess.run(f'schtasks /Run /TN "{task_name}"',
                   shell=True, capture_output=True)


def _sftp_view_log(job_name, lines=60):
    log_path = SFTP_LOGS / f"{job_name}.log"
    if not log_path.exists():
        warn("No log file found yet -- sync may not have run.")
        return
    all_lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    recent = all_lines[-lines:] if len(all_lines) > lines else all_lines
    print()
    divider()
    print(f"  {_c(C.BOLD+C.WHITE, f'Sync log: {job_name}')}  {_c(C.DIM, f'({log_path})')}")
    divider()
    for line in recent:
        if "ERROR" in line or "FAILED" in line:
            print(f"  {_c(C.RED, line)}")
        elif "SKIPPED" in line:
            print(f"  {_c(C.YELLOW, line)}")
        elif "Stale lock" in line:
            print(f"  {_c(C.MAGENTA, line)}")
        elif "DOWNLOADED" in line or "UPLOADED" in line:
            print(f"  {_c(C.GREEN, line)}")
        elif "DELETED" in line:
            print(f"  {_c(C.YELLOW, line)}")
        elif "START" in line or "END" in line:
            print(f"  {_c(C.CYAN, line)}")
        else:
            print(f"  {_c(C.DIM, line)}")
    divider()
    if len(all_lines) > lines:
        info(f"Showing last {lines} of {len(all_lines)} lines.")
    print()


def _sftp_get_interval_scheduled():
    subheader("Sync Interval")
    print(f"  {_c(C.CYAN,'[1]')} Every minute")
    print(f"  {_c(C.CYAN,'[2]')} Every 5 minutes")
    print(f"  {_c(C.CYAN,'[3]')} Every 15 minutes")
    print(f"  {_c(C.CYAN,'[4]')} Hourly")
    print(f"  {_c(C.CYAN,'[5]')} Daily")
    while True:
        ch = prompt("Choice [1-5]:").strip()
        if ch in ("1","2","3","4","5"):
            return ch
        err("Invalid choice.")


def menu_sftp():
    pm, _Obs, _FSH, _tqdm = _sftp_load_heavy()
    if not pm:
        pause(); return

    jobs = _sftp_jobs_load()

    while True:
        header("SFTP / FTP SYNC MONITOR")
        print()
        print(f"  {_c(C.CYAN,'[1]')} Create new sync job  {_c(C.DIM,'(registers background Task Scheduler task)')}")
        print(f"  {_c(C.CYAN,'[2]')} View sync status / logs")
        print(f"  {_c(C.CYAN,'[3]')} Manage existing jobs")
        print(f"  {_c(C.RED, '[0]')} Back")
        print()
        print(f"  {_c(C.DIM, C.BULLET + '  Syncs run silently in the background via Task Scheduler.')}")
        print(f"  {_c(C.DIM, C.BULLET + '  Folder trees are synced recursively (files + subfolders).')}")
        divider()
        ch = prompt("Choice:").strip()
        if ch == "0": break

        elif ch == "1":
            subheader("Connection Setup")
            use_sftp  = not prompt("Use SFTP? (y/n, default y):").strip().lower().startswith("n")
            host      = prompt("Server host:").strip()
            if not host: err("Host cannot be empty."); pause(); continue
            default_port = 22 if use_sftp else 21
            raw_port  = prompt(f"Port (default {default_port}):").strip()
            port      = int(raw_port) if raw_port.isdigit() else default_port
            username  = prompt("Username:").strip()
            password  = _sftp_get_pw_masked("Password: ")
            job_label = prompt("Job name (short identifier, e.g. case01-download):").strip()
            if not job_label:
                err("Job name cannot be empty."); pause(); continue
            job_name = re.sub(r"[^a-zA-Z0-9_-]", "_", job_label)

            spinner("Connecting to server...", 1.5)
            ftp_test = _FTPClient(host, username, password, port, use_sftp, pm)
            if not ftp_test.connect():
                err("Could not connect. Check credentials and try again.")
                pause(); continue
            info("Select remote folder...")
            remote_folder = _sftp_select_remote_folder(ftp_test)
            ftp_test.disconnect()
            if not remote_folder:
                err("No remote folder selected."); pause(); continue
            remote_folder = remote_folder.replace("\\", "/")

            info("Select local folder...")
            local_folder = pick_folder("Select Local Folder")
            if not local_folder:
                err("No local folder selected."); pause(); continue

            print()
            print(f"  {_c(C.CYAN,'[1]')} REMOTE to LOCAL  {_c(C.DIM,'(download: server to local)')}")
            print(f"  {_c(C.CYAN,'[2]')} LOCAL to REMOTE  {_c(C.DIM,'(upload: local to server)')}")
            dir_ch    = prompt("Direction [1/2]:").strip()
            direction = "local" if dir_ch == "2" else "remote"
            interval_key = _sftp_get_interval_scheduled()

            cfg = {
                "host": host, "username": username, "password": password,
                "port": port, "use_sftp": use_sftp,
                "remote_folder": remote_folder, "local_folder": local_folder,
                "direction": direction,
            }

            spinner("Generating sync script...", 1.0)
            script_path = _sftp_make_sync_script(job_name, cfg)
            spinner("Registering Task Scheduler task...", 1.5)
            if _sftp_register_task(job_name, script_path, interval_key):
                imap_desc = {"1":"Every minute","2":"Every 5 min","3":"Every 15 min","4":"Hourly","5":"Daily"}
                jobs[job_name] = {
                    "label": job_label,
                    "host": host, "port": port, "use_sftp": use_sftp,
                    "remote_folder": remote_folder, "local_folder": local_folder,
                    "direction": direction,
                    "interval_desc": imap_desc.get(interval_key, "?"),
                    "script_path": str(script_path),
                    "log_path": str(SFTP_LOGS / f"{job_name}.log"),
                    "created": datetime.now().isoformat(timespec="seconds"),
                }
                _sftp_jobs_save(jobs)
                print()
                ok(f"Job '{job_name}' created and scheduled.")
                info(f"Sync log:   {SFTP_LOGS / (job_name + '.log')}")
                info("Use option [2] from this menu to view sync status.")
            else:
                err("Failed to register Task Scheduler task.")
                err("Ensure DFIRVault is running as Administrator.")
            pause()

        elif ch == "2":
            jobs = _sftp_jobs_load()
            if not jobs:
                warn("No sync jobs configured yet."); pause(); continue
            subheader("View Sync Status")
            job_list = list(jobs.keys())
            print()
            for i, jn in enumerate(job_list, 1):
                d = jobs[jn]
                arrow = "server->local" if d.get("direction") == "remote" else "local->server"
                itv = d.get("interval_desc", "?"); hst = d.get("host", "?"); lbl = d.get("label", jn)
                print(f"  {_c(C.CYAN, '['+ str(i) +']')}" + f" {lbl}  " + _c(C.DIM, f"({arrow})  {itv}  |  {hst}"))
            print(f"  {_c(C.RED, f'[{len(job_list)+1}]')} Back")
            print()
            raw = prompt("Select job:").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(job_list):
                sel_job = job_list[int(raw) - 1]
                _sftp_view_log(sel_job)
                print(f"  {_c(C.CYAN,'[1]')} Run sync now   {_c(C.CYAN,'[0]')} Back")
                if prompt("Action:").strip() == "1":
                    spinner("Triggering sync task...", 1.5)
                    _sftp_run_task_now(sel_job)
                    ok("Sync task triggered. Check log in a moment.")
            pause()

        elif ch == "3":
            jobs = _sftp_jobs_load()
            if not jobs:
                warn("No sync jobs configured yet."); pause(); continue
            subheader("Manage Sync Jobs")
            job_list = list(jobs.keys())
            print()
            for i, jn in enumerate(job_list, 1):
                d = jobs[jn]
                mode = "Remote->Local" if d.get("direction") == "remote" else "Local->Remote"
                mode = "Remote->Local" if d.get("direction") == "remote" else "Local->Remote"
                itv2 = d.get("interval_desc","?"); hst2 = d.get("host","?"); lbl2 = d.get("label",jn)
                print(f"  {_c(C.CYAN, '['+ str(i) +']')}" + f" {lbl2}  " + _c(C.DIM, f"| {mode} | {itv2} | {hst2}"))
            print(f"  {_c(C.RED, f'[{len(job_list)+1}]')} Back")
            print()
            raw = prompt("Select job:").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(job_list)):
                continue
            sel_job = job_list[int(raw) - 1]
            d = jobs[sel_job]
            subheader(f"Job: {d.get('label', sel_job)}")
            arrow = "Server -> Local" if d.get("direction") == "remote" else "Local -> Server"
            print(f"\n  {_c(C.DIM,'Direction:')}  {arrow}")
            print(f"  {_c(C.DIM,'Host:     ')}  {d.get('host')}:{d.get('port')}")
            print(f"  {_c(C.DIM,'Remote:   ')}  {d.get('remote_folder')}")
            print(f"  {_c(C.DIM,'Local:    ')}  {d.get('local_folder')}")
            print(f"  {_c(C.DIM,'Interval: ')}  {d.get('interval_desc','?')}")
            print(f"  {_c(C.DIM,'Log:      ')}  {d.get('log_path','?')}")
            print(f"  {_c(C.DIM,'Created:  ')}  {d.get('created','?')}")
            divider()
            print(f"  {_c(C.CYAN,'[1]')} Run now")
            print(f"  {_c(C.RED, '[2]')} Delete job + task")
            print(f"  {_c(C.DIM, '[0]')} Back")
            sub = prompt("Action:").strip()
            if sub == "1":
                spinner("Triggering sync task...", 1.5)
                _sftp_run_task_now(sel_job)
                ok("Sync task triggered.")
            elif sub == "2":
                if prompt(f"Delete job '{sel_job}'? (y/n):").lower().startswith("y"):
                    _sftp_delete_task(sel_job)
                    del jobs[sel_job]
                    _sftp_jobs_save(jobs)
                    ok(f"Job '{sel_job}' deleted.")
            pause()

        else:
            err("Invalid choice.")



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
                 'otx_pulse_names':'','otx_pulse_urls':'','otx_tags':'','otx_malicious':False,'otx_found':False}
        try:
            url = f"{self.base_url}/indicators/{indicator_type}/{indicator}/general"
            r   = _le_requests.get(url, headers=self.headers, timeout=30)
            if r.status_code == 200:
                data   = r.json()
                pulses = data.get('pulse_info',{}).get('pulses',[])
                count  = data.get('pulse_info',{}).get('count',0)
                names, urls, tags, mal = [], [], set(), 0
                for p in pulses[:10]:
                    n = p.get('name','')
                    if n: names.append(n[:100])
                    pid = p.get('id','')
                    if pid: urls.append(f"https://otx.alienvault.com/pulse/{pid}")
                    tags.update(p.get('tags',[]))
                    if p.get('is_malicious'): mal += 1
                result = {
                    'otx_threat_score':     min(100, count * 10),
                    'otx_pulse_count':      count,
                    'otx_malicious_pulses': mal,
                    'otx_pulse_names':      ' | '.join(names[:5]),
                    'otx_pulse_urls':       ' | '.join(urls[:5]),
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

def bf_convert_epoch_to_str(epoch):
    """Convert epoch to dd/mm/yyyy HH:MM:SS (UTC), or blank if 0/invalid."""
    try:
        epoch = int(epoch)
        if epoch > 0:
            return datetime.utcfromtimestamp(epoch).strftime('%d/%m/%Y %H:%M:%S')
    except Exception:
        pass
    return ""

def bf_assess_noteworthy(name, mode, atime, mtime, ctime, crtime):
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

def bf_get_available_port(start_port=8000, max_port=8100):
    """Find an available port starting from start_port up to max_port"""
    for port in range(start_port, max_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    raise Exception(f"No available ports found between {start_port} and {max_port}")

def bf_ask_date_range_filter():
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

def bf_filter_rows_by_date_range(rows, date_filter):
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

def bf_create_database(rows, db_path, bodyfile_name="default"):
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

def bf_add_bodyfile_to_database(bodyfile_path, db_path):
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

def bf_verify_database_contents(db_path):
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

def bf_check_database_schema(db_path):
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

def bf_test_database_query(db_path):
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

def bf_get_summary_stats(db_path, timeline_type="mtime"):
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

def bf_generate_lightweight_html(db_path, csv_path, port):
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

class BfForensicRequestHandler(SimpleHTTPRequestHandler):
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

def bf_start_server(db_path, port=8000):
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
    server_thread = threading.Thread(target=bf_start_server, args=(db_path, port), daemon=True)
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


# ══════════════════════════════════════════════════════════════════
#  SECTION 11 — CSV SPLITTER
# ══════════════════════════════════════════════════════════════════

def _csv_get_file_size_mb(filepath):
    return os.path.getsize(filepath) / (1024 * 1024)

def _csv_count_lines(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return sum(1 for _ in f)

class _CsvCountingWriter:
    """Wraps a file handle and tracks bytes written."""
    def __init__(self, file_handle):
        self.file_handle = file_handle
        self.byte_count  = 0

    def write(self, data):
        encoded = data.encode('utf-8')
        self.byte_count += len(encoded)
        self.file_handle.write(data)

    def flush(self):   self.file_handle.flush()
    def close(self):   self.file_handle.close()
    def size_mb(self): return self.byte_count / (1024 * 1024)


def _csv_split_by_lines(input_file, output_prefix, lines_per_file, dup_header):
    total_data_lines = _csv_count_lines(input_file) - (1 if dup_header else 0)
    split_files = []
    start = time.time()

    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader) if dup_header else None

        file_count   = 1
        current_line = 0
        out_fh = None
        writer = None

        for row in reader:
            if current_line % lines_per_file == 0:
                if out_fh:
                    out_fh.close()
                out_path = f"{output_prefix}_{file_count}.csv"
                out_fh = open(out_path, 'w', newline='', encoding='utf-8')
                split_files.append(out_path)
                writer = csv.writer(out_fh)
                if dup_header and header:
                    writer.writerow(header)
                file_count += 1

            writer.writerow(row)
            current_line += 1

            if current_line % 5000 == 0 or current_line == total_data_lines:
                progress_bar(current_line, total_data_lines, label=f"line {current_line:,}")

        if out_fh:
            out_fh.close()

    print()
    elapsed = time.time() - start
    ok(f"Created {file_count - 1} file(s) in {elapsed:.2f}s")
    return split_files


def _csv_split_by_size(input_file, output_prefix, max_size_mb, dup_header):
    total_size = _csv_get_file_size_mb(input_file)
    split_files  = []
    start = time.time()
    processed_mb = 0.0

    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader) if dup_header else None

        file_count = 1

        def _open_next():
            nonlocal file_count
            out_path = f"{output_prefix}_{file_count}.csv"
            fh = open(out_path, 'w', newline='', encoding='utf-8')
            cw = _CsvCountingWriter(fh)
            w  = csv.writer(cw)
            if header:
                w.writerow(header)
            file_count += 1
            split_files.append(out_path)
            return cw, w

        cw, writer = _open_next()

        for row in reader:
            tmp = StringIO()
            csv.writer(tmp).writerow(row)
            row_mb = len(tmp.getvalue().encode('utf-8')) / (1024 * 1024)

            if cw.size_mb() + row_mb > max_size_mb:
                cw.close()
                cw, writer = _open_next()

            writer.writerow(row)
            processed_mb += row_mb
            progress_bar(min(processed_mb, total_size), total_size,
                         label=f"{processed_mb:.1f} / {total_size:.1f} MB")

        cw.close()

    print()
    elapsed = time.time() - start
    ok(f"Created {file_count - 1} file(s) in {elapsed:.2f}s")
    return split_files


def _csv_verify_integrity(original_file, split_files, dup_header):
    subheader("Integrity Check")
    original_lines = _csv_count_lines(original_file) - 1  # exclude header

    split_total = 0
    for fp in split_files:
        with open(fp, 'r', encoding='utf-8') as fh:
            n = sum(1 for _ in fh)
            if dup_header:
                n -= 1
            split_total += n

    print(f"  {_c(C.DIM, 'Original lines (excl. header):')} {original_lines:,}")
    print(f"  {_c(C.DIM, 'Lines across split files:     ')} {split_total:,}")

    if split_total == original_lines:
        ok("Line integrity check passed — all lines accounted for.")
    else:
        err(f"Integrity check FAILED  (difference: {original_lines - split_total:+,} lines)")


def menu_csv_splitter():
    header("CSV SPLITTER")
    info("Split large CSV files by size (MB) or number of lines")
    print()

    while True:
        print(f"  {_c(C.CYAN, '[1]')} Split a CSV file")
        print(f"  {_c(C.RED,  '[0]')} Back")
        divider()
        ch = prompt("Choice:").strip()

        if ch == "0":
            break
        elif ch != "1":
            err("Invalid choice.")
            continue

        # ── file selection ──────────────────────────────────────
        clear_screen()
        header("CSV SPLITTER")
        info("Select input CSV file…")
        input_file = pick_file("Select CSV to split",
                               filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not input_file:
            warn("No file selected.")
            pause(); continue

        size_mb     = _csv_get_file_size_mb(input_file)
        total_lines = _csv_count_lines(input_file) - 1
        print()
        ok(f"Loaded: {os.path.basename(input_file)}")
        print(f"  {_c(C.DIM, 'Size:')}  {size_mb:.2f} MB")
        print(f"  {_c(C.DIM, 'Data rows:')} {total_lines:,}")
        print()

        # ── split method ────────────────────────────────────────
        print(f"  {_c(C.CYAN, '[1]')} Split by file size (MB)")
        print(f"  {_c(C.CYAN, '[2]')} Split by number of lines")
        divider()
        method = prompt("Split method:").strip()

        if method == "1":
            raw = prompt("Max size per split file in MB (e.g. 500):").strip()
            try:
                max_size = float(raw)
            except ValueError:
                err("Invalid value."); pause(); continue
            split_type = "size"
        elif method == "2":
            raw = prompt("Max lines per split file (e.g. 100000):").strip()
            try:
                max_lines = int(raw)
            except ValueError:
                err("Invalid value."); pause(); continue
            split_type = "lines"
        else:
            err("Invalid selection."); pause(); continue

        dup_hdr_raw = prompt("Duplicate header in each split file? (y/n):").strip().lower()
        dup_header  = dup_hdr_raw == "y"

        # ── output directory ────────────────────────────────────
        info("Select output directory…")
        output_dir = pick_folder("Select Output Directory")
        if not output_dir:
            warn("No output directory selected."); pause(); continue

        base     = os.path.splitext(os.path.basename(input_file))[0]
        out_pfx  = os.path.join(output_dir, base + "_split")

        print()
        info(f"Splitting  →  {os.path.normpath(out_pfx)}_#.csv")
        print()

        try:
            if split_type == "size":
                split_files = _csv_split_by_size(input_file, out_pfx, max_size, dup_header)
            else:
                split_files = _csv_split_by_lines(input_file, out_pfx, max_lines, dup_header)

            print()
            _csv_verify_integrity(input_file, split_files, dup_header)

            print()
            info("Opening output folder…")
            try:
                os.startfile(output_dir)
            except Exception:
                pass

        except Exception as exc:
            err(f"Split failed: {exc}")

        pause()


# ══════════════════════════════════════════════════════════════════
#  SECTION 12 — CSV TIMESTAMP CLEANER
# ══════════════════════════════════════════════════════════════════

def _ts_guess_column(columns):
    """Return the most likely timestamp column name."""
    priority = ['timestamp', '@timestamp', 'time', 'datetime', 'date']
    for p in priority:
        for col in columns:
            if re.search(p, col, re.IGNORECASE):
                return col
    return None


def _ts_format_sample(val):
    """Try to convert a raw value to a human-readable date string for preview."""
    try:
        num = float(str(val))
        digits = len(str(int(num)))
        if digits >= 13:
            return datetime.utcfromtimestamp(num / 1000).strftime("%d/%m/%Y %H:%M:%S") + "  (epoch ms)"
        elif digits == 10:
            return datetime.utcfromtimestamp(num).strftime("%d/%m/%Y %H:%M:%S") + "  (epoch s)"
    except Exception:
        pass
    return str(val)


def _ts_convert_value(val):
    """Convert a single timestamp value → 'DD/MM/YYYY HH:MM:SS' string or None."""
    if val is None or (isinstance(val, float) and math.isnan(val)):
        return None
    s = str(val).strip()
    if not s:
        return None
    try:
        if re.match(r'^\d+(\.\d+)?$', s):
            f = float(s)
            if f > 1e12:
                return datetime.utcfromtimestamp(f / 1000).strftime("%d/%m/%Y %H:%M:%S")
            else:
                return datetime.utcfromtimestamp(f).strftime("%d/%m/%Y %H:%M:%S")
        else:
            import pandas as _pd_local
            dt = _pd_local.to_datetime(val, utc=True)
            return dt.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return None


def _ts_select_column_interactive(df):
    """Present column list, let user pick the timestamp column."""
    print()
    subheader("Column Selection")
    sample_row = df.iloc[0].to_dict() if not df.empty else {}

    for i, col in enumerate(df.columns, 1):
        sample = str(sample_row.get(col, ''))[:60]
        print(f"  {_c(C.CYAN, f'[{i:>2}]')} {col}  {_c(C.DIM, sample)}")

    print()
    default_guess = _ts_guess_column(df.columns)
    if default_guess:
        eg = str(sample_row.get(default_guess, ''))[:40]
        info(f"Suggested: {_c(C.YELLOW, default_guess)}  ({eg})")
    print()

    while True:
        raw = prompt(f"Select timestamp column [Enter = '{default_guess}']:").strip()
        if raw == "" and default_guess:
            col_name = default_guess
            break
        try:
            idx = int(raw) - 1
            col_name = df.columns[idx]
            break
        except (ValueError, IndexError):
            err("Invalid selection, try again.")

    # Preview samples
    print()
    subheader(f"Sample values → '{col_name}'")
    for s in df[col_name].dropna().astype(str).head(5).tolist():
        formatted = _ts_format_sample(s)
        print(f"  {_c(C.DIM, s[:40])}  →  {_c(C.GREEN, formatted)}")

    print()
    confirm = prompt("Proceed with this column? (y/n):").strip().lower()
    if confirm != "y":
        return _ts_select_column_interactive(df)

    return col_name


def _ts_process_file(csv_path, output_folder, ts_col=None, auto=False):
    """Read CSV, convert timestamps, save output.  Returns (lines_read, lines_written, out_path)."""
    if not _PANDAS_OK:
        err("pandas is required for this feature.  Install with:  pip install pandas")
        return 0, 0, None

    import pandas as _pd_local

    df = _pd_local.read_csv(csv_path, encoding='utf-8', low_memory=False, on_bad_lines='warn')
    df = df.where(_pd_local.notnull(df), None)
    lines_read = len(df)

    if auto:
        col = _ts_guess_column(df.columns)
        if not col:
            warn(f"Could not auto-detect timestamp column in: {os.path.basename(csv_path)}")
            return lines_read, 0, None
    else:
        col = ts_col if ts_col else _ts_select_column_interactive(df)
        if not col:
            return lines_read, 0, None

    info(f"Converting  '{col}'  →  timestamp …")
    total = len(df)
    converted = []
    for i, val in enumerate(df[col]):
        converted.append(_ts_convert_value(val))
        if (i + 1) % 5000 == 0 or (i + 1) == total:
            progress_bar(i + 1, total, label=f"{i+1:,} / {total:,}")
    print()

    df['timestamp'] = converted
    cols = ['timestamp'] + [c for c in df.columns if c != 'timestamp']
    df = df[cols]

    base     = os.path.splitext(os.path.basename(csv_path))[0]
    out_name = base + "_processed.csv"
    out_path = os.path.join(output_folder, out_name)
    df.to_csv(out_path, index=False)
    lines_written = len(df)
    return lines_read, lines_written, out_path


def menu_csv_timestamp_cleaner():
    header("CSV TIMESTAMP CLEANER")
    info("Normalise timestamps to DD/MM/YYYY HH:MM:SS — supports epoch (s/ms) and ISO-8601")
    print()

    while True:
        print(f"  {_c(C.CYAN, '[1]')} Process single CSV file  {_c(C.DIM, 'interactive column selection')}")
        print(f"  {_c(C.CYAN, '[2]')} Bulk process folder       {_c(C.DIM, 'auto-detect timestamp column')}")
        print(f"  {_c(C.RED,  '[0]')} Back")
        divider()
        ch = prompt("Choice:").strip()

        if ch == "0":
            break

        elif ch == "1":
            clear_screen()
            header("CSV TIMESTAMP CLEANER  —  SINGLE FILE")

            info("Select input CSV file…")
            csv_path = pick_file("Select CSV file",
                                 filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
            if not csv_path:
                warn("No file selected."); pause(); continue

            ok(f"Loaded: {os.path.basename(csv_path)}")

            info("Select output folder…")
            out_folder = pick_folder("Select Output Folder")
            if not out_folder:
                warn("No output folder selected."); pause(); continue

            print()
            try:
                lines_r, lines_w, out_path = _ts_process_file(csv_path, out_folder)
            except Exception as exc:
                err(f"Processing failed: {exc}"); pause(); continue

            if out_path:
                print()
                subheader("Summary")
                print(f"  {_c(C.DIM, 'Input file: ')} {os.path.basename(csv_path)}")
                print(f"  {_c(C.DIM, 'Lines read: ')} {lines_r:,}")
                print(f"  {_c(C.DIM, 'Lines out:  ')} {lines_w:,}")
                print(f"  {_c(C.DIM, 'Saved to:   ')} {out_path}")
                ok("Processing complete.")
            pause()

        elif ch == "2":
            clear_screen()
            header("CSV TIMESTAMP CLEANER  —  BULK")

            info("Select folder containing CSV files (searches subfolders)…")
            in_folder = pick_folder("Select Input Folder")
            if not in_folder:
                warn("No folder selected."); pause(); continue

            info("Select output folder…")
            out_folder = pick_folder("Select Output Folder")
            if not out_folder:
                warn("No output folder selected."); pause(); continue

            csv_files = []
            for root_dir, _, files in os.walk(in_folder):
                for fn in files:
                    if fn.lower().endswith('.csv'):
                        csv_files.append(os.path.join(root_dir, fn))

            if not csv_files:
                warn("No CSV files found in selected folder."); pause(); continue

            info(f"Found {len(csv_files)} CSV file(s). Processing with auto-detection…")
            print()

            success, total_r, total_w = 0, 0, 0
            for i, fp in enumerate(csv_files, 1):
                info(f"[{i}/{len(csv_files)}] {os.path.basename(fp)}")
                try:
                    lr, lw, out_path = _ts_process_file(fp, out_folder, auto=True)
                    total_r += lr
                    if out_path:
                        total_w += lw
                        success += 1
                        ok(f"Saved → {os.path.basename(out_path)}")
                    else:
                        warn(f"Skipped (no timestamp column detected)")
                except Exception as exc:
                    err(f"Failed: {exc}")

            print()
            subheader("Bulk Summary")
            print(f"  {_c(C.DIM, 'Files found:       ')} {len(csv_files)}")
            print(f"  {_c(C.DIM, 'Successfully saved:')} {success}")
            print(f"  {_c(C.DIM, 'Failed / skipped:  ')} {len(csv_files) - success}")
            print(f"  {_c(C.DIM, 'Total rows read:   ')} {total_r:,}")
            print(f"  {_c(C.DIM, 'Total rows written:')} {total_w:,}")
            ok("Bulk processing complete.")
            pause()

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
  {_c(C.DIM, 'Version')} {_c(C.BOLD + C.CYAN, CURRENT_VERSION)}{_c(C.DIM, '  •  github.com/dfirvault/DFIRVault')}
{_c(C.CYAN, '━' * 62)}
"""


# ══════════════════════════════════════════════════════════════════
# DISK IMAGE CONVERTER (qemu-img wrapper)
# ══════════════════════════════════════════════════════════════════

_QIMG_FORMAT_EXTENSIONS = {
    "raw":       [".raw", ".img", ".bin"],
    "qcow2":     [".qcow2"],
    "qcow":      [".qcow"],
    "qed":       [".qed"],
    "vdi":       [".vdi"],
    "vmdk":      [".vmdk"],
    "vhdx":      [".vhdx"],
    "vpc":       [".vhd"],
    "bochs":     [".bochs", ".img"],
    "cow":       [".cow"],
    "parallels": [".hds"],
    "dmg":       [".dmg"],
}
_QIMG_SUPPORTED_FORMATS = list(_QIMG_FORMAT_EXTENSIONS.keys())


def _qimg_read_header(path, n=512):
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def _qimg_detect_format(path):
    """Best-effort detection of a disk image's format via header/footer magic bytes."""
    header = _qimg_read_header(path)
    if not header:
        return "unknown"

    if header[0:4] == b"QFI\xfb":
        version = int.from_bytes(header[4:8], "big")
        if version == 1:
            return "qcow"
        elif version >= 2:
            return "qcow2"
        return "qcow"

    if header[0:4] == b"QED\x00":
        return "qed"

    if b"VirtualBox Disk Image" in header[0:64] or header[64:68] in (b"\x7f\x10\xda\xbe", b"\xbe\xda\x10\x7f"):
        return "vdi"

    if header[0:4] == b"KDMV":
        return "vmdk"
    if header.lstrip().startswith(b"# Disk DescriptorFile"):
        return "vmdk"

    if header[0:8] == b"vhdxfile":
        return "vhdx"

    if header[0:8] == b"conectix":
        return "vpc"
    try:
        size = os.path.getsize(path)
        if size >= 512:
            with open(path, "rb") as f:
                f.seek(size - 512)
                footer = f.read(512)
            if footer[0:8] == b"conectix":
                return "vpc"
    except OSError:
        pass

    if b"Bochs Virtual HD Image" in header[0:32]:
        return "bochs"

    if header[0:16] in (b"WithoutFreeSpace", b"WithouFreSpacExt"):
        return "parallels"

    try:
        size = os.path.getsize(path)
        if size >= 512:
            with open(path, "rb") as f:
                f.seek(size - 512)
                trailer = f.read(512)
            if trailer[0:4] == b"koly":
                return "dmg"
    except OSError:
        pass

    if header[0:4] == b"COWD":
        return "cow"

    return "raw"


def _qimg_likely_formats_for_extension(path):
    ext = os.path.splitext(path)[1].lower()
    return [fmt for fmt, exts in _QIMG_FORMAT_EXTENSIONS.items() if ext in exts]


def _qimg_resolve_binary():
    """
    Resolve the path to qemu-img.exe using the registry
    (HKCU\\Software\\DFIRVault\\Qemu\\QemuImgPath). If missing/invalid,
    prompt the user to locate it (and save it back to the registry), or
    open the download page if cancelled.
    """
    saved_path = RegistryConfig.load_config("Qemu", "QemuImgPath")

    if saved_path and os.path.isfile(saved_path):
        return saved_path

    if saved_path and not os.path.isfile(saved_path):
        warn(f"Registry points to a missing file: {saved_path}")
    else:
        info(r"No qemu-img location found in registry (HKCU\Software\DFIRVault\Qemu).")

    while True:
        if _LE_IMPORTS_OK:
            pass  # no-op, just keeping flake-friendly
        root = tk.Tk(); root.withdraw(); root.attributes("-topmost", True)
        messagebox.showinfo(
            "qemu-img location required",
            "qemu-img.exe could not be located.\n\n"
            "Please select the qemu-img.exe file (usually inside your "
            "QEMU installation directory, e.g. C:\\Program Files\\qemu)."
        )
        chosen = filedialog.askopenfilename(
            title="Select qemu-img.exe",
            filetypes=[("qemu-img executable", "qemu-img.exe"), ("All files", "*.*")],
        )
        root.destroy()

        if not chosen:
            url = "https://cloudbase.it/qemu-img-windows/"
            msg = (
                "qemu-img.exe is required for the Disk Image Converter.\n\n"
                f"Opening download page:\n{url}\n\n"
                "Download and unzip the latest qemu-img-windows release, "
                "then return to this menu and try again, selecting "
                "qemu-img.exe from the unzipped folder."
            )
            root = tk.Tk(); root.withdraw(); root.attributes("-topmost", True)
            messagebox.showinfo("Download qemu-img for Windows", msg)
            root.destroy()
            webbrowser.open(url)
            return None

        if not os.path.isfile(chosen):
            err(f"File not found: {chosen}")
            continue

        if os.path.basename(chosen).lower() != "qemu-img.exe":
            if not yesno_dialog(
                "Confirm executable",
                f"Selected file is '{os.path.basename(chosen)}', not "
                "'qemu-img.exe'. Use it anyway?"
            ):
                continue

        RegistryConfig.save_config("Qemu", "QemuImgPath", chosen)
        ok(f"Saved qemu-img path to registry: {chosen}")
        return chosen


def _qimg_pick_output_path(default_name, dst_format):
    ext = _QIMG_FORMAT_EXTENSIONS.get(dst_format, [".img"])[0]
    suggested = os.path.splitext(default_name)[0] + ext

    root = tk.Tk(); root.withdraw(); root.attributes("-topmost", True)
    filepath = filedialog.asksaveasfilename(
        title="Save converted image as",
        initialfile=suggested,
        defaultextension=ext,
    )
    root.destroy()
    return filepath or None


def _qimg_build_job():
    """Collect one conversion job from the user via console + dialogs. Returns dict or None."""
    subheader("New Conversion Job")

    print("  Select the DESTINATION format:")
    for i, fmt in enumerate(_QIMG_SUPPORTED_FORMATS, 1):
        print(f"    [{i}] {fmt}")
    while True:
        choice = prompt(f"Enter a number (1-{len(_QIMG_SUPPORTED_FORMATS)}):").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(_QIMG_SUPPORTED_FORMATS):
            dst_format = _QIMG_SUPPORTED_FORMATS[int(choice) - 1]
            break
        err("Invalid selection, try again.")

    info("Select the disk image file to convert...")
    src_path = pick_file(title="Select source disk image")
    if not src_path:
        warn("No source file selected, cancelling this job.")
        return None
    if not os.path.isfile(src_path):
        err(f"File not found: {src_path}")
        return None

    detected_fmt = _qimg_detect_format(src_path)
    ext_matches = _qimg_likely_formats_for_extension(src_path)
    ext = os.path.splitext(src_path)[1].lower() or "(none)"

    print(f"\n  Source file: {src_path}")
    print(f"  File extension: {ext}")
    print(f"  Detected format (from file header): {detected_fmt}")
    print(f"  Format(s) typically associated with this extension: "
          f"{', '.join(ext_matches) if ext_matches else 'none recognized'}")

    if detected_fmt != "unknown" and detected_fmt in ext_matches:
        src_format = detected_fmt
        ok(f"Extension and header agree. Using source format: {src_format}")
    elif detected_fmt == "raw" and not ext_matches:
        warn("No structured header detected and extension is unrecognized.")
        print("  Select the SOURCE format to use:")
        for i, fmt in enumerate(_QIMG_SUPPORTED_FORMATS, 1):
            print(f"    [{i}] {fmt}")
        while True:
            choice = prompt(f"Enter a number (1-{len(_QIMG_SUPPORTED_FORMATS)}):").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(_QIMG_SUPPORTED_FORMATS):
                src_format = _QIMG_SUPPORTED_FORMATS[int(choice) - 1]
                break
            err("Invalid selection, try again.")
    else:
        warn("Format mismatch or uncertain detection!")
        if detected_fmt != "unknown":
            print(f"    Header suggests   : {detected_fmt}")
        else:
            print("    Header format could not be determined.")
        if ext_matches:
            print(f"    Extension suggests: {', '.join(ext_matches)}")
        else:
            print("    Extension does not correspond to a known format.")

        use_detected = False
        if detected_fmt != "unknown":
            use_detected = yesno_dialog(
                "Source format",
                f"Use the header-detected format '{detected_fmt}' as the source format?"
            )

        if use_detected:
            src_format = detected_fmt
        elif ext_matches:
            if len(ext_matches) == 1:
                use_ext = yesno_dialog(
                    "Source format",
                    f"Use the extension-derived format '{ext_matches[0]}' instead?"
                )
                if use_ext:
                    src_format = ext_matches[0]
                else:
                    src_format = None
            else:
                src_format = None
            if src_format is None:
                options = ext_matches if len(ext_matches) > 1 else _QIMG_SUPPORTED_FORMATS
                print("  Select the SOURCE format to use:")
                for i, fmt in enumerate(options, 1):
                    print(f"    [{i}] {fmt}")
                while True:
                    choice = prompt(f"Enter a number (1-{len(options)}):").strip()
                    if choice.isdigit() and 1 <= int(choice) <= len(options):
                        src_format = options[int(choice) - 1]
                        break
                    err("Invalid selection, try again.")
        else:
            print("  Select the SOURCE format to use:")
            for i, fmt in enumerate(_QIMG_SUPPORTED_FORMATS, 1):
                print(f"    [{i}] {fmt}")
            while True:
                choice = prompt(f"Enter a number (1-{len(_QIMG_SUPPORTED_FORMATS)}):").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(_QIMG_SUPPORTED_FORMATS):
                    src_format = _QIMG_SUPPORTED_FORMATS[int(choice) - 1]
                    break
                err("Invalid selection, try again.")

    print(f"\n  Using source format: {src_format}")
    print(f"  Target output format: {dst_format}")

    info("Select where to save the converted file...")
    out_path = _qimg_pick_output_path(os.path.basename(src_path), dst_format)
    if not out_path:
        warn("No output path selected, cancelling this job.")
        return None

    if os.path.abspath(out_path) == os.path.abspath(src_path):
        err("Output path is the same as the source file -- cancelling this job "
            "to avoid overwriting the source.")
        return None

    return {
        "src_path": src_path,
        "src_format": src_format,
        "dst_format": dst_format,
        "out_path": out_path,
    }


def _qimg_run_job(job, qemu_img_bin):
    src = job["src_path"]
    dst = job["out_path"]
    src_fmt = job["src_format"]
    dst_fmt = job["dst_format"]

    out_dir = os.path.dirname(os.path.abspath(dst))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    cmd = [qemu_img_bin, "convert", "-f", src_fmt, "-O", dst_fmt, src, dst]
    info("Running: " + " ".join(f'"{c}"' if " " in c else c for c in cmd))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        err(f"'{qemu_img_bin}' not found. Is qemu-img installed?")
        return False

    if result.stdout.strip():
        print(result.stdout.strip())
    if result.returncode != 0:
        err(f"Conversion failed ({result.returncode}):")
        print(result.stderr.strip())
        return False

    if result.stderr.strip():
        print(result.stderr.strip())
    ok(f"{src} ({src_fmt}) -> {dst} ({dst_fmt})")
    return True


def menu_disk_image_converter():
    """Batch disk image format converter (qemu-img wrapper)."""
    header("DISK IMAGE CONVERTER (qemu-img)")

    qemu_img_bin = _qimg_resolve_binary()
    if not qemu_img_bin:
        warn("qemu-img.exe was not selected. Returning to main menu.")
        pause()
        return

    jobs = []

    while True:
        job = _qimg_build_job()
        if job:
            jobs.append(job)
            ok(f"Job queued ({len(jobs)} total):")
            print(f"    {job['src_path']}  [{job['src_format']}]")
            print(f"    -> {job['out_path']}  [{job['dst_format']}]")
        else:
            warn("Job not added.")

        if not yesno_dialog("Disk Image Converter", "Convert another file?"):
            break

    if not jobs:
        info("No jobs queued. Returning to main menu.")
        pause()
        return

    subheader(f"Running {len(jobs)} Conversion Job(s)")

    results = []
    for i, job in enumerate(jobs, 1):
        print(f"\n  [{i}/{len(jobs)}] {os.path.basename(job['src_path'])} "
              f"({job['src_format']} -> {job['dst_format']})")
        results.append((job, _qimg_run_job(job, qemu_img_bin)))

    subheader("Summary")
    for job, success in results:
        status = "OK" if success else "FAILED"
        if success:
            ok(f"{job['src_path']} -> {job['out_path']}")
        else:
            err(f"{job['src_path']} -> {job['out_path']}")

    pause()


# ══════════════════════════════════════════════════════════════════
#  SECTION 14 — VOLATILITY 3 MEMORY ANALYSER (VolMenu)
# ══════════════════════════════════════════════════════════════════
# Merged from VolMenu by Jacob Wilson • dfirvault@gmail.com
# All VolMenu functions are prefixed _vol_ to avoid name collisions.
# Registry config lives under HKCU\Software\DFIRVault\VolMenu.

import msvcrt as _vol_msvcrt  # Windows-only; already guarded by IS_WINDOWS check

_VOL_REG_PATH      = r"Software\DFIRVault\VolMenu"
_VOL_EXE_VALUE     = "VolExePath"
_VOL_PARALLELISM   = "ParallelismMode"
_VOL_VERBOSE       = "VerboseOutput"
_VOL_SMARTCACHE    = "SmartCacheEnabled"
_VOL_URL           = "https://github.com/volatilityfoundation/volatility3"
_VOL_PARALLELISM_MODES = ["off", "processes", "threads"]

_VOL_KEY_ESC   = b"\x1b"
_VOL_KEY_SPACE = b" "
_VOL_KEY_ENTER = (b"\r", b"\n")
_VOL_KEY_UP    = (b"H", b"w")
_VOL_KEY_DOWN  = (b"P", b"s")

class _VolCancelled(Exception):
    """Raised to unwind a configuration step back to the Volatility menu."""
    pass

# ── Plugin catalogue ───────────────────────────────────────────────
_VOL_PLUGINS = {
    "windows": [
        "windows.info.Info", "windows.pslist.PsList", "windows.pstree.PsTree",
        "windows.psscan.PsScan", "windows.dlllist.DllList", "windows.handles.Handles",
        "windows.cmdline.CmdLine", "windows.netscan.NetScan", "windows.netstat.NetStat",
        "windows.malfind.Malfind", "windows.modules.Modules", "windows.modscan.ModScan",
        "windows.driverscan.DriverScan", "windows.svcscan.SvcScan",
        "windows.registry.hivelist.HiveList", "windows.registry.printkey.PrintKey",
        "windows.filescan.FileScan", "windows.dumpfiles.DumpFiles",
        "windows.envars.Envars", "windows.getsids.GetSIDs", "windows.privileges.Privs",
        "windows.sessions.Sessions", "windows.mutantscan.MutantScan",
        "windows.symlinkscan.SymlinkScan", "windows.vadinfo.VadInfo",
        "windows.memmap.Memmap", "windows.ssdt.SSDT",
    ],
    "linux": [
        "linux.bash.Bash", "linux.pslist.PsList", "linux.pstree.PsTree",
        "linux.psaux.PsAux", "linux.lsmod.Lsmod", "linux.lsof.Lsof",
        "linux.malfind.Malfind", "linux.netstat.Netstat", "linux.proc.Maps",
        "linux.elfs.Elfs", "linux.check_afinfo.Check_afinfo",
        "linux.check_creds.Check_creds", "linux.check_idt.Check_idt",
        "linux.check_syscall.Check_syscall", "linux.mountinfo.MountInfo",
        "linux.tty_check.tty_check",
    ],
    "mac": [
        "mac.pslist.PsList", "mac.pstree.PsTree", "mac.psaux.Psaux",
        "mac.lsmod.Lsmod", "mac.lsof.Lsof", "mac.netstat.Netstat",
        "mac.malfind.Malfind", "mac.bash.Bash", "mac.check_syscall.Check_syscall",
        "mac.ifconfig.Ifconfig", "mac.mount.Mount", "mac.proc_maps.Maps",
    ],
}

_VOL_OS_LABELS = {"windows": "Windows", "linux": "Linux", "mac": "Mac"}


# ── Registry helpers (use DFIRVault's winreg import) ──────────────

def _vol_reg_get(name, default=None):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _VOL_REG_PATH, 0, winreg.KEY_READ) as k:
            value, _ = winreg.QueryValueEx(k, name)
            return value
    except FileNotFoundError:
        return default

def _vol_reg_set(name, value):
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _VOL_REG_PATH, 0, winreg.KEY_ALL_ACCESS) as k:
        if isinstance(value, bool):
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))
        elif isinstance(value, int):
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, value)
        else:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, str(value))

def _vol_reg_get_bool(name, default=False):
    val = _vol_reg_get(name, None)
    return default if val is None else bool(val)

def _vol_reg_get_int(name, default=0):
    val = _vol_reg_get(name, None)
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


# ── vol.exe setup ─────────────────────────────────────────────────

def _vol_prompt_for_exe():
    """Show a file picker for vol.exe. Opens Volatility3 GitHub if cancelled."""
    warn("Volatility 3 executable (vol.exe) not configured or not found.")
    info("A file picker will open — please select your vol.exe file.")
    pause("Press Enter to open the file picker…")
    path = pick_file(
        title="Select vol.exe",
        filetypes=[("Volatility 3", "vol.exe"), ("All executables", "*.exe"), ("All files", "*.*")],
    )
    if not path:
        info(f"Opening Volatility3 download page: {_VOL_URL}")
        webbrowser.open(_VOL_URL)
        return None
    path = os.path.normpath(path)
    _vol_reg_set(_VOL_EXE_VALUE, path)
    ok(f"vol.exe saved: {path}")
    return path

def _vol_ensure_exe():
    """Return the vol.exe path, prompting if missing/invalid."""
    path = _vol_reg_get(_VOL_EXE_VALUE, None)
    if path:
        path = os.path.normpath(path)
    if path and os.path.isfile(path):
        return path
    if path:
        warn(f"Configured vol.exe path no longer exists: {path}")
    return _vol_prompt_for_exe()

def _vol_change_exe(current):
    info(f"Current: {current}")
    path = pick_file(
        title="Select new vol.exe",
        filetypes=[("Volatility 3", "vol.exe"), ("All executables", "*.exe"), ("All files", "*.*")],
    )
    if path:
        path = os.path.normpath(path)
        _vol_reg_set(_VOL_EXE_VALUE, path)
        ok(f"vol.exe updated: {path}")
        return path
    warn("No file selected — keeping current path.")
    return current


# ── Performance settings ──────────────────────────────────────────

def _vol_show_perf_menu():
    while True:
        header("VOLATILITY  —  PERFORMANCE SETTINGS")
        mode_idx = _vol_reg_get_int(_VOL_PARALLELISM, 0)
        if mode_idx < 0 or mode_idx >= len(_VOL_PARALLELISM_MODES):
            mode_idx = 0
        mode       = _VOL_PARALLELISM_MODES[mode_idx]
        verbose    = _vol_reg_get_bool(_VOL_VERBOSE, False)
        smartcache = _vol_reg_get_bool(_VOL_SMARTCACHE, True)
        print()
        print(f"  {_c(C.CYAN,'[1]')} Parallelism (--parallelism):  {_c(C.YELLOW, mode)}")
        print(f"  {_c(C.CYAN,'[2]')} Verbose output (-vvv):        {_c(C.YELLOW, 'ON' if verbose else 'OFF')}")
        print(f"  {_c(C.CYAN,'[3]')} Smart layer caching:          {_c(C.YELLOW, 'ON' if smartcache else 'OFF')}")
        print(f"  {_c(C.RED, '[0]')} Back")
        divider()
        ch = prompt("Choice:").strip()
        if ch == "1":
            next_idx = (mode_idx + 1) % len(_VOL_PARALLELISM_MODES)
            _vol_reg_set(_VOL_PARALLELISM, next_idx)
            ok(f"Parallelism → {_VOL_PARALLELISM_MODES[next_idx]}")
        elif ch == "2":
            _vol_reg_set(_VOL_VERBOSE, not verbose)
            ok(f"Verbose output {'enabled' if not verbose else 'disabled'}.")
        elif ch == "3":
            _vol_reg_set(_VOL_SMARTCACHE, not smartcache)
            ok(f"Smart layer caching {'enabled' if not smartcache else 'disabled'}.")
        elif ch == "0":
            return
        else:
            err("Invalid choice.")
        pause()

def _vol_build_perf_args():
    args = []
    mode_idx = _vol_reg_get_int(_VOL_PARALLELISM, 0)
    if 0 <= mode_idx < len(_VOL_PARALLELISM_MODES):
        mode = _VOL_PARALLELISM_MODES[mode_idx]
        if mode != "off":
            args.extend(["--parallelism", mode])
    if _vol_reg_get_bool(_VOL_VERBOSE, False):
        args.append("-vvv")
    if not _vol_reg_get_bool(_VOL_SMARTCACHE, True):
        args.append("--no-symbol-cache")
    return args


# ── Checkbox-style plugin selector ────────────────────────────────

def _vol_checkbox_menu(title, items, extra_options=None):
    """DFIRVault-themed interactive checkbox menu for plugin selection.

    Returns a list of selected indices, or a special key string from
    extra_options.  Raises _VolCancelled if the user presses Esc/C.
    """
    extra_options = extra_options or []
    selected  = [False] * len(items)
    cursor    = 0
    total_rows = len(items) + len(extra_options)

    def render():
        os.system("cls")
        bar = C.HEAVY * 64
        print(f"\n{_c(C.CYAN, bar)}")
        print(f"{_c(C.CYAN, C.HEAVY)}{_c(C.BOLD+C.WHITE, ' ' * 20 + title[:22] + ' ' * 20)}{_c(C.CYAN, C.HEAVY)}")
        print(f"{_c(C.CYAN, bar)}")
        print()
        for idx, label in enumerate(items):
            box     = _c(C.GREEN,  "■") if selected[idx] else _c(C.DIM, "□")
            pointer = _c(C.CYAN, "▶") if idx == cursor else " "
            num     = _c(C.DIM, f"{idx+1:2d}.")
            print(f"  {pointer} [{box}] {num} {label}")
        print()
        for offset, (label, _key) in enumerate(extra_options):
            row = len(items) + offset
            pointer = _c(C.CYAN, "▶") if row == cursor else " "
            print(f"  {pointer}      {_c(C.BOLD+C.YELLOW, label)}")
        print()
        print(_c(C.DIM,
            "  Space: toggle   Enter: confirm   A: select all/none   "
            "↑/↓ or W/S: move   Esc/C: cancel"))

    render()
    while True:
        key = _vol_msvcrt.getch()

        if key == _VOL_KEY_ESC or key.lower() == b"c":
            raise _VolCancelled()

        if key in (b"\x00", b"\xe0"):
            key2 = _vol_msvcrt.getch()
            if key2 in _VOL_KEY_UP:
                cursor = (cursor - 1) % total_rows
            elif key2 in _VOL_KEY_DOWN:
                cursor = (cursor + 1) % total_rows
            render()
            continue

        if key.lower() == b"w":
            cursor = (cursor - 1) % total_rows; render(); continue
        if key.lower() == b"s":
            cursor = (cursor + 1) % total_rows; render(); continue

        if key == _VOL_KEY_SPACE:
            if cursor < len(items):
                selected[cursor] = not selected[cursor]
            render()
            continue

        if key.lower() == b"a":
            new_state = not all(selected)
            selected  = [new_state] * len(items)
            render()
            continue

        if key in _VOL_KEY_ENTER:
            if cursor >= len(items):
                _, extra_key = extra_options[cursor - len(items)]
                return extra_key
            chosen = [i for i, s in enumerate(selected) if s]
            if not chosen:
                chosen = [cursor]
            return chosen


# ── Scan configuration helpers ────────────────────────────────────

def _vol_select_memory_image():
    subheader("Select Memory Image")
    info("A file picker will open — select the memory image to analyse.")
    info("(Type 'c' and Enter to cancel)")
    raw = prompt("Press Enter to open picker or 'c' to cancel:").strip().lower()
    if raw == "c":
        raise _VolCancelled()
    path = pick_file(
        title="Select memory image",
        filetypes=[
            ("Memory images", "*.raw *.mem *.dmp *.vmem *.bin *.img *.lime"),
            ("All files", "*.*"),
        ],
    )
    if not path:
        warn("No memory image selected.")
        return None
    return os.path.normpath(path)

def _vol_select_output_dir():
    subheader("Select Output Directory")
    info("A folder picker will open — choose where to save results.")
    info("(Type 'c' and Enter to cancel)")
    raw = prompt("Press Enter to open picker or 'c' to cancel:").strip().lower()
    if raw == "c":
        raise _VolCancelled()
    path = pick_folder("Select output directory for Volatility results")
    if not path:
        warn("No output directory selected.")
        return None
    return os.path.normpath(path)

def _vol_select_target_os():
    subheader("Target Operating System")
    print(f"\n  {_c(C.CYAN,'[1]')} Windows")
    print(f"  {_c(C.CYAN,'[2]')} Linux")
    print(f"  {_c(C.CYAN,'[3]')} Mac")
    print(f"  {_c(C.RED, '[0]')} Cancel")
    divider()
    while True:
        ch = prompt("Choice:").strip()
        if ch == "1": return "windows"
        if ch == "2": return "linux"
        if ch == "3": return "mac"
        if ch == "0": raise _VolCancelled()
        err("Invalid choice.")

def _vol_select_plugins(target_os):
    plugin_list = _VOL_PLUGINS[target_os]
    result = _vol_checkbox_menu(
        title=f"Select {_VOL_OS_LABELS[target_os]} Plugins",
        items=list(plugin_list),
        extra_options=[
            ("Run ALL plugins", "ALL"),
            ("Cancel — back to Volatility menu", "CANCEL"),
        ],
    )
    if result == "CANCEL":
        raise _VolCancelled()
    if result == "ALL":
        return list(plugin_list)
    return [plugin_list[i] for i in result]

def _vol_configure_scan():
    """Walk through one scan configuration. Returns a job dict or None."""
    image_path = _vol_select_memory_image()
    if not image_path:
        return None
    output_dir = _vol_select_output_dir()
    if not output_dir:
        return None
    target_os = _vol_select_target_os()
    plugins   = _vol_select_plugins(target_os)
    return {
        "image_path": image_path,
        "output_dir": output_dir,
        "target_os":  target_os,
        "plugins":    plugins,
    }


# ── HTML report generation ────────────────────────────────────────

def _vol_generate_html_report(output_dir, job_info):
    """Embed all plugin .txt outputs into a single searchable HTML report."""
    import html as _html_mod
    output_path = Path(output_dir)
    txt_files = sorted(output_path.glob("*.txt"))
    if not txt_files:
        warn(f"No .txt result files found in {output_dir} — skipping HTML report.")
        return

    sections = []
    for tf in txt_files:
        stem  = tf.stem
        title = stem.replace("_", " ").title()
        try:
            content = tf.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            content = f"Error reading file: {e}"
        sections.append({"id": stem, "title": title, "filename": tf.name, "content": content})

    html_parts = ["""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DFIRVault — Volatility Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,sans-serif;background:#0d1117;color:#cdd6f4;line-height:1.5}
.container{display:flex;min-height:100vh}
.toc{width:280px;background:#1e1e2e;border-right:1px solid #313244;position:fixed;height:100vh;overflow-y:auto}
.toc h2{font-size:1rem;padding:1rem;background:#181825;border-bottom:1px solid #313244;color:#89b4fa;letter-spacing:.05em}
.toc ul{list-style:none}
.toc li{border-bottom:1px solid #181825}
.toc a{display:block;padding:.5rem 1rem;text-decoration:none;color:#cdd6f4;font-size:.85rem;transition:all .2s}
.toc a:hover{background:#313244;color:#89b4fa;padding-left:1.4rem}
.content{margin-left:280px;flex:1;padding:2rem;max-width:calc(100% - 280px)}
.report-section{background:#1e1e2e;border-radius:8px;border:1px solid #313244;margin-bottom:1.5rem;overflow:hidden}
.section-header{background:#181825;padding:.8rem 1.2rem;cursor:pointer;user-select:none;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #313244}
.section-header:hover{background:#313244}
.section-header h2{font-size:1rem;font-weight:600;color:#89b4fa}
.toggle-icon{color:#6c7086}
.section-content{padding:1rem;overflow-x:auto}
.section-content.collapsed{display:none}
pre{background:#11111b;color:#cdd6f4;padding:1rem;border-radius:6px;font-family:'Courier New',monospace;font-size:.82rem;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;margin:0;border:1px solid #313244}
.search-container{margin-bottom:1.5rem;background:#1e1e2e;padding:.75rem 1rem;border-radius:8px;border:1px solid #313244;display:flex;gap:.5rem;align-items:center}
.search-container input{flex:1;padding:.5rem .8rem;border:1px solid #313244;border-radius:4px;font-size:1rem;background:#11111b;color:#cdd6f4}
.search-container button{background:#89b4fa;color:#1e1e2e;border:none;padding:.5rem 1rem;border-radius:4px;cursor:pointer;font-weight:600}
.search-container button:hover{background:#74c7ec}
.highlight{background:#f9e2af;color:#1e1e2e}
.meta{font-size:.8rem;color:#6c7086;margin-bottom:1rem;padding:.5rem 1rem;background:#11111b;border-radius:4px;border:1px solid #313244}
.footer{text-align:center;margin-top:2rem;padding:1rem;color:#6c7086;font-size:.8rem}
</style>
</head>
<body>
<div class="container">
<div class="toc">
<h2>⚡ DFIRVault Volatility Report</h2>
<ul>"""]

    for sec in sections:
        html_parts.append(f'<li><a href="#{sec["id"]}">{_html_mod.escape(sec["title"])}</a></li>\n')

    html_parts.append("""</ul>
</div>
<div class="content">
<div class="meta">""")
    html_parts.append(
        f"Image: {_html_mod.escape(str(job_info.get('image_path','?')))} &nbsp;|&nbsp; "
        f"OS: {_html_mod.escape(_VOL_OS_LABELS.get(job_info.get('target_os','?'),'?'))} &nbsp;|&nbsp; "
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; "
        f"Plugins: {len(sections)}"
    )
    html_parts.append("""</div>
<div class="search-container">
<input type="text" id="searchInput" placeholder="Search across all plugin outputs…">
<button id="searchButton">🔍 Search</button>
<button id="clearSearch">✖ Clear</button>
</div>
""")
    for sec in sections:
        escaped = _html_mod.escape(sec["content"])
        html_parts.append(f"""
<div class="report-section" id="{sec['id']}">
<div class="section-header" onclick="toggleSection(this)">
<h2>{_html_mod.escape(sec['title'])}</h2>
<span class="toggle-icon">▼</span>
</div>
<div class="section-content">
<pre>{escaped}</pre>
</div>
</div>
""")
    html_parts.append("""
<div class="footer">Generated by DFIRVault Volatility Analyser • dfirvault@gmail.com</div>
</div>
</div>
<script>
function toggleSection(header){
  const content=header.nextElementSibling;
  const icon=header.querySelector('.toggle-icon');
  if(content.classList.contains('collapsed')){content.classList.remove('collapsed');icon.textContent='▼';}
  else{content.classList.add('collapsed');icon.textContent='▶';}
}
function escapeHtml(text){const d=document.createElement('div');d.textContent=text;return d.innerHTML;}
function escapeRegex(str){return str.replace(/[.*+?^${}()|[\\]\\\\]/g,'\\\\$&');}
function performSearch(){
  const query=document.getElementById('searchInput').value.trim();
  clearHighlights();
  if(!query)return;
  const regex=new RegExp('('+escapeRegex(query)+')','gi');
  document.querySelectorAll('.section-content pre').forEach(pre=>{
    pre.innerHTML=pre.innerText.replace(regex,'<span class="highlight">$1</span>');
  });
}
function clearHighlights(){
  document.querySelectorAll('.section-content pre').forEach(pre=>{
    pre.innerHTML=escapeHtml(pre.innerText);
  });
}
document.getElementById('searchButton').addEventListener('click',performSearch);
document.getElementById('clearSearch').addEventListener('click',()=>{
  document.getElementById('searchInput').value='';clearHighlights();
});
document.getElementById('searchInput').addEventListener('keypress',(e)=>{if(e.key==='Enter')performSearch();});
</script>
</body>
</html>
""")

    report_path = output_path / "volatility_report.html"
    try:
        report_path.write_text("".join(html_parts), encoding="utf-8")
        ok(f"HTML report generated: {report_path}")
        if IS_WINDOWS:
            try: os.startfile(str(report_path))
            except: pass
    except Exception as e:
        err(f"Failed to write HTML report: {e}")


# ── Progress monitor ──────────────────────────────────────────────

_VOL_PROGRESS_RE = re.compile(r"Progress:\s*([0-9]+(?:\.[0-9]+)?)\s*(.*)")

def _vol_monitor_progress(out_file, stop_event, plugin_idx, total_plugins, job_idx, total_jobs):
    last_pct = last_msg = None
    while not stop_event.is_set():
        time.sleep(0.5)
        try:
            with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except (FileNotFoundError, OSError):
            continue
        for line in reversed(lines):
            m = _VOL_PROGRESS_RE.search(line)
            if m:
                pct, msg = m.group(1), m.group(2).strip()
                if (pct, msg) != (last_pct, last_msg):
                    last_pct, last_msg = pct, msg
                    status = f"    {_c(C.CYAN, C.ARROW)} {pct}%"
                    if msg: status += f"  {_c(C.DIM, msg)}"
                    status += f"  {_c(C.DIM, f'[plugin {plugin_idx}/{total_plugins}, scan {job_idx}/{total_jobs}]')}"
                    print(status)
                break

def _vol_clean_output(out_file):
    try:
        with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except (FileNotFoundError, OSError):
        return
    cleaned = []
    blank_run = 0
    for line in lines:
        if line.lstrip().startswith("Progress"):
            continue
        if line.strip() == "":
            blank_run += 1
            if blank_run > 1:
                continue
            cleaned.append(line)
        else:
            blank_run = 0
            cleaned.append(line)
    try:
        with open(out_file, "w", encoding="utf-8", errors="replace") as fh:
            fh.writelines(cleaned)
    except OSError:
        pass


# ── Scan execution ────────────────────────────────────────────────

def _vol_find_symbols_dir(vol_exe, target_os):
    vol_dir   = Path(vol_exe).resolve().parent
    candidate = vol_dir / "symbols" / target_os
    return str(candidate) if candidate.is_dir() else None

def _vol_run_scan_job(vol_exe, job, job_index, total_jobs):
    image_path = os.path.normpath(job["image_path"])
    output_dir = os.path.normpath(job["output_dir"])
    plugins    = job["plugins"]

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    perf_args  = _vol_build_perf_args()
    sym_dir    = _vol_find_symbols_dir(vol_exe, job["target_os"])
    sym_args   = ["-s", os.path.normpath(sym_dir)] if sym_dir else []

    subheader(f"Scan {job_index}/{total_jobs}  —  {os.path.basename(image_path)}  [{_VOL_OS_LABELS[job['target_os']]}]")
    info(f"Symbols: {os.path.normpath(sym_dir) if sym_dir else 'none detected next to vol.exe'}")
    info(f"Plugins: {len(plugins)}")
    print()

    total_plugins = len(plugins)
    for plugin_idx, plugin in enumerate(plugins, start=1):
        out_file = Path(output_dir) / f"{plugin.replace('.', '_')}.txt"
        cmd = [vol_exe, *perf_args, *sym_args, "-f", image_path, plugin]

        print(f"  {_c(C.CYAN, f'[{plugin_idx}/{total_plugins}]')} {plugin}")
        info(f"Output → {out_file}")

        try:
            with open(out_file, "w", encoding="utf-8", errors="replace"):
                pass
            stop_event    = threading.Event()
            monitor_thread = threading.Thread(
                target=_vol_monitor_progress,
                args=(out_file, stop_event, plugin_idx, total_plugins, job_index, total_jobs),
                daemon=True,
            )
            monitor_thread.start()

            cf = subprocess.CREATE_NEW_PROCESS_GROUP if IS_WINDOWS else 0
            with open(out_file, "a", encoding="utf-8", errors="replace") as fh:
                proc = subprocess.Popen(
                    cmd, stdout=fh, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, creationflags=cf,
                )
                returncode = proc.wait()

            stop_event.set()
            monitor_thread.join(timeout=2)
            _vol_clean_output(out_file)

            if returncode == 0:
                ok(f"Done  ({plugin_idx}/{total_plugins})")
            else:
                warn(f"Exit code {returncode}  ({plugin_idx}/{total_plugins}) — see output file")
        except Exception as exc:
            err(f"Failed to run plugin: {exc}")

    _vol_generate_html_report(output_dir, job)
    ok(f"Scan {job_index}/{total_jobs} complete → {output_dir}")

def _vol_run_queue(vol_exe, queue):
    if not queue:
        warn("Queue is empty — nothing to run.")
        return
    total_jobs = len(queue)
    info(f"Starting {total_jobs} queued scan(s)…")
    for idx, job in enumerate(queue, start=1):
        _vol_run_scan_job(vol_exe, job, idx, total_jobs)
        info(f"Overall: {idx}/{total_jobs} complete.")
    ok("All queued scans complete.")


# ── New scan workflow ─────────────────────────────────────────────

def _vol_new_scan_workflow(vol_exe):
    queue = []
    while True:
        try:
            job = _vol_configure_scan()
        except _VolCancelled:
            warn("Cancelled. Returning to Volatility menu.")
            if queue:
                ch = prompt(f"You have {len(queue)} queued scan(s). Run them now? (y/n):").strip().lower()
                if ch == "y":
                    _vol_run_queue(vol_exe, queue)
            return

        if job is None:
            warn("Scan configuration cancelled (nothing selected).")
        else:
            queue.append(job)
            ok(f"Scan added to queue (position {len(queue)}).")
            info(f"Image:   {job['image_path']}")
            info(f"Output:  {job['output_dir']}")
            info(f"OS:      {_VOL_OS_LABELS[job['target_os']]}")
            info(f"Plugins: {len(job['plugins'])} selected")

        again = prompt("Queue another scan? (y/n  or 'c' to cancel queue):").strip().lower()
        if again == "c":
            warn("Cancelled. Returning to Volatility menu.")
            if queue:
                ch = prompt(f"{len(queue)} scan(s) in queue — run them? (y/n):").strip().lower()
                if ch == "y":
                    _vol_run_queue(vol_exe, queue)
            return
        if again != "y":
            break

    _vol_run_queue(vol_exe, queue)
    pause()


# ── Main Volatility submenu ───────────────────────────────────────

def menu_volatility():
    """DFIRVault menu entry point for the Volatility 3 Memory Analyser."""
    vol_exe = _vol_ensure_exe()
    if not vol_exe:
        err("vol.exe not configured. Cannot continue.")
        pause()
        return

    while True:
        header("VOLATILITY 3  —  MEMORY ANALYSER")
        info(f"vol.exe: {vol_exe}")
        print()
        print(f"  {_c(C.CYAN,'[1]')} New scan  {_c(C.DIM,'configure + queue one or more memory analysis jobs')}")
        print(f"  {_c(C.CYAN,'[2]')} Performance settings  {_c(C.DIM,'parallelism / verbosity / smart cache')}")
        print(f"  {_c(C.CYAN,'[3]')} Change vol.exe location")
        print(f"  {_c(C.RED, '[0]')} Back")
        divider()
        ch = prompt("Choice:").strip()
        if ch == "1":
            clear_screen()
            _vol_new_scan_workflow(vol_exe)
        elif ch == "2":
            clear_screen()
            _vol_show_perf_menu()
        elif ch == "3":
            vol_exe = _vol_change_exe(vol_exe)
            pause()
        elif ch == "0":
            break
        else:
            err("Invalid choice.")
            pause()
        clear_screen()
        header("VOLATILITY 3  —  MEMORY ANALYSER")


def main():
    if not IS_WINDOWS:
        err("This tool is designed for Windows systems only.")
        sys.exit(1)
    
    check_for_updates()
    clear_screen()
    print(BANNER)
    while True:
        print(f"\n  {_c(C.BOLD+C.WHITE, '─── DFIR CASE MANAGEMENT ─────────────────')}")
        print(f"  {_c(C.CYAN,'[1]')} DFIR Case Manager {_c(C.DIM,'Create case folders locally, and zip archive to destination')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── SCANNING TOOLS ────────────────────────')}")
        print(f"  {_c(C.CYAN,'[2]')} Hayabusa  {_c(C.DIM,'EVTX log scanner — CSV + HTML reports')}")
        print(f"  {_c(C.CYAN,'[3]')} Chainsaw  {_c(C.DIM,'EVTX hunting with Sigma rules')}")
        print(f"  {_c(C.CYAN,'[4]')} Thor      {_c(C.DIM,'Drive / filesystem IOC scanner')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── SPLUNK ─────────────────────────────────')}")
        print(f"  {_c(C.CYAN,'[5]')} Splunk Index Manager {_c(C.DIM,'Manage indexes and upload data to Splunk')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── ELASTICSEARCH ──────────────────────────')}")
        print(f"  {_c(C.CYAN,'[6]')} ELK / Elasticsearch Manager  {_c(C.DIM,'Manage indexes and upload CSV data to Elasticsearch')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── FILE SYNC & TRANSFER ───────────────────')}")
        print(f"  {_c(C.CYAN,'[7]')} SFTP / FTP Monitor {_c(C.DIM,'Setup an SFTP monitor to either auto download or upload')}")
        print(f"  {_c(C.CYAN,'[8]')} VaultMirror  {_c(C.DIM,'safe scheduled sync')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── THREAT INTELLIGENCE ────────────────────')}")
        print(f"  {_c(C.CYAN,'[9]')} CSV Log Enricher  {_c(C.DIM,'enrich logs with OTX / AbuseIPDB / IP2Location / Tor')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── FORENSIC TIMELINE ──────────────────────')}")
        print(f"  {_c(C.CYAN,'[10]')} Bodyfile Explorer  {_c(C.DIM,'bodyfile → CSV + interactive forensic analysis')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── CSV UTILITIES ──────────────────────────')}")
        print(f"  {_c(C.CYAN,'[11]')} CSV Splitter        {_c(C.DIM,'split large CSVs by size or line count')}")
        print(f"  {_c(C.CYAN,'[12]')} CSV Timestamp Cleaner  {_c(C.DIM,'normalise timestamps to DD/MM/YYYY HH:MM:SS')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── DISK IMAGES ─────────────────────────────')}")
        print(f"  {_c(C.CYAN,'[13]')} Disk Image Converter  {_c(C.DIM,'qemu-img batch convert (raw/qcow2/vmdk/vhdx/...)')}")
        print()
        print(f"  {_c(C.BOLD+C.WHITE, '─── MEMORY FORENSICS ────────────────────────')}")
        print(f"  {_c(C.CYAN,'[14]')} Volatility 3 Analyser  {_c(C.DIM,'memory image analysis — plugin runner + HTML report')}")
        print()
        print(f"  {_c(C.RED,'[0]')} Exit")
        print()
        print(f"  {_c(C.DIM, '─' * 58)}")
        print(f"  {_c(C.DIM, 'Version')} {_c(C.CYAN, CURRENT_VERSION)}{_c(C.DIM, '  •  github.com/dfirvault/DFIRVault')}")
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
        elif choice == "11": clear_screen(); menu_csv_splitter()
        elif choice == "12": clear_screen(); menu_csv_timestamp_cleaner()
        elif choice == "13": clear_screen(); menu_disk_image_converter()
        elif choice == "14": clear_screen(); menu_volatility()
        elif choice == "0":
            print(); ok("Goodbye. Stay forensically sound."); print(); sys.exit(0)
        else:
            err("Invalid choice. Enter 1-14 or 0.")
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
