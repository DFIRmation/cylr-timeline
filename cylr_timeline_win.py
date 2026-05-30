#!/usr/bin/env python3
"""
cylr_timeline.py  —  CyLR Collection Timeline Parser
=====================================================
Parses an unzipped CyLR collection directory into a single unified
timeline CSV with all timestamps normalised to AEST
(Australia/Brisbane, UTC+10, no DST).

SELF-INSTALLING: Missing pip dependencies are auto-installed on first run.
Run with --check to see dependency and artifact status before parsing.

Compatible with: Windows 10/11, Linux, macOS
Requires:        Python 3.9+

Usage:
    python cylr_timeline.py --input C:\\Cases\\HOST01 --output HOST01.csv
    python cylr_timeline.py --input C:\\Cases\\HOST01 --output HOST01.csv --verbose
    python cylr_timeline.py --input C:\\Cases\\HOST01 --output HOST01.csv ^
        --only "Prefetch,SRUM,Event Logs"
    python cylr_timeline.py --check
    python cylr_timeline.py --input C:\\Cases\\HOST01 --check

Auto-installed dependencies (all have Windows wheels on PyPI):
    tzdata           - IANA timezone database for Windows
    python-evtx      - Windows Event Log (.evtx) parser
    regipy           - Windows registry hive parser
    libscca-python   - Prefetch parser incl. MAM-compressed Win10 files
    libesedb-python  - ESE database parser (SRUDB.dat)

Artifacts parsed (17 parsers):
    App Execution  : Prefetch, BAM/DAM, Amcache.hve, UserAssist, SRUM
    File Access    : LNK files, Shellbags, Office MRU, OpenSavePidlMRU
    Browser        : Chrome, Edge, Brave, Firefox (history + downloads)
    System Session : Security/System/Winlogon/Power/WLAN event logs
    Network        : SRUM network tables, NetworkList registry profiles
    Misc           : $RECYCLE.BIN, Sticky Notes, Scheduled Tasks,
                     Teams logs.txt, EventTranscript.db
"""

from __future__ import annotations

# ── Bootstrap: auto-install dependencies before anything else ─────────────────
import subprocess
import sys
import importlib
import platform

# On Linux/macOS the system Python may be PEP 668 "externally managed",
# requiring --break-system-packages.  Windows python.org installs don't use
# this and the flag does not exist there, so we gate it by OS.
_BREAK_FLAG = ["--break-system-packages"] if platform.system() != "Windows" else []

REQUIRED_PACKAGES = {
    # pip_name          : import_name
    "tzdata":            "tzdata",           # IANA tz data — needed on Windows
    "python-evtx":       "Evtx",
    "regipy":            "regipy",
    "libscca-python":    "pyscca",
    "libesedb-python":   "pyesedb",
}


def _ensure_deps(verbose: bool = False) -> dict:
    """Check each dependency; pip-install any that are missing."""
    status = {}
    for pip_name, import_name in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(import_name)
            status[pip_name] = True
        except ImportError:
            status[pip_name] = False

    missing = [k for k, v in status.items() if not v]
    if missing:
        print(f"[*] Auto-installing: {', '.join(missing)}", file=sys.stderr)
        cmd = [sys.executable, "-m", "pip", "install", "--quiet"] + \
              _BREAK_FLAG + missing
        result = subprocess.run(cmd, capture_output=not verbose)
        if result.returncode != 0:
            print("[!] pip install failed. Try manually:", file=sys.stderr)
            print(f"    pip install {' '.join(missing)}", file=sys.stderr)
            if verbose and result.stderr:
                print(result.stderr.decode(errors="replace"), file=sys.stderr)
        # Re-check after install
        for pip_name, import_name in REQUIRED_PACKAGES.items():
            try:
                importlib.import_module(import_name)
                status[pip_name] = True
            except ImportError:
                status[pip_name] = False

    return status


# Run bootstrap before forensic imports
_dep_status = _ensure_deps()

# ── Stdlib ────────────────────────────────────────────────────────────────────
import argparse
import csv
import json
import logging
import os
import re
import sqlite3
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional

# zoneinfo is stdlib from 3.9; tzdata provides the IANA DB on Windows.
from zoneinfo import ZoneInfo

# ── Conditional forensic imports ──────────────────────────────────────────────
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    EVTX_OK = True
except ImportError:
    EVTX_OK = False

try:
    from regipy.registry import RegistryHive
    REGIPY_OK = True
except ImportError:
    REGIPY_OK = False

try:
    import pyscca
    PYSCCA_OK = True
except ImportError:
    PYSCCA_OK = False

try:
    import pyesedb
    PYESEDB_OK = True
except ImportError:
    PYESEDB_OK = False

# ── Constants ─────────────────────────────────────────────────────────────────
AEST           = ZoneInfo("Australia/Brisbane")   # UTC+10, no DST
UTC            = timezone.utc
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
CHROME_EPOCH   = FILETIME_EPOCH
OA_EPOCH       = datetime(1899, 12, 30, tzinfo=UTC)  # OLE Automation Date epoch

CSV_COLS = [
    "timestamp_aest",
    "timestamp_utc",
    "artifact_category",
    "artifact_type",
    "event_description",
    "source_file",
    "username",
    "detail",
]

WANTED_EVENT_IDS = {
    "4624", "4625", "4634", "4647", "4648",
    "4800", "4801", "4802", "4803",
    "6005", "6006", "1074", "6008",
    "7045",
    "1", "107", "41",
    "8001", "8003",
    "811",  "812",
}

LOGON_TYPES = {
    "2": "Interactive",    "3": "Network",
    "4": "Batch",          "5": "Service",
    "7": "Unlock",         "8": "NetworkCleartext",
    "10": "RemoteInteractive", "11": "CachedInteractive",
}

EVENT_DESCRIPTIONS = {
    "4624": "Logon",               "4625": "Failed Logon",
    "4634": "Logoff (auto)",       "4647": "Logoff (user-initiated)",
    "4648": "Explicit Credential Logon",
    "4800": "Workstation Locked",  "4801": "Workstation Unlocked",
    "4802": "Screensaver On",      "4803": "Screensaver Off",
    "6005": "Event Log Started (Boot)",
    "6006": "Event Log Stopped (Shutdown)",
    "1074": "Shutdown/Restart Initiated",
    "6008": "Unexpected Shutdown",
    "7045": "Service Installed",
    "1":    "System Wake / Standby Resumed",
    "107":  "System Resumed from Sleep",
    "41":   "Unexpected Reboot (Kernel-Power)",
    "8001": "WiFi Connected",
    "8003": "WiFi Disconnected",
    "811":  "Logon Session Started (Winlogon)",
    "812":  "Logon Session Ended (Winlogon)",
}

SRUM_TABLES = {
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "App Resource Usage",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": "App Resource Usage (v2)",
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": "Network Data Usage",
    "{DD6636C4-8929-4683-974E-22C046A43763}": "Network Connections",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "Energy Usage",
    "{5C8CF1C7-A381-4A55-A0FE-2601B62D3DE5}": "App Timeline Provider",
}

# ── Logging ───────────────────────────────────────────────────────────────────
log = logging.getLogger("cylr_timeline")


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        format="%(levelname)-7s %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
        stream=sys.stderr,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# TIMESTAMP HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def filetime_to_dt(ft: int) -> Optional[datetime]:
    """Windows FILETIME (100-ns ticks since 1601-01-01 UTC)."""
    if not ft:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


def chrome_ts_to_dt(micros: int) -> Optional[datetime]:
    """Chrome/Edge timestamp (µs since 1601-01-01 UTC)."""
    if not micros:
        return None
    try:
        return CHROME_EPOCH + timedelta(microseconds=micros)
    except (OverflowError, OSError):
        return None


def unix_micros_to_dt(micros: int) -> Optional[datetime]:
    """Firefox visit_date (µs since Unix epoch)."""
    if not micros:
        return None
    try:
        return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=micros)
    except (OverflowError, OSError):
        return None


def unix_ts_to_dt(ts) -> Optional[datetime]:
    """Unix timestamp (seconds, int or float)."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def oa_date_to_dt(oa: float) -> Optional[datetime]:
    """
    OLE Automation Date (float: days since 1899-12-30 UTC).
    Used by the SRUM TimeStamp column.
    """
    if not oa:
        return None
    try:
        return OA_EPOCH + timedelta(days=float(oa))
    except (OverflowError, OSError, ValueError):
        return None


def to_aest(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(AEST)


def fmt(dt: datetime) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


# ═══════════════════════════════════════════════════════════════════════════════
# GENERAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def make_row(dt_utc: Optional[datetime], category: str, atype: str,
             description: str, source: str,
             username: str = "", detail: str = "") -> Optional[Dict]:
    if dt_utc is None:
        return None
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=UTC)
    aest_dt = to_aest(dt_utc)
    return {
        "timestamp_aest":    fmt(aest_dt),
        "timestamp_utc":     fmt(dt_utc),
        "artifact_category": category,
        "artifact_type":     atype,
        "event_description": description,
        "source_file":       str(source),
        "username":          username,
        "detail":            detail,
    }


def find_files(root: Path, *patterns: str) -> List[Path]:
    """Recursive glob for one or more patterns."""
    results = []
    for pat in patterns:
        try:
            results.extend(root.rglob(pat))
        except Exception:
            pass
    return results


def rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def open_sqlite_ro(db_path: Path) -> Optional[sqlite3.Connection]:
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        return conn
    except sqlite3.OperationalError as e:
        log.debug("SQLite open failed %s: %s", db_path.name, e)
        return None


def _extract_username(path: Path) -> str:
    """
    Extract a Windows username from a CyLR-mirrored path.
    CyLR preserves the full path including drive letter as a directory,
    e.g.  C\\Users\\bob\\AppData\\...  or  C/Users/bob/NTUSER.DAT
    Uses Path.parts so it's cross-platform safe.
    """
    parts = path.parts
    for i, part in enumerate(parts):
        if part.lower() in ("users", "user"):
            if i + 1 < len(parts):
                candidate = parts[i + 1]
                if candidate.lower() not in {
                    "all users", "public", "default", "default user",
                    "appdata", "local", "roaming",
                    "localservice", "networkservice",
                }:
                    return candidate
    return ""


def _is_browser_path(path: Path, *browser_markers: str) -> bool:
    """
    Check whether a path contains any of the given browser folder markers.
    Uses Path.parts for reliable cross-platform comparison (no str.replace hacks).
    """
    lower_parts = {p.lower() for p in path.parts}
    return any(m.lower() in lower_parts for m in browser_markers)


def _regipy_ts(ts) -> Optional[datetime]:
    if ts is None:
        return None
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except Exception:
            return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return ts if ts.year > 2000 else None
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# 1. APPLICATION EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

def parse_prefetch(root: Path) -> List[Dict]:
    """
    Parse Prefetch files.

    Primary path  : pyscca (libscca-python) — handles all versions
                    natively including MAM-compressed Win10 (v30).
    Fallback path : manual struct parsing for uncompressed v17/v23/v26
                    when pyscca is unavailable.  MAM files are skipped
                    with a warning in that case.
    """
    rows = []

    if PYSCCA_OK:
        for pf in find_files(root, "*.pf"):
            try:
                scca = pyscca.file()
                scca.open(str(pf))
                exe_name  = scca.executable_filename or pf.stem
                run_count = scca.run_count or 0
                for i in range(8):
                    try:
                        ts_int = scca.get_last_run_time_as_integer(i)
                        if ts_int <= 0:
                            continue
                        dt_utc = filetime_to_dt(ts_int)
                        if dt_utc and dt_utc.year > 2000:
                            row = make_row(
                                dt_utc, "App Execution", "Prefetch",
                                "Ran: {}".format(exe_name),
                                rel(root, pf),
                                detail="exe={} run_count={} slot={}/8".format(
                                    exe_name, run_count, i + 1)
                            )
                            if row:
                                rows.append(row)
                    except Exception:
                        pass
                scca.close()
            except Exception as e:
                log.debug("pyscca error %s: %s", pf.name, e)
        return rows

    # ── Fallback struct parser (non-MAM only) ─────────────────────────────────
    log.warning("pyscca unavailable — Prefetch: using struct fallback "
                "(MAM-compressed Win10 files will be skipped)")
    for pf in find_files(root, "*.pf"):
        try:
            data = pf.read_bytes()
            if len(data) < 0x60 or data[4:8] != b"SCCA":
                continue  # MAM-compressed: first 4 bytes are MAM header, not SCCA
            version   = struct.unpack_from("<I", data, 0)[0]
            exe_name  = data[0x10:0x50].decode("utf-16-le", errors="replace").rstrip("\x00")
            ts_offset   = {17: 0x78, 23: 0x78, 26: 0x80}.get(version, 0x80)
            cnt_offset  = {17: 0x90, 23: 0x90, 26: 0x98}.get(version, 0x98)
            run_count   = struct.unpack_from("<I", data, cnt_offset)[0] \
                          if len(data) >= cnt_offset + 4 else 0
            for i in range(8):
                off = ts_offset + i * 8
                if off + 8 > len(data):
                    break
                ft = struct.unpack_from("<Q", data, off)[0]
                if ft == 0:
                    break
                dt_utc = filetime_to_dt(ft)
                if dt_utc and dt_utc.year > 2000:
                    row = make_row(
                        dt_utc, "App Execution", "Prefetch",
                        "Ran: {}".format(exe_name),
                        rel(root, pf),
                        detail="exe={} run_count={} slot={}/8".format(
                            exe_name, run_count, i + 1)
                    )
                    if row:
                        rows.append(row)
        except Exception as e:
            log.debug("Prefetch struct error %s: %s", pf.name, e)
    return rows


def parse_bam(root: Path) -> List[Dict]:
    """
    BAM/DAM from SYSTEM hive.
    \\<ControlSet>\\Services\\bam|dam\\State\\UserSettings\\{SID}
    Each value whose name is an executable path holds a FILETIME at bytes 0-7.
    """
    if not REGIPY_OK:
        log.warning("regipy unavailable — skipping BAM/DAM")
        return []

    rows = []
    for hive_path in find_files(root, "SYSTEM"):
        if "config" not in str(hive_path).lower() or hive_path.suffix != "":
            continue
        try:
            hive = RegistryHive(str(hive_path))
            for service in ("bam", "dam"):
                for cs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
                    key_path = "\\{}\\Services\\{}\\State\\UserSettings".format(cs, service)
                    try:
                        key = hive.get_key(key_path)
                    except Exception:
                        continue
                    try:
                        for sid_key in key.iter_subkeys():
                            sid = sid_key.name
                            try:
                                for val in sid_key.iter_values():
                                    exe = val.name
                                    if exe in ("Version", "SequenceNumber"):
                                        continue
                                    raw = val.value
                                    if not isinstance(raw, bytes) or len(raw) < 8:
                                        continue
                                    ft = struct.unpack_from("<Q", raw, 0)[0]
                                    dt_utc = filetime_to_dt(ft)
                                    if dt_utc and dt_utc.year > 2000:
                                        row = make_row(
                                            dt_utc, "App Execution", "BAM/DAM",
                                            "Ran: {}".format(Path(exe).name),
                                            rel(root, hive_path),
                                            detail="exe={} sid={} service={}".format(
                                                exe, sid, service)
                                        )
                                        if row:
                                            rows.append(row)
                            except Exception:
                                pass
                    except Exception:
                        pass
        except Exception as e:
            log.debug("BAM error %s: %s", hive_path, e)
    return rows


def parse_amcache(root: Path) -> List[Dict]:
    """Amcache.hve — app install/execution history."""
    if not REGIPY_OK:
        log.warning("regipy unavailable — skipping Amcache")
        return []

    rows = []
    for hive_path in find_files(root, "Amcache.hve"):
        try:
            hive = RegistryHive(str(hive_path))
            # Win10+ layout
            try:
                inv = hive.get_key("\\InventoryApplicationFile")
                for app_key in inv.iter_subkeys():
                    ts   = _regipy_ts(app_key.header.last_modified)
                    vals = {v.name: v.value for v in app_key.iter_values()}
                    name = vals.get("Name", app_key.name)
                    pub  = vals.get("Publisher", "")
                    link = vals.get("LinkDate", "")
                    row  = make_row(
                        ts, "App Execution", "Amcache",
                        "App seen: {}".format(name),
                        rel(root, hive_path),
                        detail="name={} publisher={} link_date={}".format(name, pub, link)
                    )
                    if row:
                        rows.append(row)
            except Exception:
                pass
            # Legacy layout
            try:
                file_key = hive.get_key("\\File")
                for vol_key in file_key.iter_subkeys():
                    for seq_key in vol_key.iter_subkeys():
                        ts    = _regipy_ts(seq_key.header.last_modified)
                        vals  = {v.name: v.value for v in seq_key.iter_values()}
                        pval  = vals.get("15", seq_key.name)
                        row   = make_row(
                            ts, "App Execution", "Amcache (legacy)",
                            "App seen: {}".format(Path(str(pval)).name),
                            rel(root, hive_path),
                            detail="path={}".format(pval)
                        )
                        if row:
                            rows.append(row)
            except Exception:
                pass
        except Exception as e:
            log.debug("Amcache error %s: %s", hive_path, e)
    return rows


def parse_userassist(root: Path) -> List[Dict]:
    """
    UserAssist from NTUSER.DAT — GUI apps launched via Explorer.
    Key names are ROT13-encoded.  72-byte value struct (Win7+):
      +4   run count (DWORD)
      +60  last exec FILETIME (QWORD)
    """
    if not REGIPY_OK:
        return []

    ROT13 = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    )
    UA_ROOT = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"

    rows = []
    for ntuser in find_files(root, "NTUSER.DAT"):
        username = _extract_username(ntuser)
        try:
            hive = RegistryHive(str(ntuser))
            try:
                ua_key = hive.get_key(UA_ROOT)
            except Exception:
                continue
            for guid_key in ua_key.iter_subkeys():
                try:
                    count_key = guid_key.get_subkey("Count")
                except Exception:
                    continue
                try:
                    for val in count_key.iter_values():
                        name      = val.name.translate(ROT13)
                        raw       = val.value
                        if not isinstance(raw, bytes) or len(raw) < 16:
                            continue
                        run_count = struct.unpack_from("<I", raw, 4)[0] if len(raw) >= 8 else 0
                        ft_offset = 60 if len(raw) >= 68 else len(raw) - 8
                        if ft_offset < 0:
                            continue
                        ft = struct.unpack_from("<Q", raw, ft_offset)[0]
                        if ft == 0:
                            continue
                        dt_utc = filetime_to_dt(ft)
                        exe_name = Path(name.split("\\")[-1]).name
                        row = make_row(
                            dt_utc, "App Execution", "UserAssist",
                            "GUI launch: {}".format(exe_name),
                            rel(root, ntuser),
                            username=username,
                            detail="app={} run_count={}".format(name, run_count)
                        )
                        if row:
                            rows.append(row)
                except Exception:
                    pass
        except Exception as e:
            log.debug("UserAssist error %s: %s", ntuser, e)
    return rows


# ═══════════════════════════════════════════════════════════════════════════════
# 2. SRUM  (System Resource Usage Monitor)
# ═══════════════════════════════════════════════════════════════════════════════

def _ese_get_col_names(table) -> List[str]:
    return [table.get_column(i).name for i in range(table.number_of_columns)]


def _ese_record_value(record, col_idx: int, col_type: int):
    ct = pyesedb.column_types
    try:
        if col_type in (ct.INTEGER_8BIT_UNSIGNED, ct.INTEGER_16BIT_SIGNED,
                        ct.INTEGER_16BIT_UNSIGNED, ct.INTEGER_32BIT_SIGNED,
                        ct.INTEGER_32BIT_UNSIGNED, ct.INTEGER_64BIT_SIGNED):
            return record.get_value_data_as_integer(col_idx)
        elif col_type in (ct.FLOAT_32BIT, ct.DOUBLE_64BIT, ct.DATE_TIME):
            return record.get_value_data_as_floating_point(col_idx)
        elif col_type in (ct.TEXT, ct.LARGE_TEXT):
            return record.get_value_data_as_string(col_idx)
        else:
            raw = record.get_value_data(col_idx)
            if raw:
                return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            return None
    except Exception:
        return None


def _build_srum_id_map(esedb) -> Dict[int, str]:
    id_map: Dict[int, str] = {}
    try:
        table     = esedb.get_table_by_name("SruDbIdMapTable")
        col_names = _ese_get_col_names(table)
        idx_index = col_names.index("IdIndex") if "IdIndex" in col_names else 1
        idx_blob  = col_names.index("IdBlob")  if "IdBlob"  in col_names else 2
        for rec_idx in range(table.number_of_records):
            rec = table.get_record(rec_idx)
            try:
                id_index = rec.get_value_data_as_integer(idx_index)
                raw      = rec.get_value_data(idx_blob)
                if raw:
                    id_map[id_index] = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            except Exception:
                pass
    except Exception as e:
        log.debug("SRUM id_map error: %s", e)
    return id_map


def parse_srum(root: Path) -> List[Dict]:
    """
    Parse SRUDB.dat directly via pyesedb — no pre-export required.
    TimeStamp column is an OLE Automation Date (float: days since 1899-12-30 UTC).
    AppId/UserId are integer FKs resolved against SruDbIdMapTable.
    """
    if not PYESEDB_OK:
        log.warning("pyesedb unavailable — skipping SRUM")
        return []

    rows = []
    for sru_path in find_files(root, "SRUDB.dat"):
        try:
            esedb  = pyesedb.file()
            esedb.open(str(sru_path))
            id_map = _build_srum_id_map(esedb)
            log.debug("SRUM: %d id_map entries from %s", len(id_map), sru_path.name)

            for guid, friendly in SRUM_TABLES.items():
                try:
                    table = esedb.get_table_by_name(guid)
                except Exception:
                    continue

                col_names  = _ese_get_col_names(table)
                col_types  = [table.get_column(i).type for i in range(table.number_of_columns)]
                ts_idx     = col_names.index("TimeStamp") if "TimeStamp" in col_names else None
                app_idx    = col_names.index("AppId")     if "AppId"     in col_names else None
                user_idx   = col_names.index("UserId")    if "UserId"    in col_names else None

                if ts_idx is None:
                    continue

                detail_cols = [c for c in (
                    "ForegroundCycleTime", "BackgroundCycleTime",
                    "ForegroundBytesRead", "ForegroundBytesWritten",
                    "BytesSent", "BytesRecvd", "ConnectedTime",
                    "ConnectStartTime", "ActiveAcTime",
                ) if c in col_names]

                category = "Network" if "Network" in friendly else "App Execution"

                for rec_idx in range(table.number_of_records):
                    try:
                        rec      = table.get_record(rec_idx)
                        ts_val   = _ese_record_value(rec, ts_idx, col_types[ts_idx])
                        dt_utc   = oa_date_to_dt(ts_val)
                        if dt_utc is None or dt_utc.year < 2000:
                            continue

                        app_name = ""
                        username = ""
                        if app_idx is not None:
                            app_id   = _ese_record_value(rec, app_idx, col_types[app_idx])
                            app_name = id_map.get(app_id, str(app_id))
                        if user_idx is not None:
                            user_id  = _ese_record_value(rec, user_idx, col_types[user_idx])
                            username = id_map.get(user_id, "")

                        detail_parts = ["table={}".format(friendly)]
                        for dc in detail_cols:
                            idx = col_names.index(dc)
                            v   = _ese_record_value(rec, idx, col_types[idx])
                            if v:
                                detail_parts.append("{}={}".format(dc, v))

                        short_app = Path(app_name).name if app_name else "unknown"
                        row = make_row(
                            dt_utc, category, "SRUM {}".format(friendly),
                            "SRUM: {} [{}]".format(short_app, friendly),
                            rel(root, sru_path),
                            username=username,
                            detail="; ".join(detail_parts)
                        )
                        if row:
                            rows.append(row)
                    except Exception as e:
                        log.debug("SRUM record error in %s: %s", guid, e)

            esedb.close()
        except Exception as e:
            log.warning("SRUM open error %s: %s", sru_path.name, e)
    return rows


# ═══════════════════════════════════════════════════════════════════════════════
# 3. FILE & FOLDER ACCESS
# ═══════════════════════════════════════════════════════════════════════════════

def parse_lnk(root: Path) -> List[Dict]:
    """
    Parse Shell Link (.lnk) files.
    Header offsets:  0x1C creation, 0x24 access, 0x2C write (all FILETIME).
    """
    rows = []
    for lnk_path in find_files(root, "*.lnk"):
        try:
            data = lnk_path.read_bytes()
            if len(data) < 0x4C or data[0:4] != b"\x4C\x00\x00\x00":
                continue
            creation = filetime_to_dt(struct.unpack_from("<Q", data, 0x1C)[0])
            access   = filetime_to_dt(struct.unpack_from("<Q", data, 0x24)[0])
            write    = filetime_to_dt(struct.unpack_from("<Q", data, 0x2C)[0])
            target   = lnk_path.stem
            username = _extract_username(lnk_path)
            for ts, label in [
                (creation, "first-opened (LNK created)"),
                (access,   "last-opened (LNK accessed)"),
                (write,    "target last-modified"),
            ]:
                if ts and ts.year > 2000:
                    row = make_row(
                        ts, "File Access", "LNK File",
                        "File interaction: {}  [{}]".format(target, label),
                        rel(root, lnk_path),
                        username=username,
                        detail="lnk={} ts_type={}".format(lnk_path.name, label)
                    )
                    if row:
                        rows.append(row)
        except Exception as e:
            log.debug("LNK error %s: %s", lnk_path.name, e)
    return rows


def parse_shellbags(root: Path) -> List[Dict]:
    """Shellbags from NTUSER.DAT and UsrClass.dat."""
    if not REGIPY_OK:
        return []

    rows = []
    for ntuser in find_files(root, "NTUSER.DAT"):
        _shellbag_hive(ntuser, root, rows)
    for usrcls in find_files(root, "UsrClass.dat"):
        _shellbag_hive(usrcls, root, rows)
    return rows


def _shellbag_hive(hive_path: Path, root: Path, rows: List[Dict]) -> None:
    username = _extract_username(hive_path)
    try:
        hive = RegistryHive(str(hive_path))
        for subkey in hive.recurse_subkeys(fetch_values=False):
            if "BagMRU" not in (subkey.path or ""):
                continue
            ts = _regipy_ts(subkey.timestamp)
            if ts is None:
                continue
            row = make_row(
                ts, "File Access", "Shellbags",
                "Folder browsed: {}".format(subkey.path),
                rel(root, hive_path),
                username=username,
                detail="key={}".format(subkey.path)
            )
            if row:
                rows.append(row)
    except Exception as e:
        log.debug("Shellbags error %s: %s", hive_path, e)


def parse_office_mru(root: Path) -> List[Dict]:
    """
    Office Recent Files from NTUSER.DAT.
    Values contain embedded FILETIME in [Txxxxxxxxxxxxxxxx] format.
    """
    if not REGIPY_OK:
        return []

    rows = []
    for ntuser in find_files(root, "NTUSER.DAT"):
        username = _extract_username(ntuser)
        try:
            hive = RegistryHive(str(ntuser))
            try:
                off_key = hive.get_key("\\Software\\Microsoft\\Office")
            except Exception:
                continue
            for ver_key in off_key.iter_subkeys():
                for app_key in ver_key.iter_subkeys():
                    mru_path = (
                        "\\Software\\Microsoft\\Office\\"
                        "{}\\{}\\File MRU".format(ver_key.name, app_key.name)
                    )
                    try:
                        mru_key = hive.get_key(mru_path)
                    except Exception:
                        continue
                    fallback_ts = _regipy_ts(mru_key.header.last_modified)
                    try:
                        for val in mru_key.iter_values():
                            if not val.name.startswith("Item"):
                                continue
                            raw_str  = str(val.value or "")
                            m        = re.search(r"\[T([0-9A-Fa-f]{16})\]", raw_str)
                            dt_utc   = filetime_to_dt(int(m.group(1), 16)) if m else fallback_ts
                            path_m   = re.search(r"\*([^\*]+)$", raw_str)
                            file_path = path_m.group(1) if path_m else raw_str
                            if dt_utc and dt_utc.year > 2000:
                                row = make_row(
                                    dt_utc, "File Access", "Office MRU",
                                    "Office file opened: {}".format(Path(file_path).name),
                                    rel(root, ntuser),
                                    username=username,
                                    detail="app={} ver={} path={}".format(
                                        app_key.name, ver_key.name, file_path)
                                )
                                if row:
                                    rows.append(row)
                    except Exception:
                        pass
        except Exception as e:
            log.debug("Office MRU error %s: %s", ntuser, e)
    return rows


def parse_opensave_mru(root: Path) -> List[Dict]:
    """OpenSavePidlMRU — files opened/saved via standard dialogs."""
    if not REGIPY_OK:
        return []

    KEY = ("\\Software\\Microsoft\\Windows\\CurrentVersion"
           "\\Explorer\\ComDlg32\\OpenSavePidlMRU")
    rows = []
    for ntuser in find_files(root, "NTUSER.DAT"):
        username = _extract_username(ntuser)
        try:
            hive = RegistryHive(str(ntuser))
            try:
                mru_key = hive.get_key(KEY)
            except Exception:
                continue
            for ext_key in mru_key.iter_subkeys():
                ts = _regipy_ts(ext_key.header.last_modified)
                if ts is None:
                    continue
                row = make_row(
                    ts, "File Access", "OpenSavePidlMRU",
                    "Open/Save dialog: .{} files".format(ext_key.name),
                    rel(root, ntuser),
                    username=username,
                    detail="extension={}".format(ext_key.name)
                )
                if row:
                    rows.append(row)
        except Exception as e:
            log.debug("OpenSaveMRU error %s: %s", ntuser, e)
    return rows


# ═══════════════════════════════════════════════════════════════════════════════
# 4. BROWSER ACTIVITY
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_chromium_history(db_path: Path, browser: str, root: Path) -> List[Dict]:
    rows: List[Dict] = []
    conn = open_sqlite_ro(db_path)
    if conn is None:
        return rows
    username = _extract_username(db_path)
    try:
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT v.visit_time, u.url, u.title, v.visit_duration
                FROM visits v JOIN urls u ON v.url = u.id
                WHERE v.visit_time > 0 ORDER BY v.visit_time
            """)
            for vt, url, title, dur in cur.fetchall():
                row = make_row(
                    chrome_ts_to_dt(vt), "Browser", "{} History".format(browser),
                    "Visited: {}".format(title or url[:80]),
                    rel(root, db_path), username=username,
                    detail="url={} duration_ms={}".format(
                        url, dur // 1000 if dur else 0)
                )
                if row:
                    rows.append(row)
        except Exception as e:
            log.debug("%s visits error: %s", browser, e)
        try:
            cur.execute(
                "SELECT start_time, target_path, tab_url FROM downloads WHERE start_time > 0")
            for st, target, src in cur.fetchall():
                fname = Path(target).name if target else "unknown"
                row   = make_row(
                    chrome_ts_to_dt(st), "Browser", "{} Download".format(browser),
                    "Downloaded: {}".format(fname),
                    rel(root, db_path), username=username,
                    detail="target={} src={}".format(target, src)
                )
                if row:
                    rows.append(row)
        except Exception as e:
            log.debug("%s downloads error: %s", browser, e)
    finally:
        conn.close()
    return rows


def parse_browser_history(root: Path) -> List[Dict]:
    rows: List[Dict] = []
    for h in find_files(root, "History"):
        # Use Path.parts for reliable cross-platform browser detection
        if _is_browser_path(h, "Google", "Chrome"):
            rows.extend(_parse_chromium_history(h, "Chrome", root))
        elif _is_browser_path(h, "Microsoft", "Edge"):
            rows.extend(_parse_chromium_history(h, "Edge", root))
        elif _is_browser_path(h, "BraveSoftware"):
            rows.extend(_parse_chromium_history(h, "Brave", root))

    for places in find_files(root, "places.sqlite"):
        username = _extract_username(places)
        conn     = open_sqlite_ro(places)
        if conn is None:
            continue
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT v.visit_date, p.url, p.title
                FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id
                WHERE v.visit_date > 0 ORDER BY v.visit_date
            """)
            for vd, url, title in cur.fetchall():
                row = make_row(
                    unix_micros_to_dt(vd), "Browser", "Firefox History",
                    "Visited: {}".format(title or url[:80]),
                    rel(root, places), username=username,
                    detail="url={}".format(url)
                )
                if row:
                    rows.append(row)
        except Exception as e:
            log.debug("Firefox error: %s", e)
        finally:
            conn.close()
    return rows


# ═══════════════════════════════════════════════════════════════════════════════
# 5. SYSTEM SESSION (Event Logs)
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_evtx_file(evtx_path: Path, root: Path) -> List[Dict]:
    rows: List[Dict] = []
    NS  = "http://schemas.microsoft.com/win/2004/08/events/event"
    ns  = {"e": NS}
    try:
        with Evtx(str(evtx_path)) as lf:
            for xml_str, _ in evtx_file_xml_view(lf.chunks()):
                try:
                    tree   = ET.fromstring(xml_str)
                    sys_el = tree.find("e:System", ns)
                    if sys_el is None:
                        continue
                    eid_el = sys_el.find("e:EventID", ns)
                    eid    = eid_el.text.strip() if eid_el is not None else ""
                    if eid not in WANTED_EVENT_IDS:
                        continue
                    ts_el  = sys_el.find("e:TimeCreated", ns)
                    ts_str = ts_el.get("SystemTime", "") if ts_el is not None else ""
                    try:
                        dt_utc = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    except Exception:
                        continue
                    ch_el  = sys_el.find("e:Channel", ns)
                    ch     = ch_el.text.strip() if ch_el is not None else ""
                    co_el  = sys_el.find("e:Computer", ns)
                    comp   = co_el.text.strip() if co_el is not None else ""
                    ed_el  = tree.find("e:EventData", ns)
                    ed: Dict[str, str] = {}
                    if ed_el is not None:
                        for d in ed_el.findall("e:Data", ns):
                            ed[d.get("Name", "")] = (d.text or "").strip()
                    username = (ed.get("TargetUserName") or
                                ed.get("SubjectUserName") or "")
                    if username.startswith("$") or username == "-":
                        username = ""
                    lt_num  = ed.get("LogonType", "")
                    lt_str  = LOGON_TYPES.get(lt_num, lt_num)
                    base    = EVENT_DESCRIPTIONS.get(eid, "Event {}".format(eid))
                    if eid == "4624" and lt_str:
                        desc = "{} ({})".format(base, lt_str)
                    elif eid in ("8001", "8003"):
                        ssid = ed.get("SSID", ed.get("ProfileName", ""))
                        desc = "{}: {}".format(base, ssid) if ssid else base
                    elif eid == "7045":
                        desc = "{}: {}".format(base, ed.get("ServiceName", ""))
                    elif eid == "1074":
                        reason = ed.get("Comment", ed.get("Reason", ""))
                        desc   = "{}: {}".format(base, reason) if reason else base
                    else:
                        desc = base
                    detail_items = [
                        "EventID={}".format(eid),
                        "Channel={}".format(ch),
                        "Computer={}".format(comp),
                    ]
                    for k in ("LogonType", "WorkstationName", "IpAddress",
                              "ProcessName", "SSID", "ServiceName", "Reason"):
                        v = ed.get(k, "")
                        if v and v != "-":
                            detail_items.append("{}={}".format(k, v))
                    category = "Network" if eid in ("8001", "8003") else "System Session"
                    row = make_row(
                        dt_utc, category, "EventLog ({})".format(evtx_path.stem),
                        desc, rel(root, evtx_path),
                        username=username,
                        detail="; ".join(detail_items)
                    )
                    if row:
                        rows.append(row)
                except Exception as e:
                    log.debug("EVTX record error %s: %s", evtx_path.name, e)
    except Exception as e:
        log.warning("Could not open EVTX %s: %s", evtx_path.name, e)
    return rows


def parse_event_logs(root: Path) -> List[Dict]:
    if not EVTX_OK:
        log.warning("python-evtx unavailable — skipping Event Logs")
        return []
    rows: List[Dict] = []
    evtx_files = find_files(root, "*.evtx")
    log.info("Found %d .evtx file(s)", len(evtx_files))
    for f in evtx_files:
        fr = _parse_evtx_file(f, root)
        log.debug("  %s: %d events", f.name, len(fr))
        rows.extend(fr)
    return rows


# ═══════════════════════════════════════════════════════════════════════════════
# 6. NETWORK
# ═══════════════════════════════════════════════════════════════════════════════

def parse_network_profiles(root: Path) -> List[Dict]:
    """
    NetworkList from SOFTWARE hive.
    DateCreated / DateLastConnected are 16-byte SYSTEMTIME structs.
    """
    if not REGIPY_OK:
        return []

    KEY  = ("\\Microsoft\\Windows NT\\CurrentVersion"
            "\\NetworkList\\Profiles")
    rows: List[Dict] = []
    for soft in find_files(root, "SOFTWARE"):
        if "config" not in str(soft).lower() or soft.suffix != "":
            continue
        try:
            hive = RegistryHive(str(soft))
            try:
                profiles = hive.get_key(KEY)
            except Exception:
                continue
            for profile in profiles.iter_subkeys():
                vals: Dict = {}
                try:
                    for v in profile.iter_values():
                        vals[v.name] = v.value
                except Exception:
                    pass
                name = vals.get("ProfileName", profile.name)
                for vname, label in [("DateCreated",       "first joined"),
                                     ("DateLastConnected", "last connected")]:
                    raw = vals.get(vname)
                    if not isinstance(raw, bytes) or len(raw) < 16:
                        continue
                    try:
                        yr, mo, _, dy, hr, mn, sc, ms = struct.unpack_from("<8H", raw)
                        if yr < 1970 or yr > 2100:
                            continue
                        dt_utc = datetime(yr, mo, dy, hr, mn, sc, ms * 1000, tzinfo=UTC)
                        row = make_row(
                            dt_utc, "Network", "NetworkList Profile",
                            "Network profile: {}  [{}]".format(name, label),
                            rel(root, soft),
                            detail="profile={} ts_type={}".format(name, label)
                        )
                        if row:
                            rows.append(row)
                    except Exception as e:
                        log.debug("NetworkList date error: %s", e)
        except Exception as e:
            log.debug("NetworkList error %s: %s", soft, e)
    return rows


# ═══════════════════════════════════════════════════════════════════════════════
# 7. MISCELLANEOUS
# ═══════════════════════════════════════════════════════════════════════════════

def parse_recycle_bin(root: Path) -> List[Dict]:
    """
    $RECYCLE.BIN $I files.
    v1: +16 = deletion FILETIME, +24 = 520-byte UTF-16LE path
    v2: +16 = deletion FILETIME, +24 = 4-byte len, +28 = UTF-16LE path
    """
    rows: List[Dict] = []
    # Walk the tree and match files whose name starts with $I
    # (rglob("$I*") — $ is not a glob metachar, so this works on all platforms)
    for i_file in find_files(root, "$I*"):
        if i_file.name.upper().startswith("$R"):
            continue
        try:
            data = i_file.read_bytes()
            if len(data) < 24:
                continue
            version = struct.unpack_from("<Q", data, 0)[0]
            ft      = struct.unpack_from("<Q", data, 16)[0]
            dt_utc  = filetime_to_dt(ft)
            if not dt_utc or dt_utc.year < 2000:
                continue
            if version == 2 and len(data) > 28:
                flen = struct.unpack_from("<I", data, 24)[0]
                orig = data[28: 28 + flen * 2].decode("utf-16-le", errors="replace").rstrip("\x00")
            elif version == 1 and len(data) >= 544:
                orig = data[24:544].decode("utf-16-le", errors="replace").rstrip("\x00")
            else:
                orig = i_file.stem.replace("$I", "")
            username = _extract_username(i_file)
            row = make_row(
                dt_utc, "Misc", "$RECYCLE.BIN",
                "File deleted: {}".format(Path(orig).name),
                rel(root, i_file),
                username=username,
                detail="original_path={}".format(orig)
            )
            if row:
                rows.append(row)
        except Exception as e:
            log.debug("RecycleBin error %s: %s", i_file, e)
    return rows


def parse_sticky_notes(root: Path) -> List[Dict]:
    """Sticky Notes plum.sqlite."""
    rows: List[Dict] = []
    for db_path in find_files(root, "plum.sqlite"):
        username = _extract_username(db_path)
        conn     = open_sqlite_ro(db_path)
        if conn is None:
            continue
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT CreatedAt, UpdatedAt, Text, Id FROM Note ORDER BY CreatedAt")
            for created, updated, text, note_id in cur.fetchall():
                snippet = str(text or "")[:80].replace("\n", " ")
                for ts_val, ts_label in [(created, "created"), (updated, "modified")]:
                    if not ts_val:
                        continue
                    dt_utc = None
                    if isinstance(ts_val, (int, float)):
                        try:
                            dt_utc = datetime(1, 1, 1, tzinfo=UTC) + timedelta(
                                microseconds=int(ts_val) // 10)
                            if dt_utc.year < 2000:
                                dt_utc = unix_ts_to_dt(ts_val)
                        except Exception:
                            dt_utc = unix_ts_to_dt(ts_val)
                    elif isinstance(ts_val, str):
                        try:
                            dt_utc = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                        except Exception:
                            pass
                    row = make_row(
                        dt_utc, "Misc", "Sticky Notes",
                        "Sticky note [{}]: {}".format(ts_label, snippet),
                        rel(root, db_path),
                        username=username,
                        detail="note_id={} ts_type={}".format(note_id, ts_label)
                    )
                    if row:
                        rows.append(row)
        except Exception as e:
            log.debug("Sticky notes error: %s", e)
        finally:
            conn.close()
    return rows


def parse_scheduled_tasks(root: Path) -> List[Dict]:
    """Scheduled Task XML files under Windows/System32/Tasks."""
    rows: List[Dict] = []
    for xml_path in find_files(root, "*.xml"):
        if "tasks" not in str(xml_path).lower():
            continue
        if xml_path.stat().st_size > 256 * 1024:
            continue
        try:
            tree    = ET.parse(str(xml_path))
            r       = tree.getroot()
            ns_free = re.sub(r"\{[^}]+\}", "", ET.tostring(r, encoding="unicode"))
            r2      = ET.fromstring(ns_free)
            date_el = r2.find("RegistrationInfo/Date")
            if date_el is None or not date_el.text:
                continue
            try:
                dt_utc = datetime.fromisoformat(
                    date_el.text.strip().replace("Z", "+00:00"))
            except Exception:
                continue
            cmd_el    = r2.find(".//Command")
            cmd       = cmd_el.text.strip() if cmd_el is not None else ""
            row = make_row(
                dt_utc, "Misc", "Scheduled Task",
                "Task registered: {}".format(xml_path.stem),
                rel(root, xml_path),
                detail="task={} cmd={}".format(xml_path.stem, cmd)
            )
            if row:
                rows.append(row)
        except Exception as e:
            log.debug("Sched task error %s: %s", xml_path.name, e)
    return rows


def parse_teams_log(root: Path) -> List[Dict]:
    """Teams classic logs.txt."""
    rows: List[Dict] = []
    TS_RE    = re.compile(
        r"^(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})\s+GMT")
    KEYWORDS = {"meeting", "call", "joined", "left", "started", "ended",
                "login", "logout", "signed", "app initialized"}
    for log_path in find_files(root, "logs.txt"):
        if "teams" not in str(log_path).lower():
            continue
        username = _extract_username(log_path)
        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = TS_RE.match(line)
                    if not m:
                        continue
                    try:
                        dt_utc = datetime.strptime(
                            m.group(1), "%a %b %d %Y %H:%M:%S").replace(tzinfo=UTC)
                    except Exception:
                        continue
                    if any(kw in line.lower() for kw in KEYWORDS):
                        snippet = line[m.end():].strip()[:120]
                        row = make_row(
                            dt_utc, "Misc", "Teams Log",
                            "Teams event: {}".format(snippet),
                            rel(root, log_path),
                            username=username,
                            detail="raw={}".format(snippet[:200])
                        )
                        if row:
                            rows.append(row)
        except Exception as e:
            log.debug("Teams log error: %s", e)
    return rows


def parse_event_transcript(root: Path) -> List[Dict]:
    """EventTranscript.db — Windows Diagnostic Data Viewer."""
    rows: List[Dict] = []
    for db_path in find_files(root, "EventTranscript.db"):
        conn = open_sqlite_ro(db_path)
        if conn is None:
            continue
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT timestamp, full_event_name, payload "
                "FROM events_persisted ORDER BY timestamp")
            for ts_ms, event_name, payload in cur.fetchall():
                if not ts_ms:
                    continue
                dt_utc = unix_ts_to_dt(ts_ms / 1000.0)
                try:
                    pdata = json.loads(payload) if payload else {}
                    app   = pdata.get("data", {}).get("AppId", "")
                except Exception:
                    app = ""
                row = make_row(
                    dt_utc, "Misc", "EventTranscript",
                    "Diagnostic event: {}{}".format(
                        event_name, " | {}".format(app) if app else ""),
                    rel(root, db_path),
                    detail="event={} app={}".format(event_name, app)
                )
                if row:
                    rows.append(row)
        except Exception as e:
            log.debug("EventTranscript error: %s", e)
        finally:
            conn.close()
    return rows


# ═══════════════════════════════════════════════════════════════════════════════
# READINESS CHECK
# ═══════════════════════════════════════════════════════════════════════════════

def run_check(root: Optional[Path] = None) -> None:
    print("\n── Dependency Status ─────────────────────────────────────────────")
    dep_flags = {
        "tzdata":          _dep_status.get("tzdata", False),
        "python-evtx":     EVTX_OK,
        "regipy":          REGIPY_OK,
        "libscca-python":  PYSCCA_OK,
        "libesedb-python": PYESEDB_OK,
    }
    all_ok = True
    for pkg, ok in dep_flags.items():
        mark  = "OK " if ok else "!!!"
        label = "installed" if ok else "MISSING  (run: pip install {})".format(pkg)
        print("  [{}]  {:<22}  {}".format(mark, pkg, label))
        if not ok:
            all_ok = False
    if all_ok:
        print("  All dependencies satisfied.")

    print("\n── Parsing Capability ────────────────────────────────────────────")
    caps = [
        ("Prefetch — Win10 MAM-compressed",  PYSCCA_OK,   "libscca-python"),
        ("Prefetch — v17/v23/v26 (fallback)", True,        "built-in struct"),
        ("SRUM SRUDB.dat",                   PYESEDB_OK,  "libesedb-python"),
        ("Event Logs .evtx",                 EVTX_OK,     "python-evtx"),
        ("Registry hives",                   REGIPY_OK,   "regipy"),
        ("LNK files",                        True,         "built-in struct"),
        ("Browser SQLite DBs",               True,         "built-in sqlite3"),
        ("$RECYCLE.BIN $I files",            True,         "built-in struct"),
        ("Scheduled Tasks XML",              True,         "built-in xml"),
        ("Sticky Notes SQLite",              True,         "built-in sqlite3"),
        ("Teams logs.txt",                   True,         "built-in re"),
        ("EventTranscript.db",               True,         "built-in sqlite3"),
    ]
    for name, ok, lib in caps:
        mark = "OK " if ok else "!!!"
        print("  [{}]  {:<42}  (via {})".format(mark, name, lib))

    if root is None:
        print("\n  Tip: add --input <path> to also check artifact presence.")
        return

    print("\n── Artifact Presence in {} ──".format(root))
    checks = [
        ("Prefetch files (.pf)",
            list(root.rglob("*.pf"))),
        ("EVTX log files",
            list(root.rglob("*.evtx"))),
        ("SRUDB.dat",
            list(root.rglob("SRUDB.dat"))),
        ("Amcache.hve",
            list(root.rglob("Amcache.hve"))),
        ("SYSTEM hive",
            [p for p in root.rglob("SYSTEM")
             if "config" in str(p).lower() and p.suffix == ""]),
        ("SOFTWARE hive",
            [p for p in root.rglob("SOFTWARE")
             if "config" in str(p).lower() and p.suffix == ""]),
        ("NTUSER.DAT",
            list(root.rglob("NTUSER.DAT"))),
        ("LNK files",
            list(root.rglob("*.lnk"))),
        ("Chrome/Edge History",
            [p for p in root.rglob("History")
             if _is_browser_path(p, "Chrome", "Edge", "BraveSoftware")]),
        ("Firefox places.sqlite",
            list(root.rglob("places.sqlite"))),
        ("EventTranscript.db",
            list(root.rglob("EventTranscript.db"))),
        ("$RECYCLE.BIN $I files",
            [p for p in root.rglob("$I*")
             if not p.name.upper().startswith("$R")]),
        ("Sticky Notes plum.sqlite",
            list(root.rglob("plum.sqlite"))),
        ("Scheduled Task XMLs",
            [p for p in root.rglob("*.xml")
             if "tasks" in str(p).lower()]),
        ("Teams logs.txt",
            [p for p in root.rglob("logs.txt")
             if "teams" in str(p).lower()]),
    ]
    for label, files in checks:
        n    = len(files)
        mark = "OK " if n else "---"
        print("  [{}]  {:<40}  {} file(s)".format(mark, label, n))
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# PARSER REGISTRY & MAIN
# ═══════════════════════════════════════════════════════════════════════════════

PARSERS = [
    ("Prefetch",          parse_prefetch),
    ("BAM/DAM",           parse_bam),
    ("Amcache",           parse_amcache),
    ("UserAssist",        parse_userassist),
    ("SRUM",              parse_srum),
    ("LNK files",         parse_lnk),
    ("Shellbags",         parse_shellbags),
    ("Office MRU",        parse_office_mru),
    ("OpenSave MRU",      parse_opensave_mru),
    ("Browser History",   parse_browser_history),
    ("Event Logs",        parse_event_logs),
    ("Network Profiles",  parse_network_profiles),
    ("Recycle Bin",       parse_recycle_bin),
    ("Sticky Notes",      parse_sticky_notes),
    ("Scheduled Tasks",   parse_scheduled_tasks),
    ("Teams Log",         parse_teams_log),
    ("EventTranscript",   parse_event_transcript),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse a CyLR collection into a unified timeline CSV (AEST).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples (Windows):
  python cylr_timeline.py --input C:\Cases\HOST01 --output HOST01.csv
  python cylr_timeline.py --input C:\Cases\HOST01 --output HOST01.csv --verbose
  python cylr_timeline.py --input C:\Cases\HOST01 --output HOST01.csv ^
      --only "Prefetch,SRUM,Event Logs,Browser History"
  python cylr_timeline.py --check
  python cylr_timeline.py --input C:\Cases\HOST01 --check

Examples (Linux/macOS):
  python3 cylr_timeline.py --input /cases/HOST01 --output HOST01.csv
        """,
    )
    parser.add_argument("--input",  "-i",
                        help="Path to unzipped CyLR collection directory")
    parser.add_argument("--output", "-o",
                        help="Output CSV file path")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--check", action="store_true",
                        help="Show dependency and artifact readiness, then exit")
    parser.add_argument("--only", default="",
                        help="Comma-separated parser names to run (default: all). "
                             "Names: " + ", ".join(n for n, _ in PARSERS))
    args = parser.parse_args()

    setup_logging(args.verbose)

    # Warn about anything that couldn't be installed
    missing = [k for k, v in _dep_status.items() if not v]
    if missing:
        log.warning("Could not install: %s — affected parsers will be skipped.",
                    ", ".join(missing))

    if args.check:
        root = Path(args.input).resolve() if args.input else None
        run_check(root)
        return

    if not args.input or not args.output:
        parser.error("--input and --output are required (or use --check)")

    root = Path(args.input).resolve()
    if not root.exists():
        log.error("Input path does not exist: %s", root)
        sys.exit(1)

    log.info("Platform        : %s", platform.system())
    log.info("Collection root : %s", root)
    log.info("Output          : %s", args.output)
    log.info("Timezone        : AEST (Australia/Brisbane, UTC+10, no DST)")

    only_set = {x.strip() for x in args.only.split(",")} if args.only else set()

    all_rows: List[Dict] = []
    for name, fn in PARSERS:
        if only_set and name not in only_set:
            continue
        log.info("[%s]", name)
        try:
            result = fn(root)
            log.info("  => %d events", len(result))
            all_rows.extend(result)
        except Exception as e:
            log.error("Parser '%s' failed: %s", name, e, exc_info=args.verbose)

    log.info("Total events (pre-sort): %d", len(all_rows))
    all_rows.sort(key=lambda r: r.get("timestamp_utc", "9999"))

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # utf-8-sig = UTF-8 with BOM — opens correctly in Excel on Windows
    with open(out_path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_rows)

    log.info("Timeline written: %s  (%d rows)", out_path, len(all_rows))

    from collections import Counter
    cats = Counter(r["artifact_type"] for r in all_rows)
    log.info("── Summary by artifact type ──────────────────────────────────")
    for atype, count in sorted(cats.items(), key=lambda x: -x[1]):
        log.info("  %7d  %s", count, atype)


if __name__ == "__main__":
    main()
