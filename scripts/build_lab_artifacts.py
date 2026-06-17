#!/usr/bin/env python3
"""
Build safe artifacts for the BlackFrost PE Strings Lab.

The generated file is an inert PE-style binary for static analysis practice.
It contains realistic strings, decoys, an encoded config, and an overlay clue,
but it is not functional malware.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
SAMPLE_NAME = "BlackFrost_Update.exe"
FLAG = "pwndora{pe_studio_strings_unmask_blackfrost}"
XOR_KEY = 0x37


def align(data: bytes, boundary: int, pad: bytes = b"\x00") -> bytes:
    remainder = len(data) % boundary
    if remainder == 0:
        return data
    return data + pad * (boundary - remainder)


def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def utf16le(text: str) -> bytes:
    return text.encode("utf-16le") + b"\x00\x00"


def make_config() -> dict[str, object]:
    flag_b64 = base64.b64encode(FLAG.encode()).decode()
    flag_xor_b64 = base64.b64encode(xor_bytes(flag_b64.encode(), XOR_KEY)).decode()
    return {
        "family": "BlackFrost",
        "campaign": "BF-2026-06",
        "mutex": "Global\\BFROST-6E7A-PESTUDIO",
        "c2": [
            "hxxps://cdn-frost-sync.example/update",
            "hxxps://api-win-telemetry.example/checkin",
        ],
        "ua": "Mozilla/5.0 BFrostUpdater/4.7",
        "install_path": "%APPDATA%\\Microsoft\\FrostCache\\bfupdater.exe",
        "task_name": "Microsoft\\Windows\\FrostCache\\UpdateTask",
        "note": "final_flag is xor(0x37) over base64(flag), then base64 wrapped",
        "final_flag_xor37_b64": flag_xor_b64,
    }


def make_pe_style_binary() -> bytes:
    dos = bytearray(b"MZ" + b"\x90" * 58)
    dos += struct.pack("<I", 0x80)
    dos = align(bytes(dos), 0x80)

    pe_header = bytearray()
    pe_header += b"PE\x00\x00"
    pe_header += struct.pack("<HHIIIHH", 0x14C, 4, 0x66714321, 0, 0, 0xE0, 0x010F)
    pe_header += struct.pack("<HBBIIIIII", 0x10B, 14, 38, 0x2200, 0x1800, 0x1000, 0x1000, 0x3000, 0x400000)
    pe_header += struct.pack("<IIHHHHHHIIIIHHIIIIII", 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x9000, 0x400, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    pe_header += b"\x00" * (16 * 8)

    sections = [
        (".text", 0x1000, 0x60000020),
        (".rdata", 0x2000, 0x40000040),
        (".data", 0x3000, 0xC0000040),
        (".rsrc", 0x4000, 0x40000040),
    ]
    raw_pointer = 0x400
    section_headers = bytearray()
    section_blobs: list[bytes] = []

    text_blob = align(
        b"\x55\x8B\xEC\x83\xEC\x18"
        b"\x68BlackFrost benign training artifact\x00"
        b"\xE8\x00\x00\x00\x00\x83\xC4\x04\x5D\xC3",
        0x200,
    )

    api_strings = "\n".join(
        [
            "LoadLibraryA",
            "GetProcAddress",
            "CreateToolhelp32Snapshot",
            "Process32FirstW",
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "RegSetValueExW",
            "CreateServiceW",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpSendRequest",
            "CryptStringToBinaryA",
            "BCryptDecrypt",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
        ]
    )
    decoys = "\n".join(
        [
            "pwndora{this_is_a_decoy_keep_going}",
            "flag=pwndora{wrong_layer_wrong_answer}",
            "debug_token=BF-LOCAL-ONLY",
            "PDB=C:\\build\\blackfrost\\Release\\updater.pdb",
            "OriginalFilename=WindowsUpdateHealth.exe",
            "CompanyName=Northbridge Energy PLC",
        ]
    )
    config_json = json.dumps(make_config(), separators=(",", ":"), sort_keys=True)
    config_b64 = base64.b64encode(config_json.encode()).decode()
    rdata_ascii = (
        "BLACKFROST_CFG_B64="
        + config_b64
        + "\n"
        + api_strings
        + "\n"
        + decoys
        + "\n"
        + "Overlay hint: seek BF_OVERLAY_V2 near EOF.\n"
    ).encode()
    rdata_blob = align(rdata_ascii + utf16le("Global\\BFROST-6E7A-PESTUDIO") + utf16le("BFROST telemetry disabled in lab"), 0x200)

    data_blob = align(
        b"\x37" * 32
        + b"xor_key=0x37\x00"
        + b"sleep_ms=45000\x00"
        + b"campaign_id=BF-2026-06\x00",
        0x200,
    )

    manifest = json.dumps(
        {
            "requestedExecutionLevel": "asInvoker",
            "description": "Synthetic updater sample for static malware analysis training",
            "warning": "No execution behavior is implemented.",
        },
        indent=2,
    )
    rsrc_blob = align(manifest.encode() + b"\x00" + utf16le("Version 4.7.19"), 0x200)

    section_blobs = [text_blob, rdata_blob, data_blob, rsrc_blob]
    for (name, virtual_address, characteristics), blob in zip(sections, section_blobs):
        name_bytes = name.encode().ljust(8, b"\x00")
        virtual_size = len(blob)
        raw_size = len(blob)
        section_headers += struct.pack(
            "<8sIIIIIIHHI",
            name_bytes,
            virtual_size,
            virtual_address,
            raw_size,
            raw_pointer,
            0,
            0,
            0,
            0,
            characteristics,
        )
        raw_pointer += raw_size

    headers = align(dos + bytes(pe_header) + bytes(section_headers), 0x400)
    overlay_payload = {
        "layer": "overlay",
        "instruction": "Decode BLACKFROST_CFG_B64, then unwrap final_flag_xor37_b64.",
        "sha256_note": "Hash the full artifact after generation for reporting.",
    }
    overlay = (
        b"\nBF_OVERLAY_V2\n"
        + base64.b64encode(json.dumps(overlay_payload, sort_keys=True).encode())
        + b"\nEND_BF_OVERLAY_V2\n"
    )
    return headers + b"".join(section_blobs) + overlay


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def make_network_log() -> str:
    hosts = [
        "workstation-03",
        "workstation-07",
        "workstation-11",
        "workstation-17",
        "workstation-22",
        "finance-laptop-04",
        "eng-build-02",
        "hr-kiosk-01",
    ]
    benign_domains = [
        "login.microsoftonline.com",
        "graph.microsoft.com",
        "teams.microsoft.com",
        "officecdn.microsoft.com",
        "windowsupdate.microsoft.com",
        "ctldl.windowsupdate.com",
        "settings-win.data.microsoft.com",
        "clients4.google.com",
        "safebrowsing.googleapis.com",
        "ocsp.digicert.com",
        "crl3.digicert.com",
        "github.com",
        "objects.githubusercontent.com",
        "slack.com",
        "zoom.us",
        "cdn.jsdelivr.net",
        "assets.adobedtm.com",
        "northbridge-energy.example",
    ]
    decoy_domains = [
        "win-health-update.example",
        "telemetry-cache.example",
        "driver-checkin.example",
        "frosted-cdn.example",
        "bf-update-mirror.example",
        "northbridge-cdn.example",
    ]
    user_agents = [
        "Microsoft-CryptoAPI/10.0",
        "Windows-Update-Agent/10.0",
        "Mozilla/5.0 Chrome/126.0",
        "Microsoft Office/16.0",
        "OneDriveSync/24.096",
        "Teams/24231.512.3010",
    ]
    lines: list[str] = []

    for i in range(240):
        hour = 8 + (i // 60)
        minute = i % 60
        second = (i * 7) % 60
        host = hosts[(i * 5 + 2) % len(hosts)]
        domain = benign_domains[(i * 7 + 3) % len(benign_domains)]
        ua = user_agents[(i * 11 + 1) % len(user_agents)]

        if i % 17 == 0:
            decoy = decoy_domains[(i // 17) % len(decoy_domains)]
            lines.append(f"2026-06-14T{hour:02d}:{minute:02d}:{second:02d}Z {host} DNS {decoy} NXDOMAIN")
        elif i % 19 == 0:
            lines.append(f"2026-06-14T{hour:02d}:{minute:02d}:{second:02d}Z {host} TLS SNI {domain} allowed ja3=72a589da586844d7f0818ce684948eea")
        elif i % 23 == 0:
            lines.append(f"2026-06-14T{hour:02d}:{minute:02d}:{second:02d}Z {host} HTTP GET hxxps://{domain}/status/204 UA \"{ua}\" status=204 bytes=0")
        else:
            lines.append(f"2026-06-14T{hour:02d}:{minute:02d}:{second:02d}Z {host} DNS {domain} A ttl={120 + (i % 50)}")

    true_events = [
        '2026-06-14T09:12:41Z workstation-17 DNS cdn-frost-sync.example NXDOMAIN process=BlackFrost_Update.exe pid=4824',
        '2026-06-14T09:12:42Z workstation-17 TLS SNI api-win-telemetry.example blocked ja3=6734f37431670b3ab4292b8f60f29984',
        '2026-06-14T09:13:03Z workstation-17 HTTP POST hxxps://api-win-telemetry.example/checkin UA "Mozilla/5.0 BFrostUpdater/4.7" status=blocked bytes_out=512',
        '2026-06-14T09:13:08Z workstation-17 HTTP GET hxxps://cdn-frost-sync.example/update UA "Mozilla/5.0 BFrostUpdater/4.7" status=blocked bytes_in=0',
        '2026-06-14T09:14:11Z workstation-17 DNS cdn-frost-sync.example NXDOMAIN process=svchost.exe note=parent_name_mismatch',
        '2026-06-14T09:16:29Z workstation-17 EDR netblock category=malware-sim domain=api-win-telemetry.example sample=BlackFrost_Update.exe',
    ]
    insert_at = [73, 96, 117, 138, 169, 211]
    for offset, event in zip(insert_at, true_events):
        lines.insert(offset, event)

    return "\n".join(lines) + "\n"


def make_memory_strings() -> str:
    noise = [
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\System32\\RuntimeBroker.exe",
        "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        "Global\\CLR_PerfMon_v4.0.30319_32",
        "Global\\SessionEnvReadyEvent",
        "Local\\FontCachePort",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
        "Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
        "Microsoft\\Windows\\Windows Defender\\Cache Maintenance",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "https://graph.microsoft.com/v1.0/me/messages",
        "https://settings-win.data.microsoft.com/settings/v3.0",
        "Mozilla/5.0 Chrome/126.0",
        "Windows-Update-Agent/10.0",
        "pwndora{memory_dump_decoy_not_final}",
        "flag_candidate=pwndora{volatile_false_positive}",
        "BF-LOCAL-ONLY",
        "FrostCache.tmp",
        "frosted-cdn.example",
        "win-health-update.example",
        "api-health-telemetry.example",
        "CryptUnprotectData",
        "CreateFileW",
        "ReadFile",
        "WriteFile",
        "CloseHandle",
        "GetTickCount64",
        "QueryPerformanceCounter",
    ]
    lines: list[str] = []

    for i in range(420):
        value = noise[(i * 9 + 4) % len(noise)]
        address = 0x10000000 + (i * 0x130)
        region = ["heap", "stack", "mapped", "private"][(i * 3) % 4]
        pid = [640, 884, 1332, 2204, 4824, 5100][(i * 5) % 6]
        lines.append(f"0x{address:08x} pid={pid:<5} region={region:<7} {value}")

    true_strings = [
        "0x1004bf10 pid=4824  region=mapped  BLACKFROST_CFG_B64 appears in mapped .rdata",
        "0x1004c020 pid=4824  region=heap    Global\\BFROST-6E7A-PESTUDIO",
        "0x1004c0d0 pid=4824  region=heap    Microsoft\\Windows\\FrostCache\\UpdateTask",
        "0x1004c190 pid=4824  region=private BFROST telemetry disabled in lab",
        "0x1004c250 pid=4824  region=private final layer requires xor key 0x37",
        "0x1004c310 pid=4824  region=heap    Mozilla/5.0 BFrostUpdater/4.7",
        "0x1004c3d0 pid=4824  region=heap    hxxps://api-win-telemetry.example/checkin",
        "0x1004c490 pid=4824  region=heap    hxxps://cdn-frost-sync.example/update",
    ]
    insert_at = [58, 119, 166, 214, 277, 313, 356, 402]
    for offset, value in zip(insert_at, true_strings):
        lines.insert(offset, value)

    return "\n".join(lines) + "\n"


def main() -> None:
    DIST.mkdir(exist_ok=True)
    sample = make_pe_style_binary()
    sample_path = DIST / SAMPLE_NAME
    sample_path.write_bytes(sample)

    sha256 = hashlib.sha256(sample).hexdigest()
    write_text(DIST / "SHA256SUMS.txt", f"{sha256}  {SAMPLE_NAME}\n")
    write_text(DIST / "network.log", make_network_log())
    write_text(
        DIST / "README_FIRST.txt",
        """BlackFrost PE Strings Lab

Analyze BlackFrost_Update.exe statically. Do not execute it.
Recommended tools: PE Studio, strings, CyberChef, Python, hash utilities.
Supporting telemetry is intentionally noisy. Correlate logs, strings, and PE clues.
Deliverables: family, mutex, suspicious APIs, C2s, persistence clue, decoded config, final flag.
""",
    )
    write_text(DIST / "memory_strings.txt", make_memory_strings())
    print(f"Wrote {sample_path}")
    print(f"SHA256 {sha256}")


if __name__ == "__main__":
    main()
