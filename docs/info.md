# Lab Info: BlackFrost PE Strings

## Difficulty

Hard

## Theme

Static malware triage of a suspicious Windows PE-style updater using PE Studio, strings, hashes, and manual decoding.

## Safety

The supplied artifact is synthetic and inert. It is designed to look useful in PE Studio and string extraction tools, but it does not perform malicious actions. Players should still follow normal malware-lab discipline and avoid executing unknown binaries.

## Learning Objectives

- Triage PE metadata, sections, imports, and suspicious strings.
- Separate decoy flags from meaningful encoded configuration.
- Extract ASCII and UTF-16LE strings.
- Identify likely capabilities from API names.
- Recover C2, mutex, persistence clue, campaign ID, and final flag from encoded data.
- Document IOCs with confidence and uncertainty.

## Recommended Tools

- PE Studio
- FLOSS or Sysinternals Strings
- CyberChef
- Python 3
- SHA256 hashing utility
- Optional: Detect It Easy, PE-bear, x64dbg for non-execution inspection only

## Build the Lab Artifacts

Run from the repository root:

```powershell
python .\scripts\build_lab_artifacts.py
```

The challenge bundle is created in `dist\`.

## Player Deliverables

Players should submit:

- SHA256 of `BlackFrost_Update.exe`
- Relevant evidence from `network.log`
- Relevant evidence from `memory_strings.txt`
- Malware family or campaign name
- At least two suspicious APIs and their likely purpose
- Mutex
- C2 endpoints
- Persistence clue
- Decoded configuration
- Final flag in `pwndora{}` format
