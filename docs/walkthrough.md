# Walkthrough: BlackFrost PE Strings

## 1. Generate and Hash

Build the challenge files:

```powershell
python .\scripts\build_lab_artifacts.py
```

Hash the generated sample:

```powershell
Get-FileHash .\dist\BlackFrost_Update.exe -Algorithm SHA256
```

Record the SHA256 from `dist\SHA256SUMS.txt` or your hash command.

## 2. Open in PE Studio

Open `dist\BlackFrost_Update.exe` in PE Studio. Confirm the file has `MZ` and `PE` markers and observe the visible sections:

- `.text`
- `.rdata`
- `.data`
- `.rsrc`

The file is synthetic, but the static triage flow mirrors a real PE investigation.

## 3. Review Suspicious Strings

Use PE Studio strings view or run:

```powershell
python .\scripts\extract_strings.py .\dist\BlackFrost_Update.exe
```

Important strings include:

- `BLACKFROST_CFG_B64=...`
- `Global\BFROST-6E7A-PESTUDIO`
- `VirtualAllocEx`
- `WriteProcessMemory`
- `CreateRemoteThread`
- `RegSetValueExW`
- `CreateServiceW`
- `WinHttpSendRequest`
- `IsDebuggerPresent`
- `CheckRemoteDebuggerPresent`

These imply possible process injection, persistence, network communication, and anti-analysis behavior.

## 4. Ignore Decoys

The sample contains visible decoy flags:

- `pwndora{this_is_a_decoy_keep_going}`
- `pwndora{wrong_layer_wrong_answer}`

Reject them because the scenario asks for the final flag from the embedded configuration. The overlay and config both point to an additional decoding layer.

## 5. Decode the Configuration

Extract the value after:

```text
BLACKFROST_CFG_B64=
```

Base64-decode it. The result is compact JSON containing family, campaign, mutex, C2s, user-agent, persistence, and a field named:

```text
final_flag_xor37_b64
```

## 6. Recover the Final Flag

The config note says the final flag is:

```text
xor(0x37) over base64(flag), then base64 wrapped
```

Recovery steps:

1. Base64-decode `final_flag_xor37_b64`.
2. XOR each byte with `0x37`.
3. The result is another Base64 string.
4. Base64-decode that string.

The final flag is:

```text
pwndora{pe_studio_strings_unmask_blackfrost}
```

Validate it:

```powershell
python .\scripts\check_answer.py "pwndora{pe_studio_strings_unmask_blackfrost}"
```
