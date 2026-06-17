# Answers: BlackFrost PE Strings

1. The SHA256 is generated per build and written to `dist\SHA256SUMS.txt`.
2. Yes. It has `MZ` and `PE` markers. Visible sections are `.text`, `.rdata`, `.data`, and `.rsrc`.
3. Suspicious APIs include `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `RegSetValueExW`, `CreateServiceW`, `WinHttpSendRequest`, `IsDebuggerPresent`, and `CheckRemoteDebuggerPresent`.
4. Injection: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`. Persistence: `RegSetValueExW`, `CreateServiceW`, scheduled-task path. Network: `WinHttpOpen`, `WinHttpConnect`, `WinHttpSendRequest`. Anti-analysis: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`.
5. Family or campaign: `BlackFrost`, campaign `BF-2026-06`.
6. Mutex: `Global\BFROST-6E7A-PESTUDIO`.
7. C2 endpoints: `hxxps://cdn-frost-sync.example/update` and `hxxps://api-win-telemetry.example/checkin`.
8. Persistence clue: `Microsoft\Windows\FrostCache\UpdateTask`.
9. Decoys: `pwndora{this_is_a_decoy_keep_going}` and `pwndora{wrong_layer_wrong_answer}`. They are rejected because the config and overlay indicate another layer.
10. Encoded config marker: `BLACKFROST_CFG_B64=`.
11. Decode `BLACKFROST_CFG_B64`, then Base64-decode `final_flag_xor37_b64`, XOR with `0x37`, then Base64-decode the resulting text.
12. Final flag: `pwndora{pe_studio_strings_unmask_blackfrost}`.
