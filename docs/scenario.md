# Scenario: BlackFrost Intrusion Triage

Northbridge Energy's helpdesk received reports of a fake updater prompt on one workstation. EDR blocked outbound traffic but preserved a suspicious file named `BlackFrost_Update.exe`. The SOC also exported noisy network telemetry and recovered memory strings from several hosts, most of which are unrelated daily activity. Your job is to perform static triage, correlate the useful evidence, and recover the operator's embedded configuration.

Do not execute the sample. Treat the binary as hostile and work from static artifacts only.

## Questions

1. What is the SHA256 hash of the sample?
2. Does the file identify as a PE-style executable, and what sections are visible?
3. What suspicious API names appear in the strings or PE Studio indicators?
4. Which strings suggest anti-analysis, process injection, registry, service, or HTTP behavior?
5. What is the apparent malware family or campaign name?
6. What mutex is embedded in the sample?
7. What C2 endpoints are embedded in the decoded configuration?
8. Which string suggests scheduled-task persistence?
9. What decoy flags are present, and why should they be rejected?
10. What encoded configuration marker should be extracted from `.rdata`?
11. After decoding the configuration, what additional transformation is required for the final flag?
12. What is the final flag?

## Hints

- PE Studio should make section names and interesting strings easy to browse.
- Extract both ASCII and UTF-16LE strings.
- Treat `network.log` and `memory_strings.txt` as noisy evidence. Correlate hostnames, process names, user agents, domains, and timestamps.
- The real flag is not the first `pwndora{}` string you see.
- Look for a named configuration marker, then decode in layers.
- The overlay near EOF is a clue, not the main payload.
