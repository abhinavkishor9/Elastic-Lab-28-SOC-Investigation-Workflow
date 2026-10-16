# Troubleshooting Notes

## 1. Initial Baseline Findings

### Query

```esql
FROM logs-*
| STATS event_count = COUNT(*) BY host.name, event.code
| SORT event_count DESC
| LIMIT 50
```

### Observation

The captured results reported 47 documents processed. Visible groups included:

- 24 records without a displayed event code.
- 3 records with event code `12`.
- 2 records with event code `6062`.

The screenshot showed 18 results, so the displayed groups were not exhaustive.

### Assessment

The query returned records, but the event-code distribution did not establish that the records were Sysmon events.

**Next step:** inspect the original document and its provider and dataset fields.

## 2. Process Field Visibility

### Query

```esql
FROM logs-*
| WHERE event.code == "1"
| KEEP @timestamp, host.name, user.name,
       process.name, process.executable,
       process.command_line, process.pid
| SORT @timestamp DESC
| LIMIT 50
```

### Observation

The query processed 227 documents. The visible rows contained timestamps and the host name, while the selected user and process fields were empty.

### Assessment

The results were insufficient to determine whether the records represented Sysmon process creation events with missing metadata.

Possible explanations include:

- The records originated from a different event provider or dataset.
- The fields were absent from the original documents.
- The selected fields were not populated for those records.
- The query matched event code `1` from a source other than the expected Sysmon stream.

These possibilities remain unverified.

### Next Step

Inspect a complete document and establish its source before investigating field mappings or changing collection configuration.

## 3. Network Event Review

### Query

```esql
FROM logs-*
| WHERE event.code == "3"
| KEEP @timestamp, host.name, process.name,
       process.pid, source.ip,
       destination.ip, destination.port
| SORT @timestamp DESC
| LIMIT 50
```

### Observation

The query processed 101 documents. The visible results included network records attributed to `Zoho Mail - Desktop.exe`.

The observed destinations included `169.148.149.132:443` and `1.1.1.1:53`.

### Assessment

The results show that some queried records contained process and network fields. They do not establish malicious activity or prove that the process and network queries returned the same telemetry source.

### Next Step

Inspect the provider and dataset of the network records, then compare the timestamps and source details before attempting event correlation.

## 4. Local Sysmon Validation

### Service Command

```powershell
Get-Service Sysmon64
```

**Result:** The service was running.

### Event Log Command

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10 |
    Select-Object TimeCreated, Id, ProviderName |
    Format-Table -AutoSize
```

### Result

Recent local Sysmon events were present, including event IDs `1`, `11`, and `22`.

### Assessment

The local Windows event log confirms Sysmon activity at the time of the check.

It does not prove successful collection or indexing by Elastic Agent.

**Next step:** select one recent local event and search for a corresponding indexed record using its timestamp and available identifying details.

## 5. Elastic Agent Command Lookup

### Initial Issue

The command below was not recognized by PowerShell.

```powershell
elastic-agent status
```

`Get-Command elastic-agent` also returned no executable path.

### Assessment

The executable was not available through the current PowerShell command lookup. This did not establish that Elastic Agent was missing because its Windows service was running.

### Service Registration Check

```powershell
Get-CimInstance Win32_Service -Filter "Name='Elastic Agent'" |
    Select-Object Name, State, StartMode, PathName |
    Format-List
```

### Result

The service registration showed:

- Name: `Elastic Agent`.
- State: `Running`.
- Startup mode: `Auto`.
- Executable path: `C:\Program Files\Elastic\Agent\elastic-agent.exe`.

### Resolution

The executable was located through the Windows service registration. Using the full path allowed the agent status command to be executed without relying on PowerShell command lookup.

No reinstallation or re-enrollment was necessary for this check.

## 6. Elastic Agent and Fleet Health

### Command

```powershell
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status
```

### Result

```text
fleet
  status: (HEALTHY) Connected
elastic-agent
  status: (HEALTHY) Running
```

### Assessment

Elastic Agent reported a healthy running state and a healthy Fleet connection.

This reduces concern about a completely stopped agent or a reported Fleet disconnection at the time of the check. It does not prove that the Sysmon integration is configured correctly or that all expected events are being indexed.

## 7. Current Diagnostic Status

| Layer | Status | Remaining question |
|---|---|---|
| Sysmon service | Running | Are relevant local events being collected? |
| Local Sysmon log | Recent events present | Can individual events be matched to indexed records? |
| Elastic Agent service | Running | Is the relevant integration operating as expected? |
| Fleet connection | Healthy and connected | Is the policy and integration configuration correct? |
| Elasticsearch queries | Records returned | Which provider and dataset produced each record? |
| Process fields | Incomplete in visible rows | Are the fields absent from the source documents? |
| End-to-end Sysmon ingestion | Unverified | Can local and indexed events be reconciled? |

