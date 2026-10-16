# Investigation Notes 
## 1. Baseline Event Review

### Query

```esql
FROM logs-*
| STATS event_count = COUNT(*) BY host.name, event.code
| SORT event_count DESC
| LIMIT 50
```

### Observations

The captured query reported 47 documents processed.

| Event code | Count shown | Observation |
|---|---:|---|
| Missing or null | 24 | No event code was displayed |
| `12` | 3 | Records grouped under event code 12 |
| `6062` | 2 | Records grouped under event code 6062 |

The screenshot indicated 18 results, so the groups above are not a complete listing.

### Assessment

The query returned records associated with `desktop-9mmm37v`. However, the displayed event codes do not independently establish the source of the records.

The provider, dataset, module, and original document fields must be inspected before identifying these records as Sysmon telemetry.

## 2. Process Creation Investigation

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

### Observations

The captured query processed 227 documents.

The visible records included:

- Host: `desktop-9mmm37v`.
- October 16, 2026 timestamps.
- Empty values in the displayed user and process fields.

Visible timestamps included:

- October 16, 2026, at 08:54:31.723.
- October 16, 2026, at 08:30:35.777.
- October 16, 2026, at 07:57:02.184.

### Assessment

The query matched records with event code `1`, but the displayed fields were insufficient to verify that these records contained the expected process creation details.

Potential explanations include differences in event source, dataset, document contents, or field population. None of these explanations has been confirmed.

### Follow-up

Inspect the original records and check `event.provider`, `event.dataset`, `event.module`, and the available process fields.

## 3. Network Connection Investigation

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

### Observations

The captured query processed 101 documents.

| Timestamp | Process | PID | Source IP | Destination IP | Destination port |
|---|---|---:|---|---|---:|
| October 15, 2026, 06:49:24.091 | `Zoho Mail - Desktop.exe` | 10596 | `192.168.1.6` | `169.148.149.132` | 443 |
| October 15, 2026, 06:47:23.179 | `Zoho Mail - Desktop.exe` | 10596 | `192.168.1.6` | `169.148.149.132` | 443 |
| October 15, 2026, 06:47:23.141 | `Zoho Mail - Desktop.exe` | 10596 | `192.168.1.6` | `1.1.1.1` | 53 |

### Assessment

The records show network activity attributed to the named application, including traffic to ports `443` and `53`.

These observations do not independently establish malicious behavior. Additional application context, destination validation, and surrounding telemetry would be required to assess whether the connections were expected.

The network records were observed on October 15, while the local Sysmon events were checked on October 16. They have not been proven to be directly correlated.

## 4. Local Sysmon Validation

### Service Check

```powershell
Get-Service Sysmon64
```

**Result:** The service was reported as running.

### Event Log Check

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10 |
    Select-Object TimeCreated, Id, ProviderName |
    Format-Table -AutoSize
```

### Observations

Recent local events were present in the Sysmon Operational log.

| Event ID | Category | Observation |
|---|---|---|
| `1` | Process creation | Present |
| `11` | File creation | Present |
| `22` | DNS query | Present |

The displayed timestamps ranged from October 16, 2026, at approximately 10:37:57 to 10:38:14.

### Assessment

The local event log confirms that Sysmon was generating these event categories at the time of the check.

It does not prove that every event was collected, forwarded, or indexed by Elastic.

## 5. Elastic Agent and Fleet Validation

### Service Registration

```powershell
Get-CimInstance Win32_Service -Filter "Name='Elastic Agent'" |
    Select-Object Name, State, StartMode, PathName |
    Format-List
```

### Observations

- Service name: `Elastic Agent`.
- State: `Running`.
- Startup mode: `Auto`.
- Executable: `C:\Program Files\Elastic\Agent\elastic-agent.exe`.

### Agent Status

```powershell
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status
```

The command reported:

```text
fleet
  status: (HEALTHY) Connected
elastic-agent
  status: (HEALTHY) Running
```

### Assessment

Elastic Agent reported a healthy running state and a healthy Fleet connection.

This does not independently verify the Sysmon integration configuration or prove successful indexing of every expected event.

## 6. Evidence Assessment

| Finding | Status | Assessment |
|---|---|---|
| Sysmon service running | Confirmed | Local service is active |
| Local Sysmon events present | Confirmed | Event IDs 1, 11, and 22 were observed |
| Elastic Agent running | Confirmed | Windows service reports Running |
| Fleet connection healthy | Confirmed | Agent reports Healthy and Connected |
| Network records available | Confirmed | Network fields were returned |
| Process fields consistently populated | Not confirmed | Several displayed fields were empty |
| All expected Sysmon events indexed | Not confirmed | Local and indexed telemetry have not been reconciled |
| Malicious activity occurred | Not established | No confirmed malicious behavior demonstrated |

