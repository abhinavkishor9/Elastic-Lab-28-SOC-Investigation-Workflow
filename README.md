# Lab 28 — Elastic Security SOC Investigation Workflow

## Overview

This lab follows a structured Security Operations Center (SOC) investigation workflow using Elastic Security, ES|QL, Windows Sysmon, and Elastic Agent.

The investigation focuses on establishing an event baseline, reviewing process and network telemetry, validating local endpoint activity, checking agent health, and troubleshooting inconsistent field visibility in Kibana.

The goal is to distinguish confirmed observations from assumptions and determine what additional evidence is needed before reaching a security conclusion.

## Objectives

- Establish a baseline of available records using ES|QL.
- Review process creation events using event code `1`.
- Examine network connection events using event code `3`.
- Inspect host, process, user, IP address, and destination port fields.
- Verify local Sysmon event generation.
- Validate Elastic Agent service status and Fleet connectivity.
- Investigate unexpected event-code distributions and missing process fields.
- Document evidence, limitations, and unresolved questions.

## Lab Environment

| Component | Details |
|---|---|
| Endpoint | `desktop-9mmm37v` |
| Operating system | Windows 11 |
| Investigation platform | Elastic Security / Kibana |
| Query language | ES|QL |
| Data source | `logs-*` |
| Endpoint telemetry | Windows Sysmon |
| Collection agent | Elastic Agent |
| Agent service | Running |
| Fleet connection | Healthy and connected |
| Investigation type | Endpoint telemetry validation |

## Investigation Workflow

### Step 1 — Establish an Event Baseline

The following query was used to review event counts by host and event code.

```esql
FROM logs-*
| STATS event_count = COUNT(*) BY host.name, event.code
| SORT event_count DESC
| LIMIT 50
```

The captured results reported 47 documents processed. Visible groups included 24 records without a displayed event code, 3 records with event code `12`, and 2 records with event code `6062`.

The screenshot indicated additional results, so these groups do not represent the complete distribution.

The result established that records were available in the queried data set. It did not establish that all records originated from Sysmon.

### Step 2 — Review Process Creation Events

The following query examined records matching event code `1`.

```esql
FROM logs-*
| WHERE event.code == "1"
| KEEP @timestamp, host.name, user.name,
       process.name, process.executable,
       process.command_line, process.pid
| SORT @timestamp DESC
| LIMIT 50
```

The captured query processed 227 documents. The displayed rows included timestamps and the endpoint name, but the selected user and process fields were empty.

This result requires further investigation. The available evidence does not establish whether the selected records originated from Sysmon or why the process fields were empty.

### Step 3 — Review Network Connection Events

The following query examined records matching event code `3`.

```esql
FROM logs-*
| WHERE event.code == "3"
| KEEP @timestamp, host.name, process.name,
       process.pid, source.ip,
       destination.ip, destination.port
| SORT @timestamp DESC
| LIMIT 50
```

The captured query processed 101 documents. The visible results included network records attributed to `Zoho Mail - Desktop.exe`, process ID `10596`.

Observed destinations included:

- `169.148.149.132` on port `443`.
- `1.1.1.1` on port `53`.

These records demonstrate that network-related telemetry was available in the queried data set. They do not independently establish malicious activity.

### Step 4 — Validate Local Sysmon Activity

The Sysmon service was checked using PowerShell.

```powershell
Get-Service Sysmon64
```

The service was reported as running.

The local Sysmon Operational log was then inspected.

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10 |
    Select-Object TimeCreated, Id, ProviderName |
    Format-Table -AutoSize
```

Recent local events included event IDs `1`, `11`, and `22`, corresponding to process creation, file creation, and DNS query event categories.

This confirms that these event types were being generated locally at the time of the check. It does not establish that every event was successfully collected and indexed by Elastic.

### Step 5 — Validate Elastic Agent and Fleet

The Windows service registration was inspected.

```powershell
Get-CimInstance Win32_Service -Filter "Name='Elastic Agent'" |
    Select-Object Name, State, StartMode, PathName |
    Format-List
```

The service was running with automatic startup. The executable path was:

`C:\Program Files\Elastic\Agent\elastic-agent.exe`

The agent status was checked using the full executable path.

```powershell
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status
```

The reported status was:

- Fleet: `HEALTHY` — Connected.
- Elastic Agent: `HEALTHY` — Running.

This confirms the reported service and Fleet connection state. It does not independently confirm that the Sysmon integration is collecting and indexing all expected events.

## Key Findings

- Sysmon was running and generating recent local events.
- Elastic Agent was running and reported a healthy Fleet connection.
- ES|QL queries returned records associated with `desktop-9mmm37v`.
- The process creation query displayed rows with empty process-related fields.
- The network query returned records with process and destination details.
- The baseline query displayed several event-code groups, including records without a visible event code.
- Complete Sysmon ingestion into Elasticsearch was not verified.

## Investigation Conclusion

The investigation confirmed local Sysmon event generation and a healthy reported Elastic Agent/Fleet state. However, the available evidence did not fully reconcile local Sysmon events with the records and fields displayed in Kibana.

The investigation remains a telemetry validation and troubleshooting exercise. No security incident was confirmed by the evidence collected in this lab.

## Evidence Handling

- Preserve screenshots and original query results.
- Record the time range used for each query.
- Distinguish local Windows events from indexed Elasticsearch records.
- Do not treat missing fields as proof of malicious activity.
- Do not classify an IP address or network connection as malicious without supporting evidence.
- Record unverified conclusions as unresolved.

## Final Status

**Investigation status:** Telemetry validation in progress.

**Confirmed security incident:** No.

**Local Sysmon event generation:** Confirmed.

**Elastic Agent and Fleet reported health:** Confirmed.

**Complete Sysmon ingestion:** Not yet verified.
