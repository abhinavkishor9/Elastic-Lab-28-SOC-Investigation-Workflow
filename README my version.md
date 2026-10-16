# Elastic-Lab-28-SOC-Investigation-Workflow
## Overview
A SOC analyst does not simply run queries and look at suspicious events. The analyst follows a repeatable workflow to decide whether an observation represents a security concern, what evidence supports that assessment, and what should happen next.1

1. Validate

Is the alert or event present, and is its data usable?

2. Triage

What happened, where, when, and which account or process is involved?

3. Investigate

What related evidence supports or contradicts the initial concern?

4. Assess

What is the severity, confidence, scope, and business impact?

5. Decide

Escalate, continue investigating, or close with a justified disposition.

6. Document

Record evidence, queries, limitations, decisions, and follow-up actions.


This lab follows a structured Security Operations Center (SOC) investigation workflow using Elastic Security, ES|QL, Windows Sysmon, and Elastic Agent.

The investigation focuses on establishing an event baseline, reviewing process and network telemetry, validating local endpoint activity, checking agent health, and troubleshooting inconsistent field visibility in Kibana.

The goal is to distinguish confirmed observations from assumptions and determine what additional evidence is needed before reaching a security conclusion.

## Lab Objectives

- Establish a baseline of available endpoint telemetry using ES|QL and identify the distribution of events by host and event code.
- Investigate process creation records and evaluate the availability of process names, executable paths, command lines, process IDs, and user information.
- Examine network connection records to identify associated processes, source and destination IP addresses, and destination ports.
- Validate local Windows Sysmon activity by inspecting the service status and recent events in the Sysmon Operational log.
- Verify Elastic Agent service health and Fleet connectivity using the installed agent executable.
- Investigate discrepancies between locally generated Sysmon events and records returned by Elasticsearch queries.
- Assess whether missing process fields result from incomplete source documents, differences in event providers or datasets, or other unresolved collection and ingestion issues.
- Apply a structured troubleshooting process that prioritizes read-only checks before making configuration changes.
- Correlate endpoint evidence using timestamps and available event attributes without assuming that separate records belong to the same activity.
- Distinguish confirmed observations from hypotheses, document investigation limitations, and identify the next steps required to validate telemetry ingestion.
- Produce an evidence-based investigation assessment without classifying activity as malicious unless the available evidence supports that conclusion.

## Lab Scenario

You are working as a Tier 1 SOC Analyst responsible for validating endpoint telemetry and investigating Windows activity in Elastic Security. During a routine review, you notice that ES|QL queries return process and network records, but some expected process fields appear empty. At the same time, Windows Sysmon is running locally, and recent events are visible in the Sysmon Operational log.

Your task is to determine whether the endpoint is generating telemetry, whether Elastic Agent is operating correctly, and whether the available Elasticsearch records contain sufficient information for a reliable investigation.

### Investigation Objectives

- Establish a baseline of available events using ES|QL and identify the event codes and hosts represented in the results.
- Examine process creation records for fields such as `process.name`, `process.executable`, `process.command_line`, and `process.pid`.
- Review network connection records and identify the available source IP, destination IP, destination port, and associated process information.
- Validate local Sysmon activity and check the Elastic Agent service and Fleet connection status.
- Investigate the discrepancy between locally generated Sysmon events and the records returned by Elasticsearch.

### Investigation Approach

Begin with read-only checks to understand the current state of the endpoint and its telemetry pipeline. Use ES|QL to inspect indexed records, then compare the results with recent events available on the Windows host. Check the original event metadata, including provider, dataset, module, and event code, before assuming that the returned records originate from Sysmon.

If expected fields are missing, investigate the available evidence before changing configurations or reinstalling components. A running Sysmon service and a healthy Elastic Agent connection are useful indicators, but neither independently proves that all expected events are being collected and indexed correctly.

### Expected Outcome

At the end of the lab, produce an evidence-based assessment of the endpoint's telemetry status. Document which checks succeeded, which fields or records remain inconsistent, and what additional validation is required.

The final report should clearly distinguish confirmed observations from possible explanations. Do not classify the activity as malicious merely because telemetry is incomplete or unexpected. The primary goal is to validate the investigation workflow, identify visibility gaps, and determine the next steps needed to establish reliable endpoint monitoring.

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

