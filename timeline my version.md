# Investigation Timeline
| Date and time | Activity | Evidence or observation | Assessment |
|---|---|---|---|
| October 15, 2026, 06:47:23.141 | Network event observed | `Zoho Mail - Desktop.exe`, PID `10596`, source `192.168.1.6`, destination `1.1.1.1`, port `53` | Network record observed; maliciousness not established |
| October 15, 2026, 06:47:23.179 | Network event observed | `Zoho Mail - Desktop.exe`, PID `10596`, source `192.168.1.6`, destination `169.148.149.132`, port `443` | Connection record observed; destination intent not established |
| October 15, 2026, 06:49:24.091 | Network event observed | `Zoho Mail - Desktop.exe`, PID `10596`, source `192.168.1.6`, destination `169.148.149.132`, port `443` | Additional connection record observed |
| October 16, 2026, 07:57:02.184 | Process query result | Record for `desktop-9mmm37v`; process-related fields empty in the visible row | Source and field availability require validation |
| October 16, 2026, 08:30:35.777 | Process query result | Record for `desktop-9mmm37v`; process-related fields empty in the visible row | Process attribution not established from displayed fields |
| October 16, 2026, 08:54:31.723 | Process query result | Record for `desktop-9mmm37v`; process-related fields empty in the visible row | Original document inspection required |
| October 16, 2026, approximately 10:37:57–10:38:14 | Local Sysmon event review | Recent event IDs `1`, `11`, and `22` from `Microsoft-Windows-Sysmon` | Local event generation confirmed |
| October 16, 2026, during troubleshooting | Sysmon service validation | `Sysmon64` reported as running | Local service active |
| October 16, 2026, during troubleshooting | Elastic Agent service discovery | Service reported as running with automatic startup | Agent service present |
| October 16, 2026, during troubleshooting | Elastic Agent health check | Agent reported `HEALTHY`; Fleet reported `HEALTHY — Connected` | Agent and Fleet reported healthy |
| October 16, 2026, during investigation | Baseline ES\|QL review | 47 documents processed; visible groups included missing event code, code `12`, and code `6062` | Event source and distribution require validation |
| October 16, 2026, during investigation | Network ES\|QL review | 101 documents processed; network fields visible in returned records | Network records available in queried data set |
| October 16, 2026, during investigation | Process ES\|QL review | 227 documents processed; process fields empty in visible rows | Expected process metadata not verified |

