```yml
title: DCSync via Replication Rights by Non-Machine Account
id: 1a2b3c4d-avantech-2026
status: stable
description: Non-DC, non-service account invokes DS-Replication-Get-Changes(-All).
author: AVANTech CDC
logsource: { product: windows, service: security }
detection:
  selection:
    EventID: 4662
    AccessMask: '0x100'
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes-All
      - '89e95b76-444d-4c62-991a-0facbeda640c'   # DS-Replication-Get-Changes-In-Filtered-Set
  filter_machines: { SubjectUserName|endswith: '$' }
  filter_msol:     { SubjectUserName|startswith: 'MSOL_' }
  condition: selection and not (filter_machines or filter_msol)
level: high
tags: [attack.credential_access, attack.t1003.006, stp.score.6]
```