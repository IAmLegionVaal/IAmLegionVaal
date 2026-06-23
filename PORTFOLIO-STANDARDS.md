# Portfolio Documentation Standard

Completed Windows lab repositories in this portfolio are documented using the following standard.

## Required project evidence

1. The project is clearly marked as completed.
2. The original objective and implemented configuration are described.
3. Validation steps and final outcomes are included.
4. Findings from the completed work are documented.
5. Faults or unexpected results encountered during the lab are identified.
6. Repairs or remediation performed are documented where applicable.
7. The repaired configuration is validated again after the change.
8. Security, privacy and rollback or recovery considerations are included where relevant.
9. Sensitive credentials, names, addresses and private environment details are excluded.
10. A README only describes features or repair actions that genuinely exist in the repository or were genuinely performed in the completed lab.

## Repair-capable repository standard

Where a repository includes an automated repair file, it must:

- Be a real functional PowerShell file rather than documentation-only content
- Run directly with parameters and no menu
- Include logging and error handling
- Include confirmation or `-WhatIf` support where changes may be disruptive
- Create a backup before changing recoverable configuration where practical
- Perform post-repair validation
- Return meaningful exit codes
- Clearly separate detection, automatic repair and manual action

## Completed-state wording

**This was tested by me to be working. User experience may vary.**

This standard distinguishes completed lab evidence from planned work, read-only diagnostics and repair-capable automation.
