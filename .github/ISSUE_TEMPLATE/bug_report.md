---
name: Bug Report
about: Create a report to help us improve MASARE
title: '[BUG] '
labels: bug
assignees: ''
---

## Bug Description

A clear and concise description of what the bug is.

## Steps to Reproduce

1. Go to '...'
2. Click on '....'
3. Run command '....'
4. See error

## Expected Behavior

A clear description of what you expected to happen.

## Actual Behavior

What actually happened instead.

## Environment

**Host System:**
- OS: [e.g. Ubuntu 22.04, macOS 14.0, Windows 11]
- Python Version: [e.g. 3.11.4]
- VirtualBox/UTM Version: [e.g. 7.0.10]

**Virtual Machines:**
- REMnux Version: [e.g. 7.0]
- FLARE VM Version: [if applicable]
- Network Mode: [e.g. Host-Only]

**MASARE Version:**
- Version/Commit: [e.g. 1.0.0 or commit hash]

## Error Messages

```
Paste any error messages, stack traces, or logs here
```

## Screenshots

If applicable, add screenshots to help explain your problem.

## Logs

<details>
<summary>Cuckoo Logs</summary>

```
Paste ~/.cuckoo/log/cuckoo.log here
```
</details>

<details>
<summary>Orchestrator Logs</summary>

```
Paste /shared/logs/orchestrator.log here
```
</details>

## Isolation Test Results

Did you run `./tests/test_isolation.sh`?
- [ ] Yes - All tests passed
- [ ] Yes - Some tests failed (specify which)
- [ ] No - Haven't run it yet

## Additional Context

Add any other context about the problem here.

## Possible Solution

If you have suggestions on how to fix this bug, please describe them here.

## Related Issues

Link to related issues if any: #

---

**Checklist before submitting:**
- [ ] I have searched existing issues to avoid duplicates
- [ ] I have provided all required environment information
- [ ] I have included error messages and logs
- [ ] I have run the isolation test
- [ ] I have tried basic troubleshooting (restart VMs, check network, etc.)
