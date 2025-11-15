# Pull Request

## Description

<!-- Provide a brief description of the changes in this PR -->

## Type of Change

<!-- Check all that apply -->

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Code refactoring
- [ ] Performance improvement
- [ ] Test addition/modification

## Related Issue

<!-- Link to the issue this PR addresses -->
Fixes #(issue number)

## Motivation and Context

<!-- Why is this change needed? What problem does it solve? -->

## Changes Made

<!-- List the main changes in bullet points -->

-
-
-

## Testing Performed

<!-- Describe the tests you ran to verify your changes -->

### Manual Testing

- [ ] Tested on Linux (specify distribution:_______)
- [ ] Tested on macOS (specify version:_______)
- [ ] Tested on Windows (specify version:_______)

### Automated Testing

```bash
# Commands used for testing
./scripts/check_system.sh
pytest tests/
```

**Test Results:**
```
Paste test output here
```

### Network Isolation Testing

- [ ] Ran `./tests/test_isolation.sh` - All tests passed
- [ ] Verified no internet access from analysis VMs
- [ ] Tested with actual malware sample (EICAR or similar)

## Screenshots/Output

<!-- If applicable, add screenshots or command output -->

**Before:**
```
Output before changes
```

**After:**
```
Output after changes
```

## Checklist

<!-- Check all that apply -->

### Code Quality
- [ ] My code follows the project's code style (PEP 8 for Python)
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have added docstrings to new functions/classes
- [ ] I have removed debug/print statements

### Testing
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] I have run the isolation test and verified it passes

### Documentation
- [ ] I have updated the README.md (if applicable)
- [ ] I have updated relevant documentation in `docs/` (if applicable)
- [ ] I have added comments to difficult sections of code
- [ ] I have updated CHANGELOG.md with my changes

### Security
- [ ] I have not committed malware samples (encrypted or otherwise)
- [ ] I have not included hardcoded credentials or API keys
- [ ] I have validated all user inputs
- [ ] I have considered security implications of my changes
- [ ] I have followed the security guidelines in SECURITY.md

### Dependencies
- [ ] I have updated requirements.txt (if I added dependencies)
- [ ] All new dependencies are justified and documented
- [ ] I have verified licenses of new dependencies are compatible

## Breaking Changes

<!-- If this PR introduces breaking changes, describe them here -->

- [ ] This PR does NOT introduce breaking changes

**OR**

This PR introduces the following breaking changes:
-
-

**Migration Guide:**
```
Steps for users to migrate from old to new behavior
```

## Performance Impact

<!-- Describe any performance impact (positive or negative) -->

- [ ] No performance impact
- [ ] Performance improved: [describe]
- [ ] Performance degraded: [describe and justify]

**Benchmarks** (if applicable):
```
Before: X seconds
After: Y seconds
```

## Additional Notes

<!-- Any additional information reviewers should know -->

## Reviewer Focus Areas

<!-- Guide reviewers on what to focus on -->

Please pay special attention to:
-
-

## Post-Merge Tasks

<!-- Tasks to complete after merging -->

- [ ] Update documentation website (if applicable)
- [ ] Announce in Discussions
- [ ] Update related issues
- [ ] None required

---

**By submitting this PR, I confirm that:**
- [ ] I have read and agree to the [Code of Conduct](../CODE_OF_CONDUCT.md)
- [ ] I have read the [Contributing Guidelines](../CONTRIBUTING.md)
- [ ] My contribution is my own work and I have the right to license it under MIT
- [ ] I understand this code will be used for security research purposes only
