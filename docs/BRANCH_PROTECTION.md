# Branch Protection Setup

After creating the repo, enable branch protection:

1. Go to https://github.com/Joel-Claw/agent-messenger/settings/branches
2. Add rule for `main`:
   - ☑ Require a pull request before merging
     - ☑ Require approvals (1)
     - ☑ Dismiss stale pull request approvals when new commits are pushed
     - ☑ Require review from Code Owners
   - ☑ Require status checks to pass before merging
   - ☑ Require branches to be up to date before merging
   - ☑ Do not allow bypassing the above settings

This ensures:
- No direct pushes to main
- All changes via PR only
- At least one approval required
- CODEOWNERS must review
- Malicious code cannot be sneaked in

## Why This Matters

This is a security-critical project. Agent Messenger handles:
- Authentication credentials
- Private messages
- Self-hosted infrastructure

A compromised dependency or malicious PR could:
- Steal API keys
- Read private conversations
- Compromise user servers

The review process prevents this.