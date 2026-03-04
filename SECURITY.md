# Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues through one of these channels:

### 1. GitHub Security Advisories (Preferred)
Visit: https://github.com/sparn-labs/cortex/security/advisories/new

### 2. Email
Send details to: ulrichc1.dev@gmail.com

### What to Include
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline
- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Patch Release**: Within 14 days (for confirmed vulnerabilities)

### What Happens Next
If the vulnerability is confirmed, we will:
1. Acknowledge the report
2. Develop and test a fix
3. Release a security patch
4. Publish an npm security advisory
5. Credit you in the release notes (unless you prefer to remain anonymous)

---

## Security Best Practices

### For Users

When using Cortex, follow these best practices:

1. **Validate Environment Variables**
   - Check your `EDITOR` environment variable before using `cortex config`
   - Avoid setting suspicious commands in `EDITOR`

2. **Process Trusted Context Only**
   - Only optimize context from trusted sources
   - Avoid processing arbitrary user-supplied content

3. **Regular Maintenance**
   - Run `cortex consolidate` periodically to clean database
   - Keep Cortex updated: `npm update @sparn/cortex`
   - Monitor database size (`.cortex/memory.db`)

4. **Resource Limits**
   - Avoid processing extremely large context files (>100MB)
   - Monitor memory usage during optimization
   - Use `--dry-run` flag to preview optimizations first

5. **Update Regularly**
   - Check for updates: `npm outdated @sparn/cortex`
   - Review changelogs before updating
   - Run tests after updating if you use the programmatic API

### For Developers

If you're using Cortex's programmatic API:

1. **Input Validation**
   - Validate context before passing to `optimize()`
   - Set reasonable size limits
   - Sanitize metadata and tags

2. **Error Handling**
   - Wrap Cortex calls in try-catch blocks
   - Handle database errors gracefully
   - Don't expose internal errors to end users

3. **Resource Management**
   - Close database connections: `await memory.close()`
   - Limit concurrent optimizations
   - Monitor memory usage in production

4. **Configuration**
   - Use `.cortex/config.yaml` for settings
   - Avoid hardcoding sensitive data
   - Validate config values before use

---

## Security Features

Cortex includes several security features:

### 1. SQL Injection Protection
- All queries use prepared statements
- No dynamic SQL construction
- Parameterized queries with strict typing

### 2. Command Injection Protection
- `spawn()` used with separated arguments
- No shell interpolation
- User input never evaluated as code

### 3. Path Traversal Protection
- All paths resolved to `.cortex/` directory
- No user-controlled path construction
- Safe use of `path.join()` and `path.resolve()`

### 4. Input Validation
- Schema-based config validation
- Whitelist approach for allowed keys
- Type checking and range validation

### 5. Information Disclosure Prevention
- Generic error messages
- Stack traces only in debug mode (`CORTEX_DEBUG=true`)
- No sensitive data in logs

---

## Known Limitations

### Current Limitations (v0.1.0)

1. **Resource Limits**
   - No enforced maximum context size
   - No database size limits
   - No concurrent execution protection

   **Mitigation**: Use reasonable input sizes, run `cortex consolidate` regularly

2. **Child Process Timeout**
   - Relay command has no timeout

   **Mitigation**: Use with trusted commands only

3. **DoS Protection**
   - No rate limiting on CLI commands

   **Mitigation**: CLI is local-only, low risk

These limitations are documented and will be addressed in future releases. See [ROADMAP] for planned enhancements.

---

## Dependency Security

Cortex uses well-maintained, trusted dependencies:

- **better-sqlite3**: Native SQLite binding (7k+ stars)
- **ora**: Terminal spinners by sindresorhus (9k+ stars)
- **chalk**: Terminal colors by sindresorhus (21k+ stars)
- **commander**: CLI framework (27k+ stars)

All dependencies are:
- ✅ Actively maintained
- ✅ Widely used in production
- ✅ MIT/ISC/Apache-2.0 licensed
- ✅ Regularly updated

### Automated Security

We use GitHub Dependabot to:
- Monitor dependencies for vulnerabilities
- Automatically open PRs for security updates
- Keep dependencies up-to-date

---

## Disclosure Policy

### Responsible Disclosure
We follow responsible disclosure practices:
1. Report received
2. Vulnerability confirmed (or rejected)
3. Fix developed privately
4. Patch released
5. Public disclosure after users have time to update

### Public Disclosure Timeline
- **Day 0**: Vulnerability reported
- **Day 7**: Status update provided
- **Day 14**: Patch released (if vulnerability confirmed)
- **Day 21**: Public disclosure (CVE filed, advisory published)

This gives users 7 days to update before public disclosure.

---

## Security Updates

### How to Stay Informed

1. **Watch the Repository**
   - Enable "Releases only" notifications
   - Security patches are tagged with [SECURITY] prefix

2. **npm Advisories**
   - Run `npm audit` regularly
   - Subscribe to npm security alerts

3. **GitHub Security Advisories**
   - Follow the repository
   - Enable security alert notifications

### Update Process

For security updates:
```bash
# Check for updates
npm outdated @sparn/cortex

# Update to latest patch
npm update @sparn/cortex

# Update to latest minor/major (review changelog first)
npm install @sparn/cortex@latest

# Verify update
cortex --version
```

---

## Contact

For security-related questions (non-vulnerabilities):
- Open a discussion: https://github.com/sparn-labs/cortex/discussions
- Tag with `security` label

For security vulnerabilities:
- Use GitHub Security Advisories (preferred)
- Or email (to be added)

---

**Last Updated**: 2026-02-22
**Policy Version**: 1.0
