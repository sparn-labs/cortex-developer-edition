# Privacy Policy

**Last Updated**: 2026-02-22
**Effective Date**: 2026-02-22
**Version**: 1.0

---

## 🔒 Your Privacy Matters

Cortex is a **local-only CLI tool** that respects your privacy. We believe your data belongs to you, which is why Cortex never sends your data anywhere.

---

## 📊 What Data Does Cortex Store?

All data is stored **locally on your machine** in the `.cortex/` directory within your project:

### 1. Context Content
- **What**: The AI agent context you choose to optimize
- **Where**: `.cortex/memory.db` (SQLite database)
- **Why**: To optimize and reduce token usage
- **Control**: You decide what content to optimize

### 2. Optimization Statistics
- **What**: Token counts, timestamps, performance metrics
- **Where**: `.cortex/memory.db` (SQLite database)
- **Why**: To track optimization effectiveness
- **Control**: View with `cortex stats`, delete with `cortex stats --reset`

### 3. Configuration
- **What**: Your preferences (theme, agent type, optimization settings)
- **Where**: `.cortex/config.yaml`
- **Why**: To customize Cortex's behavior
- **Control**: Edit with `cortex config` or text editor

### 4. Metadata
- **What**: Entry IDs, hashes, scores, timestamps
- **Where**: `.cortex/memory.db`
- **Why**: To manage memory lifecycle (decay, deduplication)
- **Control**: Managed automatically, visible in database

---

## 🚫 What Cortex Does NOT Do

We want to be crystal clear about what we **don't** do:

- ❌ **No Data Transmission**: Cortex NEVER sends data to external servers
- ❌ **No Telemetry**: We don't collect usage statistics or analytics
- ❌ **No Tracking**: No cookies, no tracking pixels, no fingerprinting
- ❌ **No Cloud Storage**: All data stays on your local machine
- ❌ **No Third-Party Sharing**: Your data never leaves your computer
- ❌ **No Personal Data Collection**: We don't collect names, emails, or identifiers
- ❌ **No Account Required**: No sign-up, no registration, no login

**Bottom line**: Cortex works 100% offline. You could disconnect from the internet and it would still work perfectly.

---

## 🔐 How Your Data is Protected

### Local-Only Architecture
- All processing happens on your machine
- Data never transmitted over the network
- No risk of server breaches or interception

### File System Permissions
- Data protected by your OS file permissions
- Only you (and programs you run) can access `.cortex/`
- Standard file system security applies

### Database Integrity
- SQLite database with ACID compliance
- Automatic corruption detection
- Timestamped backups on corruption

### No External Dependencies
- Doesn't require internet connection
- No API keys or credentials needed
- Self-contained processing

---

## 🎛️ Your Data, Your Control

You have **complete control** over your data:

### Access Your Data ✅
View everything Cortex stores:

```bash
# View database structure
sqlite3 .cortex/memory.db ".schema"

# View stored entries
sqlite3 .cortex/memory.db "SELECT id, timestamp, score, state FROM entries_index LIMIT 10;"

# View statistics
cortex stats --json

# View configuration
cat .cortex/config.yaml
```

### Export Your Data ✅
Take your data anywhere:

```bash
# Full database export (SQL format)
sqlite3 .cortex/memory.db .dump > cortex-backup.sql

# Export statistics (JSON format)
cortex stats --json > stats.json

# Copy entire directory
cp -r .cortex/ cortex-backup/
```

### Modify Your Data ✅
Change anything you want:

```bash
# Edit configuration
cortex config set pruning.threshold 10

# Or edit directly
nano .cortex/config.yaml

# Modify database (advanced)
sqlite3 .cortex/memory.db "UPDATE entries_index SET score = 1.0 WHERE isBTSP = 1;"
```

### Delete Your Data ✅
Remove data anytime:

```bash
# Delete all Cortex data (complete removal)
rm -rf .cortex/

# Delete old/decayed entries only
cortex consolidate

# Clear statistics only
cortex stats --reset

# Uninstall Cortex entirely
npm uninstall @sparn/cortex
rm -rf .cortex/
```

---

## 🌍 GDPR & Privacy Regulations

### EU GDPR Compliance ✅

Cortex is **fully compliant** with the EU General Data Protection Regulation (GDPR):

#### Your Rights Under GDPR:
- ✅ **Right to Access** (Art. 15): Access all data in `.cortex/`
- ✅ **Right to Rectification** (Art. 16): Edit config or database
- ✅ **Right to Erasure** (Art. 17): Delete `.cortex/` directory
- ✅ **Right to Data Portability** (Art. 20): Export SQLite database
- ✅ **Right to Object** (Art. 21): Stop processing anytime

#### How Cortex Complies:
- **Data Minimization**: Only stores necessary data
- **Purpose Limitation**: Data used only for optimization
- **Storage Limitation**: TTL mechanism, automatic decay
- **Privacy by Design**: Local-only architecture
- **Security**: No transmission, file permissions, integrity checks

### Other Privacy Laws ✅
- 🇬🇧 **UK GDPR**: Compliant (same as EU GDPR)
- 🇺🇸 **California CCPA**: Compliant (no data collection)
- 🇧🇷 **Brazil LGPD**: Compliant (local-only processing)
- 🇨🇦 **Canada PIPEDA**: Compliant (no personal data)
- 🇦🇺 **Australia Privacy Act**: Compliant

**Why Cortex is Universally Compliant**: Local-only tools don't trigger most privacy regulations because there's no data collection, transmission, or third-party processing.

---

## ⚠️ Your Responsibilities

### When Using Cortex with Personal Data

If you choose to optimize context that contains **personal data** (names, emails, addresses, etc.), **you** are responsible for:

1. **Legal Basis**: Ensure you have the right to process this data
2. **Consent**: Obtain consent from data subjects if required
3. **Security**: Secure your machine and `.cortex/` directory
4. **Data Subject Rights**: Honor access/deletion requests from individuals
5. **Breach Notification**: Report breaches per applicable laws

**Example**: If you optimize customer support transcripts containing customer names and emails, you become the **data controller** and must comply with GDPR/privacy laws.

### Cortex's Role vs Your Role

- **Cortex (the tool)**: Provides local optimization functionality
- **You (the user)**: Decide what data to process and are responsible for compliance

This is similar to using Microsoft Word or Excel with personal data—the tool provider isn't responsible for your use of the tool.

### Best Practices

To minimize privacy risks:
- ✅ **Anonymize data** before optimization if possible
- ✅ **Remove PII** from context when not needed
- ✅ **Secure your machine** with encryption, passwords
- ✅ **Don't share** `.cortex/` directory with others
- ✅ **Regular cleanup** using `cortex consolidate`

---

## 🔄 Data Retention

### Automatic Data Management

Cortex uses **time-based decay** to automatically manage data:

1. **Time-to-Live (TTL)**: Entries have configurable lifespans
2. **Engram Decay**: Scores decrease over time (like memory fading)
3. **State Transitions**: Old entries become "silent" (not retrieved)
4. **Consolidation**: `cortex consolidate` removes fully decayed entries

### Manual Data Control

You can control retention:

```bash
# Remove old/decayed data
cortex consolidate

# Adjust decay rate (config)
cortex config set decay.defaultTTL 24  # 24 hours

# Clear everything
rm -rf .cortex/
```

### No Indefinite Storage

By design, Cortex doesn't keep data forever:
- Unused entries decay naturally
- Low-score entries are pruned during optimization
- Consolidation removes old data
- Database stays lean and efficient

---

## 🔍 Transparency

### Open Source

Cortex is **open source** (MIT License):
- View all code: https://github.com/sparn-labs/cortex
- Verify no data transmission
- Review security measures
- Contribute improvements

### No Hidden Behavior

What you see is what you get:
- No compiled binaries with hidden code
- No obfuscation
- No analytics libraries
- No network dependencies

### Audit Trail

You can audit Cortex's behavior:

```bash
# Monitor file system access
strace -e open,write cortex optimize -i input.txt

# Monitor network (you'll see ZERO network calls)
tcpdump -i any host cortex

# Check for loaded network libraries
lsof -p $(pgrep cortex) | grep socket
```

---

## 📧 Privacy Questions?

### General Privacy Questions
- **Open a Discussion**: https://github.com/sparn-labs/cortex/discussions
- **Read the Code**: https://github.com/sparn-labs/cortex
- **Review GDPR Compliance**: See GDPR-COMPLIANCE.md (internal doc)

### Security Concerns
- **Security Policy**: See SECURITY.md
- **Report Vulnerabilities**: GitHub Security Advisories

### Legal Questions
- **Consult a Lawyer**: For specific legal advice about your use case
- **Review GDPR**: https://gdpr-info.eu/

---

## 🔄 Changes to This Policy

We may update this Privacy Policy to reflect:
- New features or functionality
- Changes in privacy regulations
- User feedback and clarifications

**How We Notify You**:
- Version number updated in this document
- Change announced in release notes
- Commit history visible on GitHub

**Your Continued Use**: Using Cortex after policy changes means you accept the updated policy.

---

## 📜 Legal Disclaimer

This Privacy Policy describes how Cortex (the software tool) handles data. It does not constitute legal advice. If you use Cortex to process personal data, consult a qualified attorney about your obligations under applicable privacy laws.

**Tool Provider**: We provide Cortex as-is under the MIT License.
**Data Controller**: You (the user) are the data controller when you use Cortex.
**No Service Provider Relationship**: We don't provide data processing services.

---

## ✅ Summary

- 🔒 **100% Local**: All data stays on your machine
- 🚫 **Zero Tracking**: No telemetry, analytics, or tracking
- 🎛️ **Full Control**: You own and control all data
- ✅ **GDPR Compliant**: Respects all data protection regulations
- 🔓 **Open Source**: Transparent, auditable code
- 💾 **Your Responsibility**: You control what data you process

**Privacy Score**: 🌟🌟🌟🌟🌟 (5/5)

Cortex respects your privacy because your data never leaves your machine. Period.

---

**Questions?** Open a discussion on GitHub or review the source code.

**Effective Date**: 2026-02-22
**Version**: 1.0
**Last Updated**: 2026-02-22
