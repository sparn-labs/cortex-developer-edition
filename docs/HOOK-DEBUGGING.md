# Cortex Hook Debugging Guide

## Overview

Cortex hooks (pre-prompt and post-tool-result) include optional debug logging to help troubleshoot why optimization may or may not be happening.

## Quick Start

### Enable Debug Logging

**Option 1: Environment Variable (Recommended)**
```bash
export CORTEX_DEBUG=true
claude --dangerously-skip-permissions
```

**Option 2: Add to Shell Profile**
```bash
# Add to ~/.bashrc or ~/.zshrc
export CORTEX_DEBUG=true
export CORTEX_LOG_FILE=~/.cortex-debug.log  # Optional: custom log location
```

**Option 3: One-Time Session**
```bash
CORTEX_DEBUG=true claude --dangerously-skip-permissions
```

### View Logs in Real-Time

```bash
# Watch logs as they're written
tail -f ~/.cortex-hook.log

# Or if you set a custom location:
tail -f ~/.cortex-debug.log
```

## What Gets Logged

### Pre-Prompt Hook Logs

```
[2026-02-23T01:30:45.123Z] [pre-prompt] Input tokens: 45234
[2026-02-23T01:30:45.124Z] [pre-prompt] Using project config: /path/to/.cortex/config.yaml
[2026-02-23T01:30:45.125Z] [pre-prompt] Threshold: 60000, Budget: 40000
[2026-02-23T01:30:45.126Z] [pre-prompt] Under threshold (45234 < 60000), passing through
```

**When optimization triggers:**
```
[2026-02-23T01:35:12.456Z] [pre-prompt] Input tokens: 75432
[2026-02-23T01:35:12.457Z] [pre-prompt] Using project config: /path/to/.cortex/config.yaml
[2026-02-23T01:35:12.458Z] [pre-prompt] Threshold: 60000, Budget: 40000
[2026-02-23T01:35:12.459Z] [pre-prompt] Over threshold! Optimizing 75432 tokens to fit 40000 budget
[2026-02-23T01:35:12.460Z] [pre-prompt] Parsed 234 context entries
[2026-02-23T01:35:12.789Z] [pre-prompt] Optimization complete: 75432 → 38567 tokens (48.9% reduction)
[2026-02-23T01:35:12.790Z] [pre-prompt] Kept 47/234 entries
```

### Post-Tool-Result Hook Logs

```
[2026-02-23T01:31:23.123Z] [post-tool-result] Tool result tokens: 8234
[2026-02-23T01:31:23.124Z] [post-tool-result] Over threshold! Compressing 8234 token tool result
[2026-02-23T01:31:23.125Z] [post-tool-result] Detected: File read
[2026-02-23T01:31:23.145Z] [post-tool-result] Compressed file read: 8234 → 456 tokens
```

**All compression types logged:**
- File read (truncation)
- Grep results (grouping by file)
- Git diffs (file-level summaries)
- Build output (errors/warnings only)
- NPM install (package counts + warnings)
- Docker logs (deduplication)
- Test results (pass/fail counts)
- TypeScript errors (grouping by file/code)

## Common Issues & Solutions

### Issue 1: "No config found, passing through"

**Cause:** Hooks can't find `.cortex/config.yaml`

**Solution:**
```bash
# Initialize Cortex in your project
cd /path/to/project
cortex init

# Or use global config
mkdir -p ~/.cortex
cortex init --global
```

### Issue 2: "Under threshold, passing through" (every time)

**Cause:** Your context never exceeds `autoOptimizeThreshold`

**Solutions:**

**Option A: Lower the threshold**
```yaml
# .cortex/config.yaml
realtime:
  autoOptimizeThreshold: 30000  # Trigger at 30K instead of 60K
  tokenBudget: 20000            # Target 20K
```

**Option B: Check your actual token usage**
```bash
# Enable logging
export CORTEX_DEBUG=true

# Start Claude Code and work for a while
claude --dangerously-skip-permissions

# Check what token counts hooks are seeing
tail -f ~/.cortex-hook.log | grep "Input tokens"
```

### Issue 3: "Config parse error"

**Cause:** Invalid YAML syntax in config file

**Solution:**
```bash
# Validate your config
cat .cortex/config.yaml

# Reinitialize if needed
cortex init --force
```

### Issue 4: Hooks not running at all

**Cause:** Hooks not installed or Claude Code not calling them

**Check installation:**
```bash
cd /path/to/project
cortex hooks status
```

**Expected output:**
```
✓ Project hooks active

Hook paths:
  prePrompt: node /path/to/cortex/dist/hooks/pre-prompt.js
  postToolResult: node /path/to/cortex/dist/hooks/post-tool-result.js
```

**Reinstall if needed:**
```bash
cortex hooks uninstall
cortex hooks install
```

**Verify hooks are in settings.json:**
```bash
cat .claude/settings.json
```

**Expected:**
```json
{
  "hooks": {
    "prePrompt": "node /path/to/cortex/dist/hooks/pre-prompt.js",
    "postToolResult": "node /path/to/cortex/dist/hooks/post-tool-result.js"
  }
}
```

### Issue 5: No logs appearing

**Possible causes:**

1. **DEBUG not enabled:**
```bash
# Check if environment variable is set
echo $CORTEX_DEBUG  # Should output: true
```

2. **Log file permissions:**
```bash
# Check if log file is writable
touch ~/.cortex-hook.log
ls -la ~/.cortex-hook.log
```

3. **Hooks exiting before logging:**
```bash
# Test hooks manually
echo "test" | CORTEX_DEBUG=true node /path/to/cortex/dist/hooks/pre-prompt.js
```

## Advanced Debugging

### Test Hooks Manually

**Test pre-prompt hook:**
```bash
cd /path/to/project
export CORTEX_DEBUG=true

# Create test context
cat > test-context.txt << 'EOF'
User: Read all files
Assistant: I'll read the files now.
[... lots of file content ...]
EOF

# Run hook
cat test-context.txt | node ~/.nvm/versions/node/*/lib/node_modules/@sparn/cortex/dist/hooks/pre-prompt.js > output.txt

# Check log
cat ~/.cortex-hook.log

# Compare input vs output tokens
wc -w test-context.txt output.txt
```

**Test post-tool-result hook:**
```bash
# Create verbose tool output
seq 1 1000 | awk '{print "Line "$1": Some log message"}' > test-tool.txt

# Run hook
export CORTEX_DEBUG=true
cat test-tool.txt | node ~/.nvm/versions/node/*/lib/node_modules/@sparn/cortex/dist/hooks/post-tool-result.js > compressed.txt

# Check compression
wc -l test-tool.txt compressed.txt
cat ~/.cortex-hook.log | grep post-tool-result
```

### Monitor Hook Activity During Session

```bash
# Terminal 1: Start Claude Code with debug logging
export CORTEX_DEBUG=true
export CORTEX_LOG_FILE=~/cortex-session.log
claude --dangerously-skip-permissions

# Terminal 2: Watch logs in real-time
tail -f ~/cortex-session.log

# Terminal 3: Monitor session file size
watch -n 5 'find ~/.claude/projects -name "*.jsonl" -exec ls -lh {} \;'
```

## Performance Impact

### With DEBUG=false (default):
- Pre-prompt hook: 10-50ms overhead
- Post-tool-result hook: 5-20ms overhead
- No log file I/O
- Minimal memory footprint

### With DEBUG=true:
- Pre-prompt hook: 15-60ms overhead (+5-10ms for logging)
- Post-tool-result hook: 10-25ms overhead (+5ms for logging)
- Log file grows ~200 bytes per hook execution
- Still safe for production use

### Log Rotation

If your log file gets too large:

```bash
# Truncate log
> ~/.cortex-hook.log

# Or use logrotate
cat > /etc/logrotate.d/cortex-hooks << 'EOF'
/home/user/.cortex-hook.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
EOF
```

## Interpreting Results

### Healthy Optimization Pattern

```
# Session starts
Input tokens: 5234 → under threshold → pass through ✓

# Work continues
Input tokens: 25456 → under threshold → pass through ✓

# Context grows
Input tokens: 62789 → OVER THRESHOLD → optimize! ✓
Optimization: 62789 → 38234 tokens (39% reduction) ✓
Kept 89/456 entries ✓

# After optimization, context is lean
Input tokens: 38234 → under threshold → pass through ✓

# More work
Input tokens: 58234 → under threshold → pass through ✓

# Grows again
Input tokens: 71234 → OVER THRESHOLD → optimize! ✓
Optimization: 71234 → 39567 tokens (44% reduction) ✓
```

### Problem Pattern

```
# Context stays below threshold entire session
Input tokens: 25234 → under threshold → pass through
Input tokens: 32456 → under threshold → pass through
Input tokens: 45678 → under threshold → pass through
... (never optimizes)
```

**Solution:** Lower `autoOptimizeThreshold` in config

## Best Practices

1. **Enable DEBUG only when needed** - Adds small overhead
2. **Use project-specific configs** - Different projects have different needs
3. **Monitor actual token usage** - Adjust thresholds based on real data
4. **Test hooks before long sessions** - Verify they're working correctly
5. **Clean logs periodically** - Prevent unlimited growth

## Support

If hooks still aren't working after following this guide:

1. Check Claude Code version: `claude --version`
2. Check Cortex version: `cortex --version`
3. Collect debug logs
4. Open issue at: https://github.com/sparn-labs/cortex/issues

Include:
- Operating system
- Claude Code version
- Cortex version
- Debug log excerpt
- Steps to reproduce
