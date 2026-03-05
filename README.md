# Cortex — Developer Edition

Full-featured context optimization & code analysis for AI coding agents. Keeps your Claude Code sessions lean so they last longer, cost less, and stay focused.

## Quick Start

```bash
npm install -g @sparn/cortex-developer-edition
cd your-project
cortex setup
```

One command handles everything: detects Claude Code, creates the config, installs hooks, starts the background daemon, and generates your `CLAUDE.md`. You don't need to change anything about how you use Claude Code — cortex works through hooks that fire automatically.

If you want more control:

```bash
cortex init              # Create .cortex/ config
cortex hooks install     # Install Claude Code hooks
cortex daemon start      # Start background optimizer
cortex docs              # Generate CLAUDE.md
```

## What It Does

### Hook-based compression

Every time Claude runs a Bash command, reads a file, or greps your codebase, cortex checks the output size. If it's large (3000+ tokens), it generates a content-aware summary and attaches it as additional context.

The compression is type-aware:
- **Test results** — extracts pass/fail lines, skips the noise
- **TypeScript errors** — groups by error code (`TS2304(12), TS7006(3)`)
- **Lint output** — aggregates by rule
- **Git diffs** — lists changed files
- **JSON responses** — shows structure (array length, object keys)
- **Build logs** — pulls error and warning lines

Typical reduction: 60-90% on verbose outputs.

### Session awareness

At the start of each prompt, cortex shows session health:

```
[cortex] Session: 4.2MB | 3 outputs compressed | ~12K tokens saved
```

When your session grows past 2MB, it nudges Claude to stay concise.

### Cross-session memory

When you start a fresh Claude Code session in a project cortex knows about, it injects a briefing with important context from past sessions (errors, architectural decisions, patterns), overdue tech debt items, and active implementation plans.

### Daemon

The background daemon watches your session files and optimizes them when they get large. It auto-starts when you open a Claude Code session — if it dies, the next prompt brings it back.

```bash
cortex daemon status    # Check if it's running
cortex daemon stop      # Stop it
```

## Codebase Intelligence

### Dependency graph

```bash
cortex graph --analyze           # Full analysis: entry points, hot paths, orphans
cortex graph --focus auth        # Focus on files related to "auth"
cortex graph --entry src/index.ts  # Trace from an entry point
```

### Search

Full-text search backed by SQLite FTS5, with ripgrep fallback:

```bash
cortex search init          # Index your codebase
cortex search validateToken # Search
cortex search refresh       # Re-index after changes
```

### Docs generation

Auto-generates a `CLAUDE.md` from your project structure, scripts, and dependency graph:

```bash
cortex docs
cortex docs -o docs/CLAUDE.md
```

### Workflow planner

Create implementation plans with token budgets, then execute and verify:

```bash
cortex plan "Add user auth" --files src/auth.ts src/routes.ts
cortex exec <plan-id>
cortex verify <plan-id>
```

### Tech debt tracker

```bash
cortex debt add "Fix N+1 queries" --severity P0 --due 2026-04-01 --files src/db.ts
cortex debt list --overdue
cortex debt resolve <id>
cortex debt stats
```

### Codebase analyzer

Multi-dimensional scoring across architecture, quality, database, security, tokens, and test coverage:

```bash
cortex analyze                    # Full analysis with score + grade
cortex analyze --json             # Machine-readable output
cortex analyze --file src/api.ts  # Per-file health score
cortex analyze --changed          # Only files changed since last commit
cortex analyze --history          # Score trend over time
cortex analyze --save-baseline    # Save current results as baseline
cortex analyze --diff             # Compare against saved baseline
```

### Security audit

11-layer OWASP security audit with 100-point weighted scoring, CVSS integration, and auto-fix suggestions:

```bash
cortex secure .                          # Full audit
cortex secure . --fix                    # Auto-fix where possible
cortex secure . --ci --min-grade B       # CI mode
cortex secure . --compliance owasp       # Map to framework
```

### Compliance audit

8-layer regulatory compliance check (GDPR, CCPA, HIPAA, SOC2):

```bash
cortex comply .                          # Full audit
cortex comply . --framework gdpr         # Focus on GDPR
cortex comply . --ci --min-grade B       # CI mode
```

## CLI

Running `cortex` with no arguments shows project status:

```bash
cortex              # Project status
cortex --help       # Essential commands
cortex --help --all # Everything
```

**Essential commands**: `setup`, `status`, `optimize`, `stats`, `hooks`.

**Advanced commands** (visible with `--all`): `init`, `analyze`, `graph`, `search`, `docs`, `plan`, `exec`, `verify`, `debt`, `secure`, `comply`, `config`, `relay`, `consolidate`, `interactive`, `daemon`, `dashboard`, `mcp:server`.

## Configuration

Edit `.cortex/config.yaml` or use the CLI:

```yaml
pruning:
  threshold: 5          # Keep top 5% of context
  aggressiveness: 50    # 0-100

decay:
  defaultTTL: 24        # Hours before context starts fading

realtime:
  tokenBudget: 40000
  autoOptimizeThreshold: 60000

agent: claude-code  # auto-detected during setup
```

```bash
cortex config get pruning.threshold
cortex config set pruning.threshold 10
```

## MCP Server

Cortex runs as an MCP server for Claude Desktop or any MCP client:

```bash
cortex mcp:server
```

Exposes four tools: `cortex_optimize`, `cortex_stats`, `cortex_search`, `cortex_consolidate`.

## Programmatic API

```typescript
import { createSparsePruner, estimateTokens } from '@sparn/cortex-developer-edition';

const pruner = createSparsePruner({ threshold: 5 });
const result = pruner.prune(largeContext, 5);
```

Full API includes: `createDependencyGraph`, `createSearchEngine`, `createWorkflowPlanner`, `createDocsGenerator`, `createDebtTracker`, `createAnalysisHistory`, `createCortexIgnore`, `createKVMemory`, `createBudgetPrunerFromConfig`, `createIncrementalOptimizer`, `createCortexMcpServer`, `runSecureAudit`, `runComplyAudit`, and more.

## `.cortexignore`

Exclude files or suppress specific rules:

```
# .cortexignore
src/generated/**
src/legacy/** QUAL-001,QUAL-003
```

## See Also

| Package | What it does |
|---|---|
| [`@sparn/cortex`](https://github.com/sparn-labs/cortex) | Simple code scanning CLI — quality, security, and compliance checks with zero setup |
| [`@sparn/cortex-lite`](https://github.com/sparn-labs/cortex-lite) | Lightweight context compression with a native Rust engine — no CLI, just hooks and a programmatic API |

## Development

```bash
git clone https://github.com/sparn-labs/cortex-developer-edition.git
cd cortex-developer-edition
npm install
npm run build
npm test
npm run lint
npm run typecheck
```

## License

MIT
