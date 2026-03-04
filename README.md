# Cortex — Developer Edition

Full-featured context optimization & code analysis for AI coding agents. Keeps your Claude Code sessions lean so they last longer, cost less, and stay focused.

> Looking for the simplified version? See [`@sparn/cortex`](https://repository.sparn.dev/-/web/detail/@sparn/cortex) — simple code scanning for everyone.

## The Problem

A typical Claude Code session generates 100K+ tokens in under an hour. File reads, test outputs, build logs — it all piles up. Eventually your context window is full of noise and Claude starts forgetting the decisions you made 20 minutes ago.

Cortex sits between Claude and your project, quietly compressing verbose outputs, tracking what's still relevant, and making sure critical context (like that error you're debugging) never gets lost.

## Quick Start

```bash
npm install -g @sparn/cortex
cd your-project
cortex setup
```

That's it. One command handles everything: detects Claude Code, creates the config, installs hooks, starts the background daemon, and generates your `CLAUDE.md`. You don't need to change anything about how you use Claude Code — cortex works through hooks that fire automatically.

If you want more control, you can run each step yourself:

```bash
cortex init              # Create .cortex/ config
cortex hooks install     # Install Claude Code hooks
cortex daemon start      # Start background optimizer
cortex docs              # Generate CLAUDE.md
```

## What It Actually Does

### Hook-based compression

Every time Claude runs a Bash command, reads a file, or greps your codebase, cortex checks the output size. If it's large (3000+ tokens), it generates a content-aware summary and attaches it as additional context. Claude still sees the full output, but also gets a compact version to reference later when the original scrolls out of view.

The compression is type-aware:
- **Test results** — extracts pass/fail lines, skips the noise
- **TypeScript errors** — groups by error code (`TS2304(12), TS7006(3)`)
- **Lint output** — aggregates by rule
- **Git diffs** — lists changed files
- **JSON responses** — shows structure (array length, object keys)
- **Build logs** — pulls error and warning lines

Typical reduction: 60-90% on verbose outputs.

### Session awareness

At the start of each prompt, cortex tells you what's going on:

```
[cortex] Session: 4.2MB | 3 outputs compressed | ~12K tokens saved
```

When your session grows past 2MB, it nudges Claude to stay concise. Small thing, but it helps.

### Cross-session memory

When you start a fresh Claude Code session in a project cortex knows about, it injects a briefing with:
- Important context from past sessions (errors, architectural decisions, patterns)
- Overdue technical debt items
- Active implementation plans

So Claude doesn't start from zero every time.

### Daemon

The background daemon watches your session files and optimizes them when they get large. It also handles periodic consolidation (merging duplicate entries, cleaning up stale data). The daemon auto-starts when you open a Claude Code session — if it dies, the next prompt brings it back.

```bash
cortex daemon status    # Check if it's running
cortex daemon stop      # Stop it
```

### Auto-updating hooks

When you upgrade cortex via npm, the postinstall script detects your existing hooks and updates their paths. No manual re-installation needed.

## Codebase Intelligence

Beyond compression, cortex can analyze your project structure to help Claude navigate smarter.

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
cortex docs --no-graph      # Skip dependency analysis
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

Track technical debt with severity levels:

```bash
cortex debt add "Fix N+1 queries" --severity P0 --due 2026-04-01 --files src/db.ts
cortex debt list --overdue
cortex debt resolve <id>
```

### Codebase analyzer

Multi-dimensional scoring across architecture, quality, database, security, tokens, and test coverage:

```bash
cortex analyze                    # Full analysis with score + grade
cortex analyze --json             # Machine-readable output with fixable/fixType hints
cortex analyze --file src/api.ts  # Per-file health score
cortex analyze --changed          # Only files changed since last commit
cortex analyze --history          # Score trend over time
cortex analyze --save-baseline    # Save current results as baseline
cortex analyze --diff             # Compare against saved baseline
```

Supports `.cortexignore` for excluding files or suppressing specific rules:

```
# .cortexignore
src/generated/**
src/legacy/** QUAL-001,QUAL-003
```

## CLI

Running `cortex` with no arguments shows project status. Help shows the essential commands by default:

```bash
cortex              # Project status
cortex --help       # Essential commands
cortex --help --all # Everything
```

Essential commands: `setup`, `status`, `optimize`, `stats`, `hooks`.

Advanced commands (visible with `--all`): `analyze`, `graph`, `search`, `docs`, `plan`, `exec`, `verify`, `debt`, `config`, `relay`, `consolidate`, `interactive`, `daemon`, `mcp:server`.

## Configuration

After setup, edit `.cortex/config.yaml` if you want to tune things:

```yaml
pruning:
  threshold: 5          # Keep top 5% of context
  aggressiveness: 50    # 0-100

decay:
  defaultTTL: 24        # Hours before context starts fading
  decayThreshold: 0.95

realtime:
  tokenBudget: 40000
  autoOptimizeThreshold: 60000

agent: claude-code  # auto-detected during setup
```

Or use the CLI:

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
import { createSparsePruner, estimateTokens } from '@sparn/cortex';

const pruner = createSparsePruner({ threshold: 5 });
const result = pruner.prune(largeContext, 5);
console.log(`${estimateTokens(largeContext)} -> ${estimateTokens(result.prunedContext)} tokens`);
```

Full API: `createDependencyGraph`, `createSearchEngine`, `createWorkflowPlanner`, `createDocsGenerator`, `createDebtTracker`, `createAnalysisHistory`, `createCortexIgnore`, `buildAnalysisContext`, `buildChangedFilesContext`, `buildSingleFileContext`, `createKVMemory`, `createBudgetPrunerFromConfig`, `createIncrementalOptimizer`, and more.

## How It Works

Cortex uses a multi-stage pipeline:

1. **Relevance filtering** — Only the top 2-5% of context carries real signal
2. **Time decay** — Older context fades unless reinforced by reuse
3. **Entry classification** — Active, ready, or silent based on score
4. **Critical event detection** — Errors and stack traces get permanently flagged (BTSP)
5. **Consolidation** — Periodic merging of duplicates and cleanup of stale data

## Development

```bash
git clone https://github.com/sparn-labs/cortex.git
cd cortex
npm install
npm run build
npm test
npm run lint
npm run typecheck
```

## License

MIT
