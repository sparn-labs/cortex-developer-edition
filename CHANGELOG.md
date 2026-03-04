# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-03-02 (@sparn/cortex)

### New Features

#### Codebase Analyzer Enhancements
- **`.cortexignore` file support**: Glob-based file exclusion with optional rule-specific suppression
  - Pattern syntax: `src/legacy/**` (exclude all rules) or `src/legacy/** QUAL-001,QUAL-003` (specific rules only)
  - Merges with config `excludePatterns`
  - Custom ReDoS-safe glob-to-regex engine (no external dependency)

- **Enhanced JSON output for AI agents**: Machine-actionable metadata on every finding
  - `fixable` (boolean) and `fixType` (9 categories: `extract-function`, `replace-pattern`, `add-constraint`, `add-index`, `add-test`, `add-docs`, `remove-code`, `refactor`, `config-change`)
  - `ActionPlanItem` with `pointsRecoverable` and `effort` heuristic
  - All 6 analyzers annotated (58 finding types total)

- **Score history + trend tracking** (`--history`): SQLite-backed analysis history
  - Auto-records every analysis run to `.cortex/memory.db`
  - Trend delta display: `(+4.7 since last run)` with color coding
  - Auto-prunes to 500 entries

- **Changed-files mode** (`--changed [ref]`): Analyze only files changed since a git ref
  - Defaults to `HEAD~1`, supports any git ref
  - Merges staged + unstaged changes
  - Uses `execFileSync` for command injection prevention

- **Per-file scoring** (`--file <path>`): Analyze a single file
  - Path traversal prevention via `resolve()` + prefix check
  - Simplified output: `Health: 85/100 (A++) | Findings: 3`

- **Baseline/delta mode** (`--save-baseline`, `--diff`): Track finding changes over time
  - SHA-256 fingerprinting (ruleId + filePath + title) — stable across line shifts
  - Shows new findings, fixed findings, and unchanged count
  - Score comparison with delta

### Security Fixes
- **Command injection prevention**: `--changed` ref argument passed via `execFileSync` array (not shell interpolation)
- **ReDoS prevention**: `globToRegex()` uses `(?:[^/]+/)*` instead of catastrophic `(?:.+/)?`
- **Path traversal prevention**: `--file` validates resolved path stays within project root
- **SQLite connection leak fix**: `try/catch` around table init with `db.close()` on failure
- **Use-after-close guard**: `ensureOpen()` check on all history operations
- **Safe JSON.parse**: Corrupt DB columns default to `{}` instead of crashing

### Testing
- **582 tests passing** across 48 test files (up from 533)
- New test suites: `cortexignore.test.ts` (11), `analysis-history.test.ts` (11), `baseline.test.ts` (8), `context-builder.test.ts` (10), report-generator additions (5)

### Technical
- 4 new modules, 4 new test files, 7 modified source files
- All findings in all 6 analyzers annotated with `fixable`/`fixType`
- New exports: `createAnalysisHistory`, `computeTrend`, `createCortexIgnore`, `parseCortexIgnore`, `fingerprint`, `saveBaseline`, `loadBaseline`, `diffFindings`, `buildChangedFilesContext`, `buildSingleFileContext`, `buildActionPlanItems`

---

## [1.4.0] - 2026-02-26

### New Features

#### TUI Dashboard
- **Interactive Dashboard** (`sparn dashboard` / `sparn dash`): Full-screen React/Ink TUI
  - Memory status panel with real-time stats
  - Optimization metrics and history
  - Dependency graph visualization
  - Technical debt overview
  - Command input with auto-complete
  - Configurable refresh interval

#### Audio Feedback
- **Cross-platform sound effects**: Audio cues for CLI events
  - Startup, command, complete, and end sounds
  - Windows (PowerShell), macOS (`afplay`), Linux (`aplay`/`paplay`/`play`)
  - Disable with `SPARN_AUDIO=false`

#### New Hooks
- **Dashboard Stats Hook**: Collects real-time metrics for the TUI dashboard
- **Stop-Docs-Refresh Hook**: Prevents unnecessary CLAUDE.md regeneration

### Testing

- **479 tests passing** across 44 test files (up from 369)
- New test suites for dashboard components, audio, adapters, and hooks

### Technical

- React/Ink dependency for TUI rendering
- Cross-platform audio via `execFileSync` with platform detection
- All existing tests continue to pass

## [1.3.0] - 2026-02-24

### New Features

#### Codebase Intelligence
- **Dependency Graph** (`sparn graph`): Analyze import/export relationships across your project
  - Entry point tracing, hot path detection, orphan file identification
  - Focus mode to zoom into specific modules
  - JSON export for programmatic use
- **Full-Text Search** (`sparn search`): FTS5 + ripgrep hybrid search engine
  - Index your codebase and query across all files
  - Ranked results with line numbers and context
- **Workflow Planner** (`sparn plan/exec/verify`): Token-budgeted implementation plans
  - Create step-by-step plans with estimated token costs
  - Execute and verify plan completion
  - Plan IDs sanitized for filesystem safety
- **Docs Generator** (`sparn docs`): Auto-generate CLAUDE.md from project structure
  - Detects entry points, scripts, dependencies, and conventions
  - Optional dependency graph integration
- **Technical Debt Tracker** (`sparn debt`): Track, prioritize, and resolve tech debt
  - Severity levels (P0-P3) with token cost estimates
  - Repayment date tracking and stats dashboard

#### Shared TF-IDF Module
- Extracted `tokenize()`, `calculateTF()`, `calculateIDF()`, `calculateTFIDF()` from 4 files into `src/utils/tfidf.ts`
- Removed ~80 lines of duplicated code across sparse-pruner, budget-pruner, incremental-optimizer, sleep-compressor

### Bug Fixes (Deep Audit)

**Critical:**
1. **Hooks wrong protocol** - Rewrote all hook files for Claude Code JSON I/O protocol
2. **Command injection** - search-engine used `execSync` with string interpolation, changed to `execFileSync`
3. **Path traversal** - workflow-planner `planPath()` now sanitizes IDs
4. **Number.parseInt radix** - Commander callbacks passed previousValue as radix (4 fixes)

**High:**
5. **getVersion()** - Was reading user's package.json instead of sparn's own
6. **DB leak** - search-engine `init()` didn't close previous connection
7. **foreign_keys pragma** - kv-memory needed explicit `PRAGMA foreign_keys = ON`
8. **compact() broken** - Wasn't actually removing expired entries
9. **resolutionTokens nullish** - Changed `|| null` to `?? null` to preserve 0
10. **verify() destroying plans** - No longer marks in-progress plans as failed

**Medium:**
11. **BTSP budget overflow** - Guard limits BTSP to 80% of budget
12. **Double watchers** - session-watcher used single recursive watcher
13. **Windows signals** - daemon-process handles Windows `process.kill` differently
14. **Conversation boost lost** - claude-code adapter now preserves boost after decay
15. **Unbounded cache** - incremental-optimizer evicts oldest 20% at 10K entries
16. **Daemon metrics misleading** - `status()` no longer reports local process metrics

**v1.3.0 Hardening Audit:**
17. **Confidence state boundary** - `> 0.7` changed to `>= 0.7` for consistency across modules
18. **Generic adapter duplicate BTSP** - `btsp.detectBTSP()` was called twice per entry
19. **Generic adapter timestamps** - All entries shared same `Date.now()`, now unique
20. **File tracker delta read** - Replaced `readFileSync` with `openSync/readSync/closeSync` for O(delta) reads
21. **MCP server version** - Hardcoded `'1.1.1'` updated to `'1.3.0'`
22. **CLI editor spawn** - Multi-word `$EDITOR` values (e.g. `"code --wait"`) now handled correctly
23. **Resource leaks** - Added `try/finally` for `memory.close()` in 5 CLI commands
24. **Session-watcher glob regex** - Fixed escaping order (`.` before `**`)
25. **Overlapping consolidation** - Added guard to prevent concurrent consolidation runs
26. **Cosine similarity perf** - Build frequency maps in single pass instead of O(n*v)
27. **Metrics percentile perf** - Pre-sort durations once, reuse for P50/P95/P99
28. **KV memory corruption** - Close db before backup/recovery attempt
29. **Stats retention** - Limit optimization_stats to 1000 rows
30. **Graph entry validation** - Error message when entry point not found in graph
31. **Default maxDepth** - Capped at 50 instead of Infinity
32. **Dead code cleanup** - Removed unused constants from claude-code adapter

### Testing

- **369 tests passing** across 35 test files (up from 230)
- New test file `v130-fixes.test.ts` with 18 targeted tests for all audit fixes
- All fix verification tests cover boundary conditions

### Technical

- 56 source files, lint clean, typecheck clean
- Build produces 6 entry points (index, cli, daemon, hooks x2, mcp)
- All hooks validated against real Claude Code protocol

## [1.2.2] - 2026-02-23

### 🐛 Critical Bug Fixes

- **Hook Config Resolution**: Fixed pre-prompt hook to check project directory (`.sparn/config.yaml`) BEFORE global config (`~/.sparn/config.yaml`)
  - **Impact**: Hooks were failing silently because they couldn't find project-specific configs
  - **Previous behavior**: Only checked `~/.sparn/config.yaml`, ignored project configs
  - **New behavior**: Checks `./sparn/config.yaml` first, falls back to `~/.sparn/config.yaml`

- **Debug Logging**: Added optional debug logging to troubleshoot hook issues
  - Enable with: `export SPARN_DEBUG=true`
  - Logs to: `~/.sparn-hook.log` (customizable via `SPARN_LOG_FILE`)
  - Tracks: token counts, threshold checks, optimization results, compression strategies, errors
  - Zero overhead when disabled (default)

- **Lower Default Threshold**: Reduced `autoOptimizeThreshold` from 80K to 60K tokens
  - **Reason**: Sessions were growing to 99K tokens without triggering optimization
  - **New defaults**: `autoOptimizeThreshold: 60000`, `tokenBudget: 40000`
  - **Impact**: More aggressive optimization, prevents sessions from approaching limits

- **Better Error Messages**: Hooks now log why they skipped optimization
  - "No config found, passing through"
  - "Under threshold (45K < 60K), passing through"
  - "Config parse error: [details]"

### ✨ Enhancements

- **Compression Logging**: post-tool-result hook now logs:
  - Which compression strategy was used (file read, grep, git diff, tests, etc.)
  - Token savings achieved (e.g., "Compressed file read: 8234 → 456 tokens")

### 📝 Documentation

- **New**: `docs/HOOK-DEBUGGING.md` - Comprehensive hook debugging guide
  - How to enable debug logging
  - Common issues & solutions
  - Advanced debugging techniques
  - Performance impact analysis
  - Best practices

### ⚙️ Technical Details

**Files Changed**:
- `src/hooks/pre-prompt.ts` - Config path resolution, debug logging
- `src/hooks/post-tool-result.ts` - Debug logging, compression tracking
- `src/types/config.ts` - Updated default thresholds
- `tests/unit/realtime-config.test.ts` - Updated tests for new defaults

**Breaking Changes**: None
- Existing configs continue to work
- Default threshold change only affects new installations

**Testing**:
- All 230 tests passing
- Hook fixes validated with manual testing

## [1.2.1] - 2026-02-23

### 🐛 Bug Fixes

- **Hooks Compatibility**: Fixed hooks command to use camelCase naming (`prePrompt`, `postToolResult`) for Claude Code 2.1.37+ compatibility
  - Previous kebab-case names (`pre-prompt`, `post-tool-result`) caused "Invalid key in record" errors
  - Updated install, uninstall, and status functions
  - Hooks now work correctly with latest Claude Code versions

## [1.2.0] - 2026-02-23

### 🚀 Major Features Added

#### MCP Server Integration
- **Model Context Protocol (MCP) Server**: Expose Sparn as MCP tools for Claude Desktop and other MCP clients
  - Three MCP tools: `sparn_optimize`, `sparn_stats`, `sparn_consolidate`
  - Full integration with `@modelcontextprotocol/sdk` v1.26.0
  - Standalone server mode: `npm run mcp:server`
  - Programmatic API: `createSparnMcpServer(options)`
  - Comprehensive documentation in `docs/MCP.md`
  - Support for Claude Desktop, VS Code, Cursor, and custom clients
  - Environment variable support for custom database paths
  - 17 integration tests covering all MCP functionality

#### CLI Interactive Mode
- **Conversational Interface**: Beautiful terminal UI for exploration and configuration
  - New `sparn interactive` (alias: `sparn i`) command
  - Configuration wizard with guided prompts for all settings (pruning, decay, states, realtime, UI)
  - Optimization preview with file browsing and confirmation
  - Stats dashboard with multiple views (optimization history, realtime metrics, memory stats)
  - Interactive memory consolidation with confirmation prompts
  - Quick actions menu (reset stats, export config, test optimization)
  - Branded terminal colors
  - 22 comprehensive integration tests

#### Automated Consolidation Scheduler
- **Periodic Memory Consolidation**: Background scheduler for automatic cleanup
  - New `realtime.consolidationInterval` config option (in hours, null = disabled)
  - Automatically runs consolidation at scheduled intervals when daemon is running
  - Full integration with existing consolidate command
  - Detailed logging to daemon log file with timestamps
  - Metrics tracking for each consolidation run (entries removed, compression ratio)
  - Status API shows next scheduled consolidation time
  - 17 unit tests with real-time interval testing

### ✨ Enhancements

- **Dependencies Added**:
  - `@modelcontextprotocol/sdk` ^1.26.0 for MCP server functionality
  - `zod` ^3.25.76 for schema validation (MCP requirement)
  - `@inquirer/prompts` ^7.10.1 for interactive terminal UI

### 📝 Technical Details

**New Files** (9):
- `src/mcp/server.ts` - Core MCP server implementation with tool definitions
- `src/mcp/index.ts` - MCP server entry point with stdio transport
- `src/cli/commands/interactive.ts` - Full interactive mode implementation (596 lines)
- `src/daemon/consolidation-scheduler.ts` - Scheduler module with setInterval
- `docs/MCP.md` - Comprehensive MCP configuration guide
- `tests/integration/mcp.test.ts` - 17 MCP integration tests
- `tests/integration/interactive.test.ts` - 22 interactive mode tests
- `tests/unit/consolidation-scheduler.test.ts` - 17 scheduler tests

**Modified Files** (5):
- `src/types/config.ts` - Added `consolidationInterval` to RealtimeConfig
- `src/daemon/index.ts` - Integrated consolidation scheduler lifecycle
- `src/index.ts` - Exported MCP server API
- `tsup.config.ts` - Added MCP entry point
- `package.json` - Added mcp:server script and mcp keyword

### 📊 Test Coverage

- **Total Tests**: 230 passing, 2 skipped (232 total)
- **Test Files**: 24 passing
- **New Test Coverage**: 56 new tests for MCP, interactive mode, and scheduler
- All tests pass, typecheck clean, lint clean, build successful

## [1.1.1] - 2026-02-23

### 🐛 Bug Fixes

- **ES Module Compatibility**: Fixed `__dirname` usage in daemon and hooks commands
  - Added `fileURLToPath` imports for ES module compatibility
  - Daemon process now correctly resolves daemon entry point path
  - Hooks command now correctly resolves hook script paths
- **Configuration**: Updated default config to include `realtime` section

### 📝 Notes

- All 176 tests passing
- Daemon functionality verified (Windows-specific detachment may vary)
- Hooks install/uninstall/status commands fully operational

## [1.1.0] - 2026-02-22

### 🚀 Major Features Added

#### Real-Time Optimization System
- **Background Daemon**: Automatically monitors Claude Code sessions and optimizes when needed
  - `sparn daemon start/stop/status` commands
  - Watches `~/.claude/projects/**/*.jsonl` files
  - Auto-optimizes when token count exceeds 80K
  - Maintains 50K token budget for Opus model

- **Claude Code Hooks**: Seamless integration with Claude Code
  - `sparn hooks install/uninstall/status` commands
  - Pre-prompt hook: Optimizes context before each Claude response
  - Post-tool-result hook: Compresses verbose tool outputs
  - Error-safe: Always exits 0, never disrupts Claude Code

#### Advanced Optimization Engine
- **Budget-Aware Pruner**: Targets specific token counts instead of percentages
  - TF-IDF relevance scoring
  - Time-based decay integration
  - State multipliers (Active 2x, Ready 1x, Silent 0.5x)
  - Critical entries bypass budget constraints

- **Incremental Optimizer**: Lightning-fast delta processing
  - Content hash-based caching
  - <50ms incremental updates
  - Document frequency table pre-computation
  - State serialization for daemon persistence

- **Streaming Context Pipeline**: Real-time sliding window buffer
  - Priority-based eviction
  - Chronological output ordering
  - Configurable window size (default: 500 entries)
  - Metadata support for custom tagging

### ✨ Enhancements

#### Tool Output Compression
Enhanced post-tool-result hook with specialized strategies for:
- **npm/pnpm install**: Extracts package counts, warnings, errors
- **Docker logs**: Deduplicates repeated log lines
- **Test results**: Summarizes pass/fail/skip counts
- **TypeScript errors**: Groups errors by file and error code
- **Git diffs**: File-level change summaries
- **Build output**: Extracts errors and warnings only

Typical compression: 70-90% token reduction

#### Configuration Extensions
New realtime configuration options:
- `realtime.tokenBudget` (default: 50000) - Target token budget
- `realtime.autoOptimizeThreshold` (default: 80000) - Auto-optimization trigger
- `realtime.watchPatterns` (default: `['**/*.jsonl']`) - File patterns to watch
- `realtime.pidFile` (default: `.sparn/daemon.pid`) - Daemon PID file location
- `realtime.logFile` (default: `.sparn/daemon.log`) - Daemon log file location
- `realtime.debounceMs` (default: 5000) - Debounce delay for file changes
- `realtime.incremental` (default: true) - Enable incremental optimization
- `realtime.windowSize` (default: 500) - Sliding window entry limit

#### Metrics and Telemetry
- New metrics collection system
- Tracks optimization duration, token savings, cache hit rates
- P50/P95/P99 latency percentiles
- Memory usage monitoring
- JSON export capability

### 📊 Performance

Validated performance targets:
- Incremental optimization: <50ms (target met)
- Full optimization: <500ms for 10K entries
- Budget pruning: <100ms for 1K entries
- Context pipeline ingestion: <10ms

### 🧪 Testing

- **176 passing tests** (up from 96)
- New test suites:
  - `context-parser.test.ts` - Context parsing utilities
  - `budget-pruner.test.ts` - Budget-aware pruning
  - `incremental-optimizer.test.ts` - Incremental optimization
  - `context-pipeline.test.ts` - Streaming pipeline
  - `file-tracker.test.ts` - Incremental file reading
  - `realtime-config.test.ts` - Configuration validation
  - `daemon.test.ts` - Daemon lifecycle integration tests
- Performance benchmarking suite added

### 📚 Documentation

- Updated `CLAUDE-CODE-SKILL.md` with real-time features
- Added technical architecture section
- Documented all new CLI commands
- Performance benchmarks documented

### 🛠️ Technical Improvements

- Extracted context parser utilities for reuse
- Added file tracker for incremental JSONL reading
- Session watcher with fs.watch integration
- Daemon process management with PID files
- Hook entry points with error-safe design
- Build configuration updated for new entry points

### 🔧 Code Quality

- All lint checks pass (Biome)
- TypeScript strict mode compliance
- No unsafe type assertions
- Import organization automated
- Consistent code formatting

## [1.0.1] - 2026-01-15

### Fixed
- Corrected package.json path in bundled init command

## [1.0.0] - 2026-01-14

### Added
- Initial release with core context optimization
- Relevance filtering (keep top 2-5%)
- Time-based decay (exponential)
- Entry classification (active/ready/silent)
- Critical event detection (one-shot locking)
- Periodic consolidation and compression
- Claude Code adapter
- CLI commands: init, optimize, stats, consolidate, relay, config
- SQLite-based KV memory store
