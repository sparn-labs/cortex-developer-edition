#!/usr/bin/env node
/**
 * UserPromptSubmit Hook - Fires before Claude processes the user's prompt
 *
 * Checks session transcript size and injects optimization hints when
 * the context is getting large. Helps Claude stay focused in long sessions.
 *
 * CRITICAL: Always exits 0 (never disrupts Claude Code).
 */

import { spawn } from 'node:child_process';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { formatDashboardStats } from './dashboard-stats.js';

const DEBUG = process.env['CORTEX_DEBUG'] === 'true';
const LOG_FILE = process.env['CORTEX_LOG_FILE'] || join(homedir(), '.cortex-hook.log');

function log(message: string): void {
  if (DEBUG) {
    const timestamp = new Date().toISOString();
    appendFileSync(LOG_FILE, `[${timestamp}] [pre-prompt] ${message}\n`);
  }
}

interface HookInput {
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  hook_event_name?: string;
  prompt?: string;
}

const CACHE_FILE = join(homedir(), '.cortex', 'hook-state-cache.json');
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface CacheEntry {
  key: string;
  hint: string;
  timestamp: number;
}

function getCacheKey(sessionId: string, size: number, mtimeMs: number): string {
  return `${sessionId}:${size}:${Math.floor(mtimeMs)}`;
}

function readCache(key: string): string | null {
  try {
    if (!existsSync(CACHE_FILE)) return null;
    const data = JSON.parse(readFileSync(CACHE_FILE, 'utf-8')) as CacheEntry;
    if (data.key !== key) return null;
    if (Date.now() - data.timestamp > CACHE_TTL_MS) return null;
    return data.hint;
  } catch {
    return null;
  }
}

function writeCache(key: string, hint: string): void {
  try {
    const dir = dirname(CACHE_FILE);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    const entry: CacheEntry = { key, hint, timestamp: Date.now() };
    writeFileSync(CACHE_FILE, JSON.stringify(entry), 'utf-8');
  } catch {
    // Fail silently — cache is best-effort
  }
}

/**
 * Auto-start daemon if not running.
 * Checks PID file and spawns daemon in background if needed.
 */
function autoStartDaemon(cwd: string): void {
  try {
    const pidFile = resolve(cwd, '.cortex/daemon.pid');
    const cortexDir = resolve(cwd, '.cortex');

    // Only auto-start if .cortex/ exists (project initialized)
    if (!existsSync(cortexDir)) return;

    // Check if daemon is already running
    if (existsSync(pidFile)) {
      try {
        const pid = Number.parseInt(readFileSync(pidFile, 'utf-8').trim(), 10);
        if (!Number.isNaN(pid)) {
          process.kill(pid, 0); // check if alive
          return; // daemon is running
        }
      } catch {
        // Process dead, stale PID file — will restart below
      }
    }

    // Find the daemon entry point relative to this hook script
    // Hook is at dist/hooks/pre-prompt.js, daemon is at dist/daemon/index.js
    const hookDir = dirname(new URL(import.meta.url).pathname);
    const daemonPath = join(hookDir, '..', 'daemon', 'index.js');

    if (!existsSync(daemonPath)) {
      log(`Daemon script not found: ${daemonPath}`);
      return;
    }

    // Read config for daemon env
    const configPath = resolve(cwd, '.cortex/config.yaml');
    if (!existsSync(configPath)) return;

    // Pass the raw config path — daemon will load it itself
    // We also pass a minimal JSON config so daemon can start
    const configContent = readFileSync(configPath, 'utf-8');
    // Quick YAML-to-JSON: use js-yaml via require (shim available)
    // biome-ignore lint/suspicious/noExplicitAny: dynamic require for optional dep
    const yaml = require('js-yaml') as any;
    const config = yaml.load(configContent);

    const child = spawn(process.execPath, [daemonPath], {
      detached: true,
      stdio: 'ignore',
      cwd,
      env: {
        ...process.env,
        CORTEX_CONFIG: JSON.stringify(config),
        CORTEX_PID_FILE: resolve(cwd, '.cortex/daemon.pid'),
        CORTEX_LOG_FILE: resolve(cwd, '.cortex/daemon.log'),
      },
    });

    child.unref();

    // Write PID file immediately
    if (child.pid) {
      if (!existsSync(dirname(pidFile))) {
        mkdirSync(dirname(pidFile), { recursive: true });
      }
      writeFileSync(pidFile, String(child.pid), 'utf-8');
      log(`Auto-started daemon with PID ${child.pid}`);
    }
  } catch (err) {
    log(`Daemon auto-start failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function main(): Promise<void> {
  try {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk);
    }
    const raw = Buffer.concat(chunks).toString('utf-8');

    let input: HookInput;
    try {
      input = JSON.parse(raw);
    } catch {
      log('Failed to parse JSON input, passing through');
      process.exit(0);
      return;
    }

    log(`Session: ${input.session_id}, prompt length: ${input.prompt?.length ?? 0}`);

    // --- Auto-start daemon if not running ---
    const cwd = input.cwd || process.cwd();
    autoStartDaemon(cwd);

    // --- Dashboard stats (always attempted, not cached) ---
    const dbPath = resolve(cwd, '.cortex/memory.db');
    let dashboardStats: string | null = null;
    try {
      dashboardStats = formatDashboardStats(dbPath, cwd);
      if (dashboardStats) {
        log(`Dashboard stats: ${dashboardStats.split('\n').length} lines`);
      }
    } catch (err) {
      log(`Dashboard stats error: ${err instanceof Error ? err.message : String(err)}`);
    }

    // --- Cross-session memory briefing (new/fresh sessions only) ---
    let memoryBriefing: string | null = null;
    const transcriptPath = input.transcript_path;
    const isNewSession =
      !transcriptPath || !existsSync(transcriptPath) || statSync(transcriptPath).size < 5000; // < 5KB = fresh session

    if (isNewSession && existsSync(dbPath)) {
      try {
        // biome-ignore lint/suspicious/noExplicitAny: dynamic require for better-sqlite3
        const Database = require('better-sqlite3') as any;
        const briefDb = new Database(dbPath, { readonly: true });
        try {
          const briefLines: string[] = [];

          // Top BTSP entries (critical context from past sessions)
          try {
            const btspRows = briefDb
              .prepare(
                `SELECT v.content FROM entries_index i
               JOIN entries_value v ON i.id = v.id
               WHERE i.is_btsp = 1
               ORDER BY i.score DESC, i.timestamp DESC
               LIMIT 5`,
              )
              .all() as Array<{ content: string }>;
            if (btspRows.length > 0) {
              briefLines.push('[cortex-memory] Critical context from previous sessions:');
              for (const row of btspRows) {
                const snippet = row.content.substring(0, 200).replace(/\n/g, ' ');
                briefLines.push(`  - ${snippet}`);
              }
            }
          } catch {
            // table may not exist
          }

          // Overdue tech debt
          try {
            const overdueRows = briefDb
              .prepare(
                `SELECT description, severity FROM tech_debt
               WHERE status != 'resolved' AND repayment_date < ?
               ORDER BY CASE severity WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 ELSE 2 END
               LIMIT 3`,
              )
              .all(Date.now()) as Array<{ description: string; severity: string }>;
            if (overdueRows.length > 0) {
              briefLines.push('[cortex-memory] Overdue tech debt:');
              for (const row of overdueRows) {
                briefLines.push(`  - [${row.severity}] ${row.description}`);
              }
            }
          } catch {
            // table may not exist
          }

          // Active plans
          try {
            const plansDir = resolve(cwd, '.cortex/plans');
            if (existsSync(plansDir)) {
              const planFiles = readdirSync(plansDir).filter((f: string) => f.endsWith('.json'));
              const activePlans: string[] = [];
              for (const f of planFiles.slice(0, 5)) {
                try {
                  const plan = JSON.parse(readFileSync(join(plansDir, f), 'utf-8'));
                  if (plan.status === 'planned' || plan.status === 'in_progress') {
                    activePlans.push(`  - ${plan.task || plan.id || f}`);
                  }
                } catch {
                  // skip invalid plans
                }
              }
              if (activePlans.length > 0) {
                briefLines.push('[cortex-memory] Active plans:');
                briefLines.push(...activePlans);
              }
            }
          } catch {
            // ignore
          }

          if (briefLines.length > 0) {
            memoryBriefing = briefLines.join('\n');
            log(`Memory briefing: ${briefLines.length} lines`);
          }
        } finally {
          briefDb.close();
        }
      } catch (err) {
        log(`Memory briefing error: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    // --- Transcript size hint (cached) ---
    let sizeHint: string | null = null;
    if (transcriptPath && existsSync(transcriptPath)) {
      const stats = statSync(transcriptPath);
      const sizeMB = stats.size / (1024 * 1024);
      log(`Transcript size: ${sizeMB.toFixed(2)} MB`);

      const cacheKey = getCacheKey(input.session_id || 'unknown', stats.size, stats.mtimeMs);
      const cachedHint = readCache(cacheKey);
      if (cachedHint) {
        log('Cache hit for transcript hint');
        sizeHint = cachedHint;
      } else if (sizeMB > 2) {
        sizeHint =
          sizeMB > 5
            ? `[cortex] Session transcript is ${sizeMB.toFixed(1)}MB. Context is very large. Prefer concise responses and avoid re-reading files already in context.`
            : `[cortex] Session transcript is ${sizeMB.toFixed(1)}MB. Context is growing. Be concise where possible.`;
        writeCache(cacheKey, sizeHint);
        log(`Injecting optimization hint: ${sizeHint}`);
      }
    }

    // --- Session status line (always-on feedback) ---
    let statusLine: string | null = null;
    try {
      const sessionStatsFile = join(homedir(), '.cortex', 'session-stats.json');
      if (existsSync(sessionStatsFile)) {
        const sessionData = JSON.parse(readFileSync(sessionStatsFile, 'utf-8'));
        const sessionId = input.session_id || 'unknown';
        if (sessionData.sessionId === sessionId && sessionData.outputsCompressed > 0) {
          const saved = sessionData.totalTokensBefore - sessionData.totalTokensAfter;
          const savedStr = saved >= 1000 ? `${(saved / 1000).toFixed(1)}K` : String(saved);
          const avgReduction =
            sessionData.totalTokensBefore > 0
              ? Math.round(
                  ((sessionData.totalTokensBefore - sessionData.totalTokensAfter) /
                    sessionData.totalTokensBefore) *
                    100,
                )
              : 0;
          const transcriptSize =
            transcriptPath && existsSync(transcriptPath)
              ? `${(statSync(transcriptPath).size / (1024 * 1024)).toFixed(1)}MB`
              : 'N/A';

          // Per-tool breakdown if available
          let toolBreakdown = '';
          if (sessionData.perTool && typeof sessionData.perTool === 'object') {
            const toolParts: string[] = [];
            for (const [tool, data] of Object.entries(sessionData.perTool)) {
              const td = data as { compressed: number; tokensBefore: number; tokensAfter: number };
              if (td.compressed > 0) {
                const toolSaved = td.tokensBefore - td.tokensAfter;
                const toolSavedStr =
                  toolSaved >= 1000 ? `${(toolSaved / 1000).toFixed(0)}K` : String(toolSaved);
                toolParts.push(`${tool}:${td.compressed}/${toolSavedStr}`);
              }
            }
            if (toolParts.length > 0) {
              toolBreakdown = ` | ${toolParts.join(' ')}`;
            }
          }

          statusLine = `[cortex] Session: ${transcriptSize} | ${sessionData.outputsCompressed} compressed (${avgReduction}% avg) | ~${savedStr} saved${toolBreakdown}`;
        }
      }
    } catch {
      // ignore
    }

    // --- Combine and output ---
    const parts = [statusLine, dashboardStats, memoryBriefing, sizeHint].filter(Boolean);
    if (parts.length > 0) {
      const combined = parts.join('\n');
      const output = JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'UserPromptSubmit',
          additionalContext: combined,
        },
      });
      process.stdout.write(output);
    }

    process.exit(0);
  } catch (error) {
    log(`Error: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(0);
  }
}

main();
