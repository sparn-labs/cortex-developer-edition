#!/usr/bin/env node
/**
 * Stop Hook - Auto-regenerate CLAUDE.md when source files change
 *
 * Fires at the end of each Claude response. Checks if any src/ files
 * have been modified since the last docs generation and, if so, spawns
 * `cortex docs` as a detached background process (fire-and-forget).
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
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEBUG = process.env['CORTEX_DEBUG'] === 'true';
const LOG_FILE = process.env['CORTEX_LOG_FILE'] || join(homedir(), '.cortex-hook.log');

function log(message: string): void {
  if (DEBUG) {
    const timestamp = new Date().toISOString();
    appendFileSync(LOG_FILE, `[${timestamp}] [stop-docs] ${message}\n`);
  }
}

interface HookInput {
  session_id?: string;
  cwd?: string;
  hook_event_name?: string;
}

const TIMESTAMP_FILE = 'docs-gen-timestamp';
const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx']);

/**
 * Get the max mtime of source files in src/ directory
 */
function getMaxSourceMtime(srcDir: string): number {
  let maxMtime = 0;

  try {
    const entries = readdirSync(srcDir, { recursive: true }) as string[];
    for (const entry of entries) {
      // Check extension
      const dotIdx = entry.lastIndexOf('.');
      if (dotIdx === -1) continue;
      const ext = entry.slice(dotIdx);
      if (!SOURCE_EXTENSIONS.has(ext)) continue;

      try {
        const stats = statSync(join(srcDir, entry));
        if (stats.mtimeMs > maxMtime) {
          maxMtime = stats.mtimeMs;
        }
      } catch {
        // Skip files we can't stat
      }
    }
  } catch {
    // src/ directory not readable
  }

  return maxMtime;
}

/**
 * Read the last generation timestamp
 */
function readTimestamp(cortexDir: string): number {
  try {
    const tsFile = join(cortexDir, TIMESTAMP_FILE);
    if (!existsSync(tsFile)) return 0;
    const content = readFileSync(tsFile, 'utf-8').trim();
    const ts = Number(content);
    return Number.isFinite(ts) ? ts : 0;
  } catch {
    return 0;
  }
}

/**
 * Write the current timestamp
 */
function writeTimestamp(cortexDir: string): void {
  try {
    if (!existsSync(cortexDir)) {
      mkdirSync(cortexDir, { recursive: true });
    }
    writeFileSync(join(cortexDir, TIMESTAMP_FILE), String(Date.now()), 'utf-8');
  } catch {
    // Best-effort
  }
}

/**
 * Spawn cortex docs as a detached background process
 */
function spawnDocsRefresh(cwd: string): void {
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    // CLI entry is at dist/cli/index.js (sibling to hooks/)
    const cliPath = join(dirname(__dirname), 'cli', 'index.js');

    log(`Spawning docs refresh: node ${cliPath} docs`);

    const child = spawn('node', [cliPath, 'docs'], {
      cwd,
      detached: true,
      stdio: 'ignore',
    });

    child.unref();
  } catch (error) {
    log(`Failed to spawn docs refresh: ${error instanceof Error ? error.message : String(error)}`);
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
      log('Failed to parse JSON input, exiting');
      process.exit(0);
      return;
    }

    log(`Session: ${input.session_id}, cwd: ${input.cwd}`);

    const cwd = input.cwd || process.cwd();
    const srcDir = join(cwd, 'src');

    // No src/ directory — nothing to do
    if (!existsSync(srcDir)) {
      log('No src/ directory found, skipping');
      process.exit(0);
      return;
    }

    const cortexDir = join(cwd, '.cortex');
    const lastGenTimestamp = readTimestamp(cortexDir);
    const maxSourceMtime = getMaxSourceMtime(srcDir);

    log(`Last gen: ${lastGenTimestamp}, max mtime: ${maxSourceMtime}`);

    if (maxSourceMtime > lastGenTimestamp) {
      log('Source files changed since last generation, triggering refresh');
      writeTimestamp(cortexDir);
      spawnDocsRefresh(cwd);
    } else {
      log('No source changes detected, skipping');
    }

    process.exit(0);
  } catch (error) {
    log(`Error: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(0);
  }
}

main();
