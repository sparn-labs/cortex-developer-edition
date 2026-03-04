#!/usr/bin/env node
/**
 * Postinstall script for @sparn/cortex
 *
 * On fresh install: prints getting-started message
 * On upgrade: detects existing hooks and re-installs with updated paths
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Resolve hook script paths (relative to installed package)
const distHooksDir = join(__dirname, '..', 'dist', 'hooks');
const prePromptPath = join(distHooksDir, 'pre-prompt.js');
const postToolResultPath = join(distHooksDir, 'post-tool-result.js');
const stopDocsRefreshPath = join(distHooksDir, 'stop-docs-refresh.js');

/**
 * Check if hooks are installed in a settings.json file and update paths
 */
function updateHooksInSettings(settingsPath) {
  if (!existsSync(settingsPath)) return false;

  try {
    const content = readFileSync(settingsPath, 'utf-8');
    const settings = JSON.parse(content);

    if (!settings.hooks || typeof settings.hooks !== 'object') return false;

    let updated = false;
    const hooks = settings.hooks;

    for (const event of Object.keys(hooks)) {
      if (!Array.isArray(hooks[event])) continue;

      for (const group of hooks[event]) {
        if (!Array.isArray(group.hooks)) continue;

        for (const hook of group.hooks) {
          if (typeof hook.command !== 'string' || !hook.command.includes('cortex')) continue;

          // Update the path in the command
          let newCommand = hook.command;

          if (hook.command.includes('pre-prompt')) {
            newCommand = `node "${prePromptPath.replace(/\\/g, '/')}"`;
          } else if (hook.command.includes('post-tool-result')) {
            newCommand = `node "${postToolResultPath.replace(/\\/g, '/')}"`;
          } else if (hook.command.includes('stop-docs-refresh')) {
            newCommand = `node "${stopDocsRefreshPath.replace(/\\/g, '/')}"`;
          }

          if (newCommand !== hook.command) {
            hook.command = newCommand;
            updated = true;
          }
        }
      }
    }

    if (updated) {
      writeFileSync(settingsPath, JSON.stringify(settings, null, 2), 'utf-8');
    }

    return updated;
  } catch {
    return false;
  }
}

function main() {
  // Skip in CI environments
  if (process.env.CI || process.env.CONTINUOUS_INTEGRATION) return;

  // Check for existing hooks (upgrade scenario)
  const globalSettings = join(homedir(), '.claude', 'settings.json');
  const localSettings = join(process.cwd(), '.claude', 'settings.json');

  let hooksUpdated = false;

  // Only update if dist/hooks exist (post-build)
  if (existsSync(prePromptPath)) {
    if (updateHooksInSettings(globalSettings)) {
      hooksUpdated = true;
      console.log('\x1b[36m[cortex]\x1b[0m Updated global hook paths');
    }

    if (updateHooksInSettings(localSettings)) {
      hooksUpdated = true;
      console.log('\x1b[36m[cortex]\x1b[0m Updated local hook paths');
    }
  }

  // Print getting-started message
  if (!hooksUpdated) {
    console.log('');
    console.log('\x1b[35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m');
    console.log('\x1b[35m  @sparn/cortex\x1b[0m — Context optimization for AI coding agents');
    console.log('\x1b[35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m');
    console.log('');
    console.log('  \x1b[36mQuick Start:\x1b[0m');
    console.log('    $ cortex setup       # One-command setup (recommended)');
    console.log('');
    console.log('  \x1b[36mManual Setup:\x1b[0m');
    console.log('    $ cortex init         # Initialize .cortex/ directory');
    console.log('    $ cortex hooks install --global  # Install Claude Code hooks');
    console.log('    $ cortex daemon start # Start background optimizer');
    console.log('');
    console.log('\x1b[35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m');
    console.log('');
  }
}

main();
