/**
 * Hooks Command - Install/uninstall/status for Claude Code hooks
 *
 * Manages hook integration with Claude Code's settings.json file.
 * Uses the correct Claude Code hook format:
 *   hooks.EventName = [{ matcher?, hooks: [{ type, command, timeout? }] }]
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface HooksCommandOptions {
  subcommand: 'install' | 'uninstall' | 'status';
  global?: boolean;
}

export interface HooksCommandResult {
  success: boolean;
  message: string;
  error?: string;
  installed?: boolean;
  hookPaths?: {
    prePrompt: string;
    postToolResult: string;
    stopDocsRefresh: string;
  };
}

// Claude Code hook event names
const PRE_PROMPT_EVENT = 'UserPromptSubmit';
const POST_TOOL_EVENT = 'PostToolUse';
const STOP_DOCS_EVENT = 'Stop';

// Matcher for which tools trigger the post-tool hook
const POST_TOOL_MATCHER = 'Bash|Read|Grep|Glob|WebFetch|WebSearch';

// Marker to identify cortex-managed hooks
const CORTEX_MARKER = 'cortex';

interface HookHandler {
  type: string;
  command: string;
  timeout?: number;
}

interface HookMatcherGroup {
  matcher?: string;
  hooks: HookHandler[];
}

type HooksConfig = Record<string, HookMatcherGroup[]>;

export async function hooksCommand(options: HooksCommandOptions): Promise<HooksCommandResult> {
  const { subcommand, global } = options;

  const settingsPath = global
    ? join(homedir(), '.claude', 'settings.json')
    : join(process.cwd(), '.claude', 'settings.json');

  // Find built hook scripts relative to this file
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const hooksDir = join(dirname(__dirname), 'hooks');
  const prePromptPath = join(hooksDir, 'pre-prompt.js');
  const postToolResultPath = join(hooksDir, 'post-tool-result.js');
  const stopDocsRefreshPath = join(hooksDir, 'stop-docs-refresh.js');

  switch (subcommand) {
    case 'install':
      return installHooks(
        settingsPath,
        prePromptPath,
        postToolResultPath,
        stopDocsRefreshPath,
        global,
      );
    case 'uninstall':
      return uninstallHooks(settingsPath, global);
    case 'status':
      return hooksStatus(settingsPath, global);
    default:
      return {
        success: false,
        message: `Unknown subcommand: ${subcommand}`,
        error: 'Invalid subcommand',
      };
  }
}

function validateHookScripts(...paths: string[]): string | null {
  for (const p of paths) {
    if (!existsSync(p)) return p;
  }
  return null;
}

function loadOrCreateSettings(settingsPath: string): Record<string, unknown> {
  if (existsSync(settingsPath)) {
    return JSON.parse(readFileSync(settingsPath, 'utf-8'));
  }
  const claudeDir = dirname(settingsPath);
  if (!existsSync(claudeDir)) {
    mkdirSync(claudeDir, { recursive: true });
  }
  return {};
}

function addHookEntry(
  hooks: HooksConfig,
  event: string,
  scriptPath: string,
  matcher?: string,
): void {
  if (!hooks[event]) hooks[event] = [];
  const entry: HookMatcherGroup = {
    hooks: [{ type: 'command', command: `node "${scriptPath.replace(/\\/g, '/')}"`, timeout: 10 }],
    ...(matcher ? { matcher } : {}),
  };
  hooks[event].push(entry);
}

function installHooks(
  settingsPath: string,
  prePromptPath: string,
  postToolResultPath: string,
  stopDocsRefreshPath: string,
  global?: boolean,
): HooksCommandResult {
  try {
    const missingScript = validateHookScripts(
      prePromptPath,
      postToolResultPath,
      stopDocsRefreshPath,
    );
    if (missingScript) {
      return {
        success: false,
        message: `Hook script not found: ${missingScript}`,
        error: 'Hook scripts not built. Run `npm run build` first.',
      };
    }

    const settings = loadOrCreateSettings(settingsPath);

    const hooks: HooksConfig =
      typeof settings['hooks'] === 'object' && settings['hooks'] !== null
        ? (settings['hooks'] as HooksConfig)
        : {};

    removeCortexHooks(hooks);
    addHookEntry(hooks, PRE_PROMPT_EVENT, prePromptPath);
    addHookEntry(hooks, POST_TOOL_EVENT, postToolResultPath, POST_TOOL_MATCHER);
    addHookEntry(hooks, STOP_DOCS_EVENT, stopDocsRefreshPath);

    settings['hooks'] = hooks;
    writeFileSync(settingsPath, JSON.stringify(settings, null, 2), 'utf-8');

    return {
      success: true,
      message: global
        ? 'Hooks installed globally (all projects)'
        : 'Hooks installed for current project',
      installed: true,
      hookPaths: {
        prePrompt: prePromptPath,
        postToolResult: postToolResultPath,
        stopDocsRefresh: stopDocsRefreshPath,
      },
    };
  } catch (error) {
    return {
      success: false,
      message: 'Failed to install hooks',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function uninstallHooks(settingsPath: string, global?: boolean): HooksCommandResult {
  try {
    if (!existsSync(settingsPath)) {
      return {
        success: true,
        message: 'No hooks installed (settings.json not found)',
        installed: false,
      };
    }

    const settingsJson = readFileSync(settingsPath, 'utf-8');
    const settings: Record<string, unknown> = JSON.parse(settingsJson);

    if (settings['hooks'] && typeof settings['hooks'] === 'object' && settings['hooks'] !== null) {
      const hooks = settings['hooks'] as HooksConfig;
      removeCortexHooks(hooks);

      // Remove empty event arrays
      for (const event of Object.keys(hooks)) {
        if (Array.isArray(hooks[event]) && hooks[event].length === 0) {
          delete hooks[event];
        }
      }

      // Remove hooks key if empty
      if (Object.keys(hooks).length === 0) {
        delete settings['hooks'];
      }
    }

    writeFileSync(settingsPath, JSON.stringify(settings, null, 2), 'utf-8');

    return {
      success: true,
      message: global ? 'Hooks uninstalled globally' : 'Hooks uninstalled from current project',
      installed: false,
    };
  } catch (error) {
    return {
      success: false,
      message: 'Failed to uninstall hooks',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function hooksStatus(settingsPath: string, global?: boolean): HooksCommandResult {
  try {
    if (!existsSync(settingsPath)) {
      return {
        success: true,
        message: global
          ? 'No global hooks installed (settings.json not found)'
          : 'No project hooks installed (settings.json not found)',
        installed: false,
      };
    }

    const settingsJson = readFileSync(settingsPath, 'utf-8');
    const settings: Record<string, unknown> = JSON.parse(settingsJson);

    const hooks =
      settings['hooks'] && typeof settings['hooks'] === 'object' && settings['hooks'] !== null
        ? (settings['hooks'] as HooksConfig)
        : {};

    const prePromptHook = findCortexHook(hooks, PRE_PROMPT_EVENT);
    const postToolHook = findCortexHook(hooks, POST_TOOL_EVENT);
    const stopDocsHook = findCortexHook(hooks, STOP_DOCS_EVENT);

    if (!prePromptHook && !postToolHook && !stopDocsHook) {
      return {
        success: true,
        message: global ? 'No global cortex hooks installed' : 'No project cortex hooks installed',
        installed: false,
      };
    }

    return {
      success: true,
      message: global ? 'Global cortex hooks active' : 'Project cortex hooks active',
      installed: true,
      hookPaths: {
        prePrompt: prePromptHook || '(not installed)',
        postToolResult: postToolHook || '(not installed)',
        stopDocsRefresh: stopDocsHook || '(not installed)',
      },
    };
  } catch (error) {
    return {
      success: false,
      message: 'Failed to check hooks status',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Remove all cortex-managed hooks from the config
 */
function removeCortexHooks(hooks: HooksConfig): void {
  for (const event of Object.keys(hooks)) {
    if (!Array.isArray(hooks[event])) continue;
    hooks[event] = hooks[event].filter((group) => {
      if (!Array.isArray(group.hooks)) return true;
      // Remove groups where any hook command contains "cortex"
      return !group.hooks.some(
        (h) => typeof h.command === 'string' && h.command.includes(CORTEX_MARKER),
      );
    });
  }
}

/**
 * Find a cortex hook command for a given event
 */
function findCortexHook(hooks: HooksConfig, event: string): string | null {
  const groups = hooks[event];
  if (!Array.isArray(groups)) return null;

  for (const group of groups) {
    if (!Array.isArray(group.hooks)) continue;
    for (const h of group.hooks) {
      if (typeof h.command === 'string' && h.command.includes(CORTEX_MARKER)) {
        return h.command;
      }
    }
  }

  return null;
}
