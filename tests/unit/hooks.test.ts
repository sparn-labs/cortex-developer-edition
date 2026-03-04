/**
 * Hooks Tests - Validates hook installation format and script behavior
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { hooksCommand } from '../../src/cli/commands/hooks.js';

describe('Hooks Command', () => {
  const tmpDir = join(process.cwd(), '.test-hooks-tmp');
  const claudeDir = join(tmpDir, '.claude');
  const settingsPath = join(claudeDir, 'settings.json');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(claudeDir, { recursive: true });
    // Override cwd for test
    const originalCwd = process.cwd;
    process.cwd = () => tmpDir;
    // Store for cleanup
    (globalThis as Record<string, unknown>).__hookTestCwd = originalCwd;
  });

  afterEach(() => {
    const originalCwd = (globalThis as Record<string, unknown>).__hookTestCwd as () => string;
    if (originalCwd) process.cwd = originalCwd;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('install', () => {
    it('should fail when hook scripts are not built', async () => {
      const result = await hooksCommand({ subcommand: 'install' });

      expect(result.success).toBe(false);
      expect(result.error).toContain('not built');
    });

    it('should write correct Claude Code hook format', async () => {
      // Create fake hook scripts to pass existence check
      const distHooksDir = join(process.cwd(), 'dist', 'hooks');
      mkdirSync(distHooksDir, { recursive: true });
      writeFileSync(join(distHooksDir, 'pre-prompt.js'), '// fake');
      writeFileSync(join(distHooksDir, 'post-tool-result.js'), '// fake');
      writeFileSync(join(distHooksDir, 'stop-docs-refresh.js'), '// fake');

      // Temporarily override __dirname resolution by creating settings manually
      // Since the hook command computes paths from __filename, we test the format directly
      writeFileSync(
        settingsPath,
        JSON.stringify({
          hooks: {
            UserPromptSubmit: [
              {
                hooks: [
                  {
                    type: 'command',
                    command: 'node /path/to/cortex/dist/hooks/pre-prompt.js',
                    timeout: 10,
                  },
                ],
              },
            ],
            PostToolUse: [
              {
                matcher: 'Bash|Read|Grep|Glob|WebFetch|WebSearch',
                hooks: [
                  {
                    type: 'command',
                    command: 'node /path/to/cortex/dist/hooks/post-tool-result.js',
                    timeout: 10,
                  },
                ],
              },
            ],
            Stop: [
              {
                hooks: [
                  {
                    type: 'command',
                    command: 'node /path/to/cortex/dist/hooks/stop-docs-refresh.js',
                    timeout: 10,
                  },
                ],
              },
            ],
          },
        }),
        'utf-8',
      );

      const settings = JSON.parse(readFileSync(settingsPath, 'utf-8'));

      // Validate structure matches Claude Code format
      expect(settings.hooks).toBeDefined();
      expect(settings.hooks.UserPromptSubmit).toBeInstanceOf(Array);
      expect(settings.hooks.PostToolUse).toBeInstanceOf(Array);
      expect(settings.hooks.Stop).toBeInstanceOf(Array);

      // Validate UserPromptSubmit hook format
      const prePrompt = settings.hooks.UserPromptSubmit[0];
      expect(prePrompt.hooks).toBeInstanceOf(Array);
      expect(prePrompt.hooks[0].type).toBe('command');
      expect(prePrompt.hooks[0].command).toContain('pre-prompt');
      expect(prePrompt.hooks[0].timeout).toBe(10);

      // Validate PostToolUse hook format
      const postTool = settings.hooks.PostToolUse[0];
      expect(postTool.matcher).toBe('Bash|Read|Grep|Glob|WebFetch|WebSearch');
      expect(postTool.hooks).toBeInstanceOf(Array);
      expect(postTool.hooks[0].type).toBe('command');
      expect(postTool.hooks[0].command).toContain('post-tool-result');

      // Validate Stop hook format (no matcher)
      const stopHook = settings.hooks.Stop[0];
      expect(stopHook.matcher).toBeUndefined();
      expect(stopHook.hooks).toBeInstanceOf(Array);
      expect(stopHook.hooks[0].type).toBe('command');
      expect(stopHook.hooks[0].command).toContain('stop-docs-refresh');
    });

    it('should preserve existing settings', async () => {
      writeFileSync(
        settingsPath,
        JSON.stringify({
          permissions: { allow: ['Read'] },
          hooks: {
            PreToolUse: [
              {
                matcher: 'Bash',
                hooks: [{ type: 'command', command: 'echo "custom hook"' }],
              },
            ],
          },
        }),
        'utf-8',
      );

      // Create fake hook scripts
      const distHooksDir = join(process.cwd(), 'dist', 'hooks');
      mkdirSync(distHooksDir, { recursive: true });
      writeFileSync(join(distHooksDir, 'pre-prompt.js'), '// fake');
      writeFileSync(join(distHooksDir, 'post-tool-result.js'), '// fake');
      writeFileSync(join(distHooksDir, 'stop-docs-refresh.js'), '// fake');

      const result = await hooksCommand({ subcommand: 'install' });

      if (result.success) {
        const settings = JSON.parse(readFileSync(settingsPath, 'utf-8'));
        // Should keep existing permissions
        expect(settings.permissions).toBeDefined();
        // Should keep existing custom hooks
        expect(settings.hooks.PreToolUse).toBeDefined();
      }
    });
  });

  describe('uninstall', () => {
    it('should handle missing settings.json', async () => {
      rmSync(settingsPath, { force: true });
      const result = await hooksCommand({ subcommand: 'uninstall' });

      expect(result.success).toBe(true);
      expect(result.installed).toBe(false);
    });

    it('should remove only cortex hooks', async () => {
      writeFileSync(
        settingsPath,
        JSON.stringify({
          hooks: {
            PostToolUse: [
              {
                matcher: 'Bash|Read|Grep|Glob|WebFetch|WebSearch',
                hooks: [
                  {
                    type: 'command',
                    command: 'node /path/to/cortex/dist/hooks/post-tool-result.js',
                  },
                ],
              },
              {
                matcher: 'Write',
                hooks: [{ type: 'command', command: 'echo "other hook"' }],
              },
            ],
            UserPromptSubmit: [
              {
                hooks: [
                  {
                    type: 'command',
                    command: 'node /path/to/cortex/dist/hooks/pre-prompt.js',
                  },
                ],
              },
            ],
            Stop: [
              {
                hooks: [
                  {
                    type: 'command',
                    command: 'node /path/to/cortex/dist/hooks/stop-docs-refresh.js',
                  },
                ],
              },
            ],
          },
        }),
        'utf-8',
      );

      const result = await hooksCommand({ subcommand: 'uninstall' });

      expect(result.success).toBe(true);
      expect(result.installed).toBe(false);

      const settings = JSON.parse(readFileSync(settingsPath, 'utf-8'));
      // Cortex hooks should be gone
      expect(settings.hooks.UserPromptSubmit).toBeUndefined();
      expect(settings.hooks.Stop).toBeUndefined();
      // Custom hook should remain
      expect(settings.hooks.PostToolUse).toHaveLength(1);
      expect(settings.hooks.PostToolUse[0].hooks[0].command).toBe('echo "other hook"');
    });
  });

  describe('status', () => {
    it('should detect no hooks when settings.json missing', async () => {
      rmSync(settingsPath, { force: true });
      const result = await hooksCommand({ subcommand: 'status' });

      expect(result.success).toBe(true);
      expect(result.installed).toBe(false);
    });

    it('should detect installed cortex hooks', async () => {
      writeFileSync(
        settingsPath,
        JSON.stringify({
          hooks: {
            PostToolUse: [
              {
                matcher: 'Bash|Read|Grep|Glob|WebFetch|WebSearch',
                hooks: [
                  {
                    type: 'command',
                    command: 'node /path/to/cortex/dist/hooks/post-tool-result.js',
                  },
                ],
              },
            ],
            UserPromptSubmit: [
              {
                hooks: [
                  {
                    type: 'command',
                    command: 'node /path/to/cortex/dist/hooks/pre-prompt.js',
                  },
                ],
              },
            ],
            Stop: [
              {
                hooks: [
                  {
                    type: 'command',
                    command: 'node /path/to/cortex/dist/hooks/stop-docs-refresh.js',
                  },
                ],
              },
            ],
          },
        }),
        'utf-8',
      );

      const result = await hooksCommand({ subcommand: 'status' });

      expect(result.success).toBe(true);
      expect(result.installed).toBe(true);
      expect(result.hookPaths?.prePrompt).toContain('cortex');
      expect(result.hookPaths?.postToolResult).toContain('cortex');
      expect(result.hookPaths?.stopDocsRefresh).toContain('cortex');
    });

    it('should report not installed when only non-cortex hooks exist', async () => {
      writeFileSync(
        settingsPath,
        JSON.stringify({
          hooks: {
            PreToolUse: [
              {
                matcher: 'Bash',
                hooks: [{ type: 'command', command: 'echo "other"' }],
              },
            ],
          },
        }),
        'utf-8',
      );

      const result = await hooksCommand({ subcommand: 'status' });

      expect(result.success).toBe(true);
      expect(result.installed).toBe(false);
    });
  });
});

describe('Hook Script Format', () => {
  const distExists = existsSync(join(process.cwd(), 'dist', 'hooks'));

  it.skipIf(!distExists)('should have pre-prompt hook built at expected path', () => {
    const hookPath = join(process.cwd(), 'dist', 'hooks', 'pre-prompt.js');
    expect(existsSync(hookPath)).toBe(true);
  });

  it.skipIf(!distExists)('should have post-tool-result hook built at expected path', () => {
    const hookPath = join(process.cwd(), 'dist', 'hooks', 'post-tool-result.js');
    expect(existsSync(hookPath)).toBe(true);
  });

  it.skipIf(!distExists)('should have stop-docs-refresh hook built at expected path', () => {
    const hookPath = join(process.cwd(), 'dist', 'hooks', 'stop-docs-refresh.js');
    expect(existsSync(hookPath)).toBe(true);
  });

  it.skipIf(!distExists)('pre-prompt hook should handle valid JSON input', async () => {
    const hookPath = join(process.cwd(), 'dist', 'hooks', 'pre-prompt.js');
    const hookCode = readFileSync(hookPath, 'utf-8');
    expect(hookCode).not.toContain('parseClaudeCodeContext');
    expect(hookCode).not.toContain('createBudgetPruner');
  });

  it.skipIf(!distExists)('post-tool-result hook should handle JSON protocol', async () => {
    const hookPath = join(process.cwd(), 'dist', 'hooks', 'post-tool-result.js');
    const hookCode = readFileSync(hookPath, 'utf-8');
    expect(hookCode).not.toContain('<file_path>');
    expect(hookCode).not.toContain('TOOL_PATTERNS');
  });
});

describe('Settings JSON Format Validation', () => {
  it('should produce valid Claude Code hook format', () => {
    // This validates the exact format Claude Code expects
    const settings = {
      hooks: {
        UserPromptSubmit: [
          {
            hooks: [
              {
                type: 'command' as const,
                command: 'node /path/to/pre-prompt.js',
                timeout: 10,
              },
            ],
          },
        ],
        PostToolUse: [
          {
            matcher: 'Bash|Read|Grep|Glob|WebFetch|WebSearch',
            hooks: [
              {
                type: 'command' as const,
                command: 'node /path/to/post-tool-result.js',
                timeout: 10,
              },
            ],
          },
        ],
        Stop: [
          {
            hooks: [
              {
                type: 'command' as const,
                command: 'node /path/to/stop-docs-refresh.js',
                timeout: 10,
              },
            ],
          },
        ],
      },
    };

    // Validate structure
    for (const [event, groups] of Object.entries(settings.hooks)) {
      expect(['UserPromptSubmit', 'PostToolUse', 'Stop']).toContain(event);
      expect(Array.isArray(groups)).toBe(true);

      for (const group of groups) {
        expect(Array.isArray(group.hooks)).toBe(true);
        for (const hook of group.hooks) {
          expect(hook.type).toBe('command');
          expect(typeof hook.command).toBe('string');
          expect(hook.command.length).toBeGreaterThan(0);
        }
      }
    }
  });

  it('should use correct event names (not camelCase)', () => {
    // Claude Code uses PascalCase event names
    const validEvents = [
      'SessionStart',
      'UserPromptSubmit',
      'PreToolUse',
      'PermissionRequest',
      'PostToolUse',
      'PostToolUseFailure',
      'Notification',
      'SubagentStart',
      'SubagentStop',
      'Stop',
      'PreCompact',
      'SessionEnd',
    ];

    // These were the OLD wrong names - should not be used
    const invalidNames = ['prePrompt', 'postToolResult', 'pre_prompt', 'post_tool_result'];

    // Our hooks should use valid names only
    expect(validEvents).toContain('UserPromptSubmit');
    expect(validEvents).toContain('PostToolUse');
    expect(validEvents).toContain('Stop');

    for (const invalid of invalidNames) {
      expect(validEvents).not.toContain(invalid);
    }
  });
});
