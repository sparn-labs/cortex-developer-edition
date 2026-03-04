/**
 * Integration tests for config command
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { configCommand } from '../../src/cli/commands/config.js';

describe('Config Command Integration Tests', () => {
  const testDir = join(process.cwd(), '.test-config-integration');
  const cortexDir = join(testDir, '.cortex');
  const configPath = join(cortexDir, 'config.yaml');

  beforeEach(() => {
    // Create test directory structure
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
    mkdirSync(cortexDir, { recursive: true });

    // Write default config
    const defaultConfig = `# Cortex Configuration (v1.0)
agent: claude-code

pruning:
  threshold: 5
  aggressiveness: 50

decay:
  defaultTTL: 24
  decayThreshold: 0.95

states:
  activeThreshold: 0.7
  readyThreshold: 0.3

ui:
  colors: true
  sounds: false
  verbose: false

# Auto-consolidation interval (hours, or null to disable)
autoConsolidate: null
`;
    writeFileSync(configPath, defaultConfig, 'utf-8');
  });

  afterEach(() => {
    // Cleanup
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  // T143: Integration test: `cortex config get pruning.threshold` returns value
  it('T143: should get config value by key', async () => {
    const result = await configCommand({
      configPath,
      subcommand: 'get',
      key: 'pruning.threshold',
    });

    expect(result.success).toBe(true);
    expect(result.value).toBe(5);
    expect(result.message).toContain('5');
  });

  // T144: Integration test: `cortex config set pruning.threshold 10` updates config.yaml
  it('T144: should set config value and update YAML', async () => {
    const result = await configCommand({
      configPath,
      subcommand: 'set',
      key: 'pruning.threshold',
      value: '10',
    });

    expect(result.success).toBe(true);
    expect(result.message).toContain('pruning.threshold');
    expect(result.message).toContain('10');

    // Verify YAML was updated
    const updatedConfig = readFileSync(configPath, 'utf-8');
    expect(updatedConfig).toContain('threshold: 10');
  });

  // T145: Integration test: `cortex config set` rejects invalid values with helpful error
  it('T145: should reject invalid threshold value', async () => {
    const result = await configCommand({
      configPath,
      subcommand: 'set',
      key: 'pruning.threshold',
      value: '999',
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('threshold');
    expect(result.error).toContain('1-100');
  });

  it('T145: should reject invalid score value', async () => {
    const result = await configCommand({
      configPath,
      subcommand: 'set',
      key: 'states.activeThreshold',
      value: '1.5',
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('0.0-1.0');
  });

  it('T145: should reject invalid key', async () => {
    const result = await configCommand({
      configPath,
      subcommand: 'set',
      key: 'invalid.key',
      value: '10',
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('invalid.key');
  });

  // T146: Integration test: `cortex config` opens editor with YAML file
  it('T146: should return editor path when no subcommand', async () => {
    const result = await configCommand({
      configPath,
    });

    expect(result.success).toBe(true);
    expect(result.editorPath).toBe(configPath);
  });

  // T147: Integration test: `cortex config --json` outputs JSON format
  it('T147: should output JSON format when flag set', async () => {
    const result = await configCommand({
      configPath,
      subcommand: 'get',
      key: 'pruning.threshold',
      json: true,
    });

    expect(result.success).toBe(true);
    expect(result.json).toBeDefined();

    const parsed = JSON.parse(result.json ?? '{}');
    expect(parsed.key).toBe('pruning.threshold');
    expect(parsed.value).toBe(5);
  });

  it('T147: should output entire config as JSON', async () => {
    const result = await configCommand({
      configPath,
      json: true,
    });

    expect(result.success).toBe(true);
    expect(result.json).toBeDefined();

    const parsed = JSON.parse(result.json ?? '{}');
    expect(parsed.agent).toBe('claude-code');
    expect(parsed.pruning.threshold).toBe(5);
  });
});
