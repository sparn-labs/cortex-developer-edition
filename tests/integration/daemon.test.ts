/**
 * Daemon Integration Tests
 */

import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createDaemonCommand } from '../../src/daemon/daemon-process.js';
import { DEFAULT_CONFIG } from '../../src/types/config.js';

describe('Daemon Integration', () => {
  let testDir: string;
  let testConfig: typeof DEFAULT_CONFIG;

  beforeEach(() => {
    testDir = join(tmpdir(), `cortex-daemon-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    testConfig = {
      ...DEFAULT_CONFIG,
      realtime: {
        ...DEFAULT_CONFIG.realtime,
        pidFile: join(testDir, 'daemon.pid'),
        logFile: join(testDir, 'daemon.log'),
      },
    };
  });

  afterEach(async () => {
    // Cleanup: stop any running daemon
    const daemon = createDaemonCommand();
    try {
      await daemon.stop(testConfig);
    } catch {
      // Ignore errors
    }

    // Wait a bit for cleanup
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Remove test directory
    if (existsSync(testDir)) {
      try {
        rmSync(testDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  describe('daemon command', () => {
    it('should report not running initially', async () => {
      const daemon = createDaemonCommand();

      const result = await daemon.status(testConfig);

      expect(result.running).toBe(false);
      expect(result.message).toContain('not running');
    });

    it('should prevent starting when already running', async () => {
      const daemon = createDaemonCommand();

      // Create a fake PID file with current process
      const pidFile = testConfig.realtime.pidFile;
      mkdirSync(join(testDir), { recursive: true });
      writeFileSync(pidFile, String(process.pid));

      const result = await daemon.start(testConfig);

      expect(result.success).toBe(false);
      expect(result.message).toContain('already running');

      // Cleanup
      if (existsSync(pidFile)) {
        rmSync(pidFile);
      }
    });

    it('should handle stop when not running', async () => {
      const daemon = createDaemonCommand();

      const result = await daemon.stop(testConfig);

      expect(result.success).toBe(true);
      expect(result.message).toContain('not running');
    });

    it('should clean up stale PID file', async () => {
      const daemon = createDaemonCommand();

      // Create a PID file with non-existent process
      const pidFile = testConfig.realtime.pidFile;
      mkdirSync(join(testDir), { recursive: true });
      writeFileSync(pidFile, '999999');

      const result = await daemon.status(testConfig);

      expect(result.running).toBe(false);
      expect(existsSync(pidFile)).toBe(false);
    });
  });

  describe('PID file management', () => {
    it('should create PID file directory if needed', async () => {
      const daemon = createDaemonCommand();

      // Ensure directory doesn't exist
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }

      // Try to stop (should handle missing directory gracefully)
      const result = await daemon.stop(testConfig);

      expect(result.success).toBe(true);
    });

    it('should handle missing PID file on status check', async () => {
      const daemon = createDaemonCommand();

      const result = await daemon.status(testConfig);

      expect(result.running).toBe(false);
      expect(result.pid).toBeUndefined();
    });
  });
});
