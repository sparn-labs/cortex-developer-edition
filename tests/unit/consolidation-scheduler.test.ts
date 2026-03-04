/**
 * Consolidation Scheduler Tests
 */

import { existsSync, mkdirSync, rmSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createKVMemory } from '../../src/core/kv-memory.js';
import { createConsolidationScheduler } from '../../src/daemon/consolidation-scheduler.js';
import type { CortexConfig } from '../../src/types/config.js';
import { DEFAULT_CONFIG } from '../../src/types/config.js';

describe('Consolidation Scheduler', () => {
  let testDir: string;
  let dbPath: string;
  let logPath: string;
  let config: CortexConfig;

  beforeEach(() => {
    // Create test directory
    testDir = join(tmpdir(), `cortex-scheduler-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    dbPath = join(testDir, 'test-memory.db');
    logPath = join(testDir, 'test-daemon.log');

    // Create test config with very short interval for testing (0.001 hour = 3.6 seconds)
    config = {
      ...DEFAULT_CONFIG,
      realtime: {
        ...DEFAULT_CONFIG.realtime,
        logFile: logPath,
        consolidationInterval: 0.001, // Very short for tests: 3.6 seconds
      },
    };
  });

  afterEach(async () => {
    // Cleanup test directory with retry for locked files
    if (existsSync(testDir)) {
      try {
        rmSync(testDir, { recursive: true, force: true });
      } catch (_error) {
        // On Windows, files might be locked. Wait and retry
        await new Promise((resolve) => setTimeout(resolve, 100));
        try {
          rmSync(testDir, { recursive: true, force: true });
        } catch {
          // If still fails, ignore - temp dir will be cleaned up eventually
        }
      }
    }
  });

  describe('start', () => {
    it('should start scheduler with valid interval', async () => {
      const memory = await createKVMemory(dbPath);
      const scheduler = createConsolidationScheduler({ memory, config });

      scheduler.start();

      const status = scheduler.getStatus();
      expect(status.running).toBe(true);
      expect(status.intervalHours).toBe(0.001);
      expect(status.nextRun).not.toBeNull();

      scheduler.stop();
      await memory.close();
    });

    it('should not start if interval is null', async () => {
      const memory = await createKVMemory(dbPath);
      const configDisabled = {
        ...config,
        realtime: {
          ...config.realtime,
          consolidationInterval: null,
        },
      };
      const scheduler = createConsolidationScheduler({ memory, config: configDisabled });

      scheduler.start();

      const status = scheduler.getStatus();
      expect(status.running).toBe(false);
      expect(status.intervalHours).toBeNull();

      await memory.close();
    });

    it('should not start if interval is zero', async () => {
      const memory = await createKVMemory(dbPath);
      const configDisabled = {
        ...config,
        realtime: {
          ...config.realtime,
          consolidationInterval: 0,
        },
      };
      const scheduler = createConsolidationScheduler({ memory, config: configDisabled });

      scheduler.start();

      const status = scheduler.getStatus();
      expect(status.running).toBe(false);

      await memory.close();
    });

    it('should not start twice', async () => {
      const memory = await createKVMemory(dbPath);
      const scheduler = createConsolidationScheduler({ memory, config });

      scheduler.start();
      scheduler.start(); // Second call should be no-op

      const status = scheduler.getStatus();
      expect(status.running).toBe(true);

      scheduler.stop();
      await memory.close();
    });

    it('should create log file', async () => {
      const memory = await createKVMemory(dbPath);
      const scheduler = createConsolidationScheduler({ memory, config });

      scheduler.start();

      // Scheduler start should create log entry synchronously
      // Just wait a bit for file write
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(existsSync(logPath)).toBe(true);

      scheduler.stop();
      await memory.close();
    });
  });

  describe('stop', () => {
    it('should stop running scheduler', async () => {
      const memory = await createKVMemory(dbPath);
      const scheduler = createConsolidationScheduler({ memory, config });

      scheduler.start();
      expect(scheduler.getStatus().running).toBe(true);

      scheduler.stop();
      expect(scheduler.getStatus().running).toBe(false);
      expect(scheduler.getStatus().nextRun).toBeNull();

      await memory.close();
    });

    it('should be safe to call when not running', async () => {
      const memory = await createKVMemory(dbPath);
      const scheduler = createConsolidationScheduler({ memory, config });

      scheduler.stop(); // Should not throw

      expect(scheduler.getStatus().running).toBe(false);

      await memory.close();
    });
  });

  describe('getStatus', () => {
    it('should return correct status when not running', async () => {
      const memory = await createKVMemory(dbPath);
      const scheduler = createConsolidationScheduler({ memory, config });

      const status = scheduler.getStatus();

      expect(status.running).toBe(false);
      expect(status.intervalHours).toBe(0.001);
      expect(status.nextRun).toBeNull();
      expect(status.totalRuns).toBe(0);
      expect(status.lastRun).toBeNull();
      expect(status.lastResult).toBeNull();

      await memory.close();
    });

    it('should return correct status when running', async () => {
      const memory = await createKVMemory(dbPath);
      const scheduler = createConsolidationScheduler({ memory, config });

      scheduler.start();
      const status = scheduler.getStatus();

      expect(status.running).toBe(true);
      expect(status.intervalHours).toBe(0.001);
      expect(status.nextRun).toBeGreaterThan(Date.now());
      expect(status.totalRuns).toBe(0);

      scheduler.stop();
      await memory.close();
    });

    it('should update total runs after consolidation', { timeout: 10000 }, async () => {
      const memory = await createKVMemory(dbPath);

      // Add some test data
      await memory.put({
        id: 'test-1',
        content: 'Test entry 1',
        timestamp: Date.now(),
        tags: [],
        hash: 'hash1',
        metadata: {},
        score: 0.5,
        ttl: 24,
        state: 'active',
        accessCount: 1,
        isBTSP: false,
      });

      const scheduler = createConsolidationScheduler({ memory, config });

      scheduler.start();

      // Wait for consolidation to run (interval is 0.001 hour = 3.6 seconds)
      await new Promise((resolve) => setTimeout(resolve, 5000));

      const status = scheduler.getStatus();
      expect(status.totalRuns).toBeGreaterThanOrEqual(1);
      expect(status.lastRun).not.toBeNull();
      expect(status.lastResult).not.toBeNull();

      scheduler.stop();
      await memory.close();
    });

    it('should track last result on success', { timeout: 10000 }, async () => {
      const memory = await createKVMemory(dbPath);

      // Add test entries
      await memory.put({
        id: 'test-1',
        content: 'Test entry 1',
        timestamp: Date.now(),
        tags: [],
        hash: 'hash1',
        metadata: {},
        score: 0.5,
        ttl: 24,
        state: 'active',
        accessCount: 1,
        isBTSP: false,
      });

      const scheduler = createConsolidationScheduler({ memory, config });

      scheduler.start();

      // Wait for consolidation to run
      await new Promise((resolve) => setTimeout(resolve, 5000));

      const status = scheduler.getStatus();
      expect(status.lastResult).not.toBeNull();
      expect(status.lastResult?.success).toBe(true);
      expect(status.lastResult?.entriesBefore).toBeGreaterThanOrEqual(0);
      expect(status.lastResult?.entriesAfter).toBeGreaterThanOrEqual(0);

      scheduler.stop();
      await memory.close();
    });
  });

  describe('consolidation execution', () => {
    it('should run consolidation at scheduled intervals', { timeout: 15000 }, async () => {
      const memory = await createKVMemory(dbPath);

      // Add test data
      for (let i = 0; i < 5; i++) {
        await memory.put({
          id: `test-${i}`,
          content: `Test entry ${i}`,
          timestamp: Date.now(),
          tags: [],
          hash: `hash${i}`,
          metadata: {},
          score: 0.5,
          ttl: 24,
          state: 'active',
          accessCount: 1,
          isBTSP: false,
        });
      }

      const scheduler = createConsolidationScheduler({ memory, config });

      scheduler.start();

      const initialStatus = scheduler.getStatus();
      expect(initialStatus.totalRuns).toBe(0);

      // Wait for first consolidation (3.6 seconds + buffer)
      await new Promise((resolve) => setTimeout(resolve, 5000));

      const firstStatus = scheduler.getStatus();
      expect(firstStatus.totalRuns).toBe(1);

      // Wait for second consolidation
      await new Promise((resolve) => setTimeout(resolve, 4000));

      const secondStatus = scheduler.getStatus();
      expect(secondStatus.totalRuns).toBeGreaterThanOrEqual(2);

      scheduler.stop();
      await memory.close();
    });

    it('should handle consolidation errors gracefully', { timeout: 10000 }, async () => {
      const memory = await createKVMemory(dbPath);

      const scheduler = createConsolidationScheduler({ memory, config });

      scheduler.start();

      // Close memory to cause errors
      await memory.close();

      // Wait for consolidation to run and fail
      await new Promise((resolve) => setTimeout(resolve, 5000));

      const status = scheduler.getStatus();
      expect(status.lastResult).not.toBeNull();
      expect(status.lastResult?.success).toBe(false);
      expect(status.lastResult?.error).toBeDefined();

      scheduler.stop();
    });

    it('should update next run time after each consolidation', { timeout: 10000 }, async () => {
      const memory = await createKVMemory(dbPath);
      const scheduler = createConsolidationScheduler({ memory, config });

      scheduler.start();

      const initialNextRun = scheduler.getStatus().nextRun;
      expect(initialNextRun).not.toBeNull();

      // Wait for consolidation to run
      await new Promise((resolve) => setTimeout(resolve, 5000));

      const updatedNextRun = scheduler.getStatus().nextRun;
      expect(updatedNextRun).not.toBeNull();
      if (initialNextRun && updatedNextRun) {
        expect(updatedNextRun).toBeGreaterThan(initialNextRun);
      }

      scheduler.stop();
      await memory.close();
    });
  });

  describe('configuration', () => {
    it('should respect custom log file path', { timeout: 10000 }, async () => {
      const customLogPath = join(testDir, 'custom-log.log');
      const memory = await createKVMemory(dbPath);

      const scheduler = createConsolidationScheduler({
        memory,
        config,
        logFile: customLogPath,
      });

      scheduler.start();

      // Wait for log file to be created
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(existsSync(customLogPath)).toBe(true);

      scheduler.stop();
      await memory.close();

      // Cleanup custom log
      if (existsSync(customLogPath)) {
        unlinkSync(customLogPath);
      }
    });

    it('should use daemon log file by default', async () => {
      const memory = await createKVMemory(dbPath);

      const scheduler = createConsolidationScheduler({
        memory,
        config,
        // No logFile specified, should use config.realtime.logFile
      });

      scheduler.start();

      // Wait for log file to be created
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(existsSync(logPath)).toBe(true);

      scheduler.stop();
      await memory.close();
    });

    it('should handle different interval values', { timeout: 15000 }, async () => {
      const memory = await createKVMemory(dbPath);

      // Test with 0.002 hour interval (7.2 seconds)
      const config2h = {
        ...config,
        realtime: {
          ...config.realtime,
          consolidationInterval: 0.002,
        },
      };

      const scheduler = createConsolidationScheduler({ memory, config: config2h });

      scheduler.start();

      const status = scheduler.getStatus();
      expect(status.intervalHours).toBe(0.002);
      expect(status.running).toBe(true);

      // Should not run after 3 seconds
      await new Promise((resolve) => setTimeout(resolve, 3000));
      expect(scheduler.getStatus().totalRuns).toBe(0);

      // Should run after 8 seconds total
      await new Promise((resolve) => setTimeout(resolve, 6000));
      expect(scheduler.getStatus().totalRuns).toBeGreaterThanOrEqual(1);

      scheduler.stop();
      await memory.close();
    });
  });
});
