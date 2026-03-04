/**
 * Realtime Config Tests
 */

import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../../src/types/config.js';

describe('Realtime Config', () => {
  describe('DEFAULT_CONFIG', () => {
    it('should include realtime configuration', () => {
      expect(DEFAULT_CONFIG.realtime).toBeDefined();
    });

    it('should have tokenBudget default', () => {
      expect(DEFAULT_CONFIG.realtime.tokenBudget).toBe(40000);
    });

    it('should have autoOptimizeThreshold default', () => {
      expect(DEFAULT_CONFIG.realtime.autoOptimizeThreshold).toBe(60000);
    });

    it('should have watchPatterns default', () => {
      expect(DEFAULT_CONFIG.realtime.watchPatterns).toEqual(['**/*.jsonl']);
    });

    it('should have pidFile default', () => {
      expect(DEFAULT_CONFIG.realtime.pidFile).toBe('.cortex/daemon.pid');
    });

    it('should have logFile default', () => {
      expect(DEFAULT_CONFIG.realtime.logFile).toBe('.cortex/daemon.log');
    });

    it('should have debounceMs default', () => {
      expect(DEFAULT_CONFIG.realtime.debounceMs).toBe(5000);
    });

    it('should have incremental default', () => {
      expect(DEFAULT_CONFIG.realtime.incremental).toBe(true);
    });

    it('should have windowSize default', () => {
      expect(DEFAULT_CONFIG.realtime.windowSize).toBe(500);
    });
  });

  describe('config validation', () => {
    it('should have reasonable token budget', () => {
      // Budget should be positive and reasonable for Opus model
      expect(DEFAULT_CONFIG.realtime.tokenBudget).toBeGreaterThan(0);
      expect(DEFAULT_CONFIG.realtime.tokenBudget).toBeLessThan(200000);
    });

    it('should have threshold higher than budget', () => {
      expect(DEFAULT_CONFIG.realtime.autoOptimizeThreshold).toBeGreaterThan(
        DEFAULT_CONFIG.realtime.tokenBudget,
      );
    });

    it('should have positive debounce delay', () => {
      expect(DEFAULT_CONFIG.realtime.debounceMs).toBeGreaterThan(0);
    });

    it('should have reasonable window size', () => {
      expect(DEFAULT_CONFIG.realtime.windowSize).toBeGreaterThan(0);
      expect(DEFAULT_CONFIG.realtime.windowSize).toBeLessThan(10000);
    });
  });
});
