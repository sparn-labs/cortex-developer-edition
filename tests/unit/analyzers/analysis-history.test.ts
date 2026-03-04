import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  computeTrend,
  createAnalysisHistory,
} from '../../../src/core/analyzers/analysis-history.js';

describe('Analysis History', () => {
  const tmpDir = join(process.cwd(), '.test-analysis-history-tmp');
  const dbPath = join(tmpDir, 'memory.db');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should record and retrieve entries', () => {
    const history = createAnalysisHistory(dbPath);

    const entry = history.record({
      timestamp: Date.now(),
      score: 85.5,
      grade: 'A+',
      categories: { quality: { score: 18, maxPoints: 20 } },
      totalFiles: 50,
      totalFindings: 10,
      projectPath: '/test/project',
      mode: 'full',
    });

    expect(entry.id).toBeGreaterThan(0);
    expect(entry.score).toBe(85.5);

    const recent = history.getRecent(5);
    expect(recent).toHaveLength(1);
    expect(recent[0]?.score).toBe(85.5);
    expect(recent[0]?.grade).toBe('A+');

    history.close();
  });

  it('should get last full analysis', () => {
    const history = createAnalysisHistory(dbPath);

    history.record({
      timestamp: Date.now() - 2000,
      score: 80,
      grade: 'A',
      categories: {},
      totalFiles: 40,
      totalFindings: 15,
      projectPath: '/test',
      mode: 'full',
    });

    history.record({
      timestamp: Date.now() - 1000,
      score: 75,
      grade: 'B',
      categories: {},
      totalFiles: 5,
      totalFindings: 3,
      projectPath: '/test',
      mode: 'changed',
    });

    const lastFull = history.getLastFull();
    expect(lastFull).not.toBeNull();
    expect(lastFull?.score).toBe(80);
    expect(lastFull?.mode).toBe('full');

    history.close();
  });

  it('should return null when no full analysis exists', () => {
    const history = createAnalysisHistory(dbPath);

    const lastFull = history.getLastFull();
    expect(lastFull).toBeNull();

    history.close();
  });

  it('should auto-prune old entries', () => {
    const history = createAnalysisHistory(dbPath);

    // Record 510 entries (exceeds MAX_ENTRIES of 500)
    for (let i = 0; i < 510; i++) {
      history.record({
        timestamp: Date.now() + i,
        score: 80 + (i % 20),
        grade: 'A',
        categories: {},
        totalFiles: 10,
        totalFindings: 5,
        projectPath: '/test',
        mode: 'full',
      });
    }

    // Should be pruned to 500
    const all = history.getRecent(600);
    expect(all.length).toBeLessThanOrEqual(500);

    history.close();
  });

  it('should preserve categories as JSON', () => {
    const history = createAnalysisHistory(dbPath);
    const cats = {
      architecture: { score: 22, maxPoints: 25 },
      quality: { score: 18, maxPoints: 20 },
    };

    history.record({
      timestamp: Date.now(),
      score: 90,
      grade: 'A++',
      categories: cats,
      totalFiles: 30,
      totalFindings: 5,
      projectPath: '/test',
      mode: 'full',
    });

    const recent = history.getRecent(1);
    expect(recent[0]?.categories).toEqual(cats);

    history.close();
  });

  it('should throw on use after close', () => {
    const history = createAnalysisHistory(dbPath);
    history.close();

    expect(() =>
      history.record({
        timestamp: Date.now(),
        score: 80,
        grade: 'A',
        categories: {},
        totalFiles: 10,
        totalFindings: 5,
        projectPath: '/test',
        mode: 'full',
      }),
    ).toThrow('already closed');
  });

  it('should return entries in descending timestamp order', () => {
    const history = createAnalysisHistory(dbPath);

    history.record({
      timestamp: 1000,
      score: 80,
      grade: 'A',
      categories: {},
      totalFiles: 10,
      totalFindings: 5,
      projectPath: '/test',
      mode: 'full',
    });

    history.record({
      timestamp: 2000,
      score: 90,
      grade: 'A++',
      categories: {},
      totalFiles: 10,
      totalFindings: 3,
      projectPath: '/test',
      mode: 'full',
    });

    const recent = history.getRecent(2);
    expect(recent[0]?.timestamp).toBe(2000);
    expect(recent[1]?.timestamp).toBe(1000);

    history.close();
  });

  it('should handle double close gracefully', () => {
    const history = createAnalysisHistory(dbPath);
    history.close();
    expect(() => history.close()).not.toThrow();
  });
});

describe('computeTrend', () => {
  it('should compute positive trend', () => {
    const trend = computeTrend(90, {
      id: 1,
      timestamp: Date.now(),
      score: 85,
      grade: 'A+',
      categories: {},
      totalFiles: 10,
      totalFindings: 5,
      projectPath: '/test',
      mode: 'full',
    });

    expect(trend).not.toBeNull();
    expect(trend?.delta).toBe(5);
    expect(trend?.label).toContain('+5');
  });

  it('should compute negative trend', () => {
    const trend = computeTrend(80, {
      id: 1,
      timestamp: Date.now(),
      score: 85,
      grade: 'A+',
      categories: {},
      totalFiles: 10,
      totalFindings: 5,
      projectPath: '/test',
      mode: 'full',
    });

    expect(trend).not.toBeNull();
    expect(trend?.delta).toBe(-5);
  });

  it('should return null when no previous entry', () => {
    const trend = computeTrend(90, null);
    expect(trend).toBeNull();
  });

  it('should handle no change', () => {
    const trend = computeTrend(85, {
      id: 1,
      timestamp: Date.now(),
      score: 85,
      grade: 'A+',
      categories: {},
      totalFiles: 10,
      totalFindings: 5,
      projectPath: '/test',
      mode: 'full',
    });

    expect(trend?.delta).toBe(0);
    expect(trend?.label).toContain('no change');
  });
});
