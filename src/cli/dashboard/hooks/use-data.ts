/**
 * Custom React hook for dashboard data fetching.
 *
 * Opens KVMemory + DebtTracker once via useRef, closes on unmount.
 * Fast data refreshes on interval, slow data (graph) runs once.
 */

import { statSync } from 'node:fs';
import type React from 'react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { DebtStats, TechDebt } from '../../../core/debt-tracker.js';
import { createDebtTracker } from '../../../core/debt-tracker.js';
import type { DependencyNode, GraphAnalysis } from '../../../core/dependency-graph.js';
import { createDependencyGraph } from '../../../core/dependency-graph.js';
import type { KVMemory, OptimizationStats } from '../../../core/kv-memory.js';
import { createKVMemory } from '../../../core/kv-memory.js';
import type { DaemonStatusResult } from '../../../daemon/daemon-process.js';

export interface DashboardData {
  // Optimization
  optimizationStats: OptimizationStats[];
  totalEntries: number;
  stateDistribution: { active: number; ready: number; silent: number };

  // Debt
  debts: TechDebt[];
  debtStats: DebtStats | null;

  // Graph (loaded once)
  graphAnalysis: GraphAnalysis | null;
  graphNodes: Map<string, DependencyNode>;

  // Daemon
  daemon: DaemonStatusResult | null;

  // DB info
  dbSizeBytes: number;

  // Meta
  loading: boolean;
  error: string | null;
  lastRefresh: Date;

  // Shared accessors for command executor
  getMemory: () => KVMemory | null;
  forceRefresh: () => void;
}

const NOOP = () => {};

const EMPTY_STATE: DashboardData = {
  optimizationStats: [],
  totalEntries: 0,
  stateDistribution: { active: 0, ready: 0, silent: 0 },
  debts: [],
  debtStats: null,
  graphAnalysis: null,
  graphNodes: new Map(),
  daemon: null,
  dbSizeBytes: 0,
  loading: true,
  error: null,
  lastRefresh: new Date(),
  getMemory: () => null,
  forceRefresh: NOOP,
};

export function useDashboardData(
  dbPath: string,
  projectRoot: string,
  refreshInterval = 2000,
): DashboardData {
  const [data, setData] = useState<DashboardData>(EMPTY_STATE);
  const memoryRef = useRef<KVMemory | null>(null);
  const mountedRef = useRef(true);
  const dbPathRef = useRef(dbPath);
  dbPathRef.current = dbPath;

  const getMemory = useCallback((): KVMemory | null => memoryRef.current, []);

  const doRefreshFast = useCallback(async () => {
    const memory = memoryRef.current;
    if (!memory) return;
    await refreshFast(memory, dbPathRef.current, projectRoot, mountedRef, setData);
  }, [projectRoot]);

  const forceRefresh = useCallback(() => {
    void doRefreshFast();
  }, [doRefreshFast]);

  // One-time init + periodic fast refresh
  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | null = null;

    async function init() {
      try {
        const memory = await createKVMemory(dbPath);
        if (!mountedRef.current) {
          await memory.close();
          return;
        }
        memoryRef.current = memory;

        // Initial fast data load
        await refreshFast(memory, dbPath, projectRoot, mountedRef, setData);

        // Load graph once (slow)
        await refreshGraph(projectRoot, mountedRef, setData);

        // Start periodic refresh
        timer = setInterval(() => {
          if (memoryRef.current) {
            void refreshFast(memoryRef.current, dbPath, projectRoot, mountedRef, setData);
          }
        }, refreshInterval);
      } catch (err) {
        if (mountedRef.current) {
          setData((prev) => ({
            ...prev,
            loading: false,
            error: err instanceof Error ? err.message : String(err),
          }));
        }
      }
    }

    void init();

    return () => {
      mountedRef.current = false;
      if (timer) clearInterval(timer);
      if (memoryRef.current) {
        void memoryRef.current.close();
        memoryRef.current = null;
      }
    };
  }, [dbPath, projectRoot, refreshInterval]);

  return { ...data, getMemory, forceRefresh };
}

async function refreshFast(
  memory: KVMemory,
  path: string,
  projectRoot: string,
  mountedRef: React.MutableRefObject<boolean>,
  setData: React.Dispatch<React.SetStateAction<DashboardData>>,
) {
  try {
    const [stats, ids, activeEntries, readyEntries, silentEntries] = await Promise.all([
      memory.getOptimizationStats(),
      memory.list(),
      memory.query({ state: 'active' }),
      memory.query({ state: 'ready' }),
      memory.query({ state: 'silent' }),
    ]);

    // Debt tracker (open/close quickly since it's a separate db concern)
    let debts: TechDebt[] = [];
    let debtStats: DebtStats | null = null;
    try {
      const tracker = createDebtTracker(path);
      debts = await tracker.list();
      debtStats = await tracker.stats();
      await tracker.close();
    } catch {
      // Debt table may not exist yet
    }

    // Daemon status
    let daemon: DaemonStatusResult | null = null;
    try {
      const { createDaemonCommand } = await import('../../../daemon/daemon-process.js');
      const { readFileSync } = await import('node:fs');
      const { resolve } = await import('node:path');
      const { load: parseYAML } = await import('js-yaml');
      const configPath = resolve(projectRoot, '.cortex/config.yaml');
      const configContent = readFileSync(configPath, 'utf-8');
      // biome-ignore lint/suspicious/noExplicitAny: YAML returns unknown
      const config = parseYAML(configContent) as any;
      daemon = await createDaemonCommand().status(config);
    } catch {
      // Config/daemon not available
    }

    // DB file size
    let dbSizeBytes = 0;
    try {
      dbSizeBytes = statSync(path).size;
    } catch {
      // File may not exist
    }

    if (mountedRef.current) {
      setData((prev) => ({
        ...prev,
        optimizationStats: stats,
        totalEntries: ids.length,
        stateDistribution: {
          active: activeEntries.length,
          ready: readyEntries.length,
          silent: silentEntries.length,
        },
        debts,
        debtStats,
        daemon,
        dbSizeBytes,
        loading: false,
        error: null,
        lastRefresh: new Date(),
      }));
    }
  } catch (err) {
    if (mountedRef.current) {
      setData((prev) => ({
        ...prev,
        loading: false,
        error: err instanceof Error ? err.message : String(err),
      }));
    }
  }
}

async function refreshGraph(
  projectRoot: string,
  mountedRef: React.MutableRefObject<boolean>,
  setData: React.Dispatch<React.SetStateAction<DashboardData>>,
) {
  try {
    const graph = createDependencyGraph({ projectRoot });
    const analysis = await graph.analyze();
    const nodes = graph.getNodes();
    if (mountedRef.current) {
      setData((prev) => ({
        ...prev,
        graphAnalysis: analysis,
        graphNodes: nodes,
      }));
    }
  } catch {
    // Graph analysis may fail if project structure is unusual
  }
}
