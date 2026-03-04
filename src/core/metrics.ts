/**
 * Metrics and Telemetry System
 *
 * Tracks performance metrics and optimization statistics:
 * - Optimization duration and throughput
 * - Token savings and reduction rates
 * - Memory usage and cache hit rates
 * - Daemon uptime and session counts
 */

export interface OptimizationMetric {
  timestamp: number;
  duration: number;
  tokensBefore: number;
  tokensAfter: number;
  entriesProcessed: number;
  entriesKept: number;
  cacheHitRate: number;
  memoryUsage: number;
}

export interface DaemonMetric {
  startTime: number;
  sessionsWatched: number;
  totalOptimizations: number;
  totalTokensSaved: number;
  averageLatency: number;
  memoryUsage: number;
}

export interface MetricsSnapshot {
  timestamp: number;
  optimization: {
    totalRuns: number;
    totalDuration: number;
    totalTokensSaved: number;
    averageReduction: number;
    p50Latency: number;
    p95Latency: number;
    p99Latency: number;
  };
  cache: {
    hitRate: number;
    totalHits: number;
    totalMisses: number;
    size: number;
  };
  daemon: {
    uptime: number;
    sessionsWatched: number;
    memoryUsage: number;
  };
}

export interface MetricsCollector {
  /**
   * Record an optimization metric
   */
  recordOptimization(metric: OptimizationMetric): void;

  /**
   * Update daemon metrics
   */
  updateDaemon(metric: Partial<DaemonMetric>): void;

  /**
   * Get current metrics snapshot
   */
  getSnapshot(): MetricsSnapshot;

  /**
   * Export metrics as JSON
   */
  export(): string;

  /**
   * Reset all metrics
   */
  reset(): void;
}

/**
 * Create a metrics collector instance
 */
export function createMetricsCollector(): MetricsCollector {
  const optimizations: OptimizationMetric[] = [];
  let daemonMetrics: DaemonMetric = {
    startTime: Date.now(),
    sessionsWatched: 0,
    totalOptimizations: 0,
    totalTokensSaved: 0,
    averageLatency: 0,
    memoryUsage: 0,
  };

  let cacheHits = 0;
  let cacheMisses = 0;

  function recordOptimization(metric: OptimizationMetric): void {
    optimizations.push(metric);

    // Update daemon totals
    daemonMetrics.totalOptimizations++;
    daemonMetrics.totalTokensSaved += metric.tokensBefore - metric.tokensAfter;

    // Update cache stats
    if (metric.cacheHitRate > 0) {
      const hits = Math.round(metric.entriesProcessed * metric.cacheHitRate);
      cacheHits += hits;
      cacheMisses += metric.entriesProcessed - hits;
    }

    // Update average latency (moving average)
    daemonMetrics.averageLatency =
      (daemonMetrics.averageLatency * (daemonMetrics.totalOptimizations - 1) + metric.duration) /
      daemonMetrics.totalOptimizations;

    // Keep only last 1000 metrics in memory
    if (optimizations.length > 1000) {
      optimizations.shift();
    }
  }

  function updateDaemon(metric: Partial<DaemonMetric>): void {
    daemonMetrics = {
      ...daemonMetrics,
      ...metric,
    };
  }

  function calculatePercentile(sortedValues: number[], percentile: number): number {
    if (sortedValues.length === 0) return 0;
    const index = Math.ceil((percentile / 100) * sortedValues.length) - 1;
    return sortedValues[index] || 0;
  }

  function getSnapshot(): MetricsSnapshot {
    const totalRuns = optimizations.length;
    const totalDuration = optimizations.reduce((sum, m) => sum + m.duration, 0);
    const totalTokensSaved = optimizations.reduce(
      (sum, m) => sum + (m.tokensBefore - m.tokensAfter),
      0,
    );

    const totalTokensBefore = optimizations.reduce((sum, m) => sum + m.tokensBefore, 0);
    const averageReduction = totalTokensBefore > 0 ? totalTokensSaved / totalTokensBefore : 0;

    // Sort durations once, reuse for all percentile calculations
    const sortedDurations = optimizations.map((m) => m.duration).sort((a, b) => a - b);

    const totalCacheQueries = cacheHits + cacheMisses;
    const hitRate = totalCacheQueries > 0 ? cacheHits / totalCacheQueries : 0;

    return {
      timestamp: Date.now(),
      optimization: {
        totalRuns,
        totalDuration,
        totalTokensSaved,
        averageReduction,
        p50Latency: calculatePercentile(sortedDurations, 50),
        p95Latency: calculatePercentile(sortedDurations, 95),
        p99Latency: calculatePercentile(sortedDurations, 99),
      },
      cache: {
        hitRate,
        totalHits: cacheHits,
        totalMisses: cacheMisses,
        size: optimizations.reduce((sum, m) => sum + m.entriesKept, 0),
      },
      daemon: {
        uptime: Date.now() - daemonMetrics.startTime,
        sessionsWatched: daemonMetrics.sessionsWatched,
        memoryUsage: daemonMetrics.memoryUsage,
      },
    };
  }

  function exportMetrics(): string {
    return JSON.stringify(getSnapshot(), null, 2);
  }

  function reset(): void {
    optimizations.length = 0;
    cacheHits = 0;
    cacheMisses = 0;
    daemonMetrics = {
      startTime: Date.now(),
      sessionsWatched: 0,
      totalOptimizations: 0,
      totalTokensSaved: 0,
      averageLatency: 0,
      memoryUsage: 0,
    };
  }

  return {
    recordOptimization,
    updateDaemon,
    getSnapshot,
    export: exportMetrics,
    reset,
  };
}

// Global metrics instance
let globalMetrics: MetricsCollector | null = null;

/**
 * Get or create the global metrics collector
 */
export function getMetrics(): MetricsCollector {
  if (!globalMetrics) {
    globalMetrics = createMetricsCollector();
  }
  return globalMetrics;
}
