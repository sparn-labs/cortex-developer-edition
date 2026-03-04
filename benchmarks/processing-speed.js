#!/usr/bin/env node

/**
 * Processing Speed Benchmark
 * Measures optimization speed across different context sizes.
 */

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import {
  createConfidenceStates,
  createEngramScorer,
  createKVMemory,
  createSparsePruner,
  DEFAULT_CONFIG,
} from '../dist/index.js';

// Generate test entries
function generateEntries(count) {
  const entries = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    entries.push({
      id: `entry-${i}`,
      content: `This is test entry ${i} with some content to optimize`,
      hash: `hash-${i}`,
      timestamp: now - i * 1000,
      score: 0.5,
      ttl: 3600,
      state: 'ready',
      accessCount: 0,
      tags: ['test'],
      metadata: {},
      isBTSP: false,
    });
  }

  return entries;
}

// Benchmark a specific operation
async function benchmarkOperation(name, operation, iterations = 100) {
  const times = [];

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await operation();
    const end = performance.now();
    times.push(end - start);
  }

  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  const min = Math.min(...times);
  const max = Math.max(...times);
  const p50 = times.sort((a, b) => a - b)[Math.floor(times.length * 0.5)];
  const p95 = times.sort((a, b) => a - b)[Math.floor(times.length * 0.95)];

  return { name, avg, min, max, p50, p95 };
}

// Main benchmark runner
async function runBenchmark() {
  console.log('⚡ Sparn Processing Speed Benchmark\n');
  console.log('━'.repeat(60));

  const results = {
    timestamp: new Date().toISOString(),
    benchmark: 'processing-speed',
    results: {},
  };

  // Setup
  const tmpDir = join(process.cwd(), '.bench-tmp');
  rmSync(tmpDir, { recursive: true, force: true });
  mkdirSync(tmpDir, { recursive: true });

  const dbPath = join(tmpDir, 'memory.db');
  const memory = await createKVMemory(dbPath);

  // Benchmark pruning (small)
  console.log('\n📊 Benchmarking sparse pruning (100 entries)...');
  const smallEntries = generateEntries(100);
  const pruner = createSparsePruner({ threshold: 5 });
  results.results.pruning_small = await benchmarkOperation(
    'Sparse Pruning (100 entries)',
    () => pruner.prune(smallEntries),
    100,
  );

  // Benchmark pruning (medium)
  console.log('📊 Benchmarking sparse pruning (1000 entries)...');
  const mediumEntries = generateEntries(1000);
  results.results.pruning_medium = await benchmarkOperation(
    'Sparse Pruning (1000 entries)',
    () => pruner.prune(mediumEntries),
    50,
  );

  // Benchmark scoring
  console.log('📊 Benchmarking engram scoring (100 entries)...');
  const scorer = createEngramScorer(DEFAULT_CONFIG.decay);
  results.results.scoring = await benchmarkOperation(
    'Engram Scoring (100 entries)',
    () => {
      for (const entry of smallEntries) {
        scorer.score(entry);
      }
    },
    100,
  );

  // Benchmark state classification
  console.log('📊 Benchmarking state classification (100 entries)...');
  const states = createConfidenceStates(DEFAULT_CONFIG.states);
  results.results.states = await benchmarkOperation(
    'State Classification (100 entries)',
    () => {
      for (const entry of smallEntries) {
        states.classify(entry);
      }
    },
    100,
  );

  // Benchmark database operations
  console.log('📊 Benchmarking database put (100 entries)...');
  results.results.db_put = await benchmarkOperation(
    'Database Put (single entry)',
    async () => {
      await memory.put(smallEntries[0]);
    },
    100,
  );

  console.log('📊 Benchmarking database query (100 entries)...');
  // Prepopulate
  for (const entry of smallEntries.slice(0, 10)) {
    await memory.put(entry);
  }
  results.results.db_query = await benchmarkOperation(
    'Database Query (all entries)',
    async () => {
      await memory.query({});
    },
    100,
  );

  // Cleanup
  await memory.close();
  rmSync(tmpDir, { recursive: true, force: true });

  // Display results
  console.log(`\n${'━'.repeat(60)}`);
  console.log('📈 Results Summary\n');

  for (const data of Object.values(results.results)) {
    console.log(`${data.name}:`);
    console.log(`  Average: ${data.avg.toFixed(2)}ms`);
    console.log(`  Min:     ${data.min.toFixed(2)}ms`);
    console.log(`  Max:     ${data.max.toFixed(2)}ms`);
    console.log(`  p50:     ${data.p50.toFixed(2)}ms`);
    console.log(`  p95:     ${data.p95.toFixed(2)}ms`);
    console.log();
  }

  // Save results
  const resultsDir = join(process.cwd(), 'benchmarks', 'results');
  mkdirSync(resultsDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const resultsPath = join(resultsDir, `processing-speed-${timestamp}.json`);
  writeFileSync(resultsPath, JSON.stringify(results, null, 2));

  console.log(`✓ Results saved to ${resultsPath}\n`);
  console.log('━'.repeat(60));
}

// Run
runBenchmark().catch(console.error);
