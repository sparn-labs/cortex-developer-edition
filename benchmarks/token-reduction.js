#!/usr/bin/env node

/**
 * Token Reduction Benchmark
 * Measures token reduction across different context sizes.
 */

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createKVMemory, createSparsePruner, estimateTokens } from '../dist/index.js';

// Generate test context of specified size
function generateContext(tokens) {
  const wordsPerToken = 0.75; // Average ~0.75 words per token
  const words = Math.floor(tokens * wordsPerToken);

  // Generate verbose, repetitive context (optimizes well)
  const patterns = [
    'The user requested a feature to implement authentication',
    'Error: ENOENT: no such file or directory',
    'Running tests... ✓ All tests passed',
    'Git status shows modified files in src/ directory',
    'Claude Code is analyzing the codebase structure',
    'Installing npm dependencies... Done',
    'Building TypeScript project with tsup...',
    'Linting code with biome... No issues found',
    'Optimization complete: 1000 → 250 tokens (75% reduction)',
    'Memory consolidation freed 45% of database space',
  ];

  let content = '';
  let wordCount = 0;

  while (wordCount < words) {
    const pattern = patterns[Math.floor(Math.random() * patterns.length)];
    content += `${pattern}\n`;
    wordCount += pattern.split(' ').length;
  }

  return content;
}

// Run benchmark for a specific size
async function benchmarkSize(name, tokens) {
  console.log(`\n📊 Benchmarking ${name} (${tokens.toLocaleString()} tokens)...`);

  // Setup
  const tmpDir = join(process.cwd(), '.bench-tmp');
  rmSync(tmpDir, { recursive: true, force: true });
  mkdirSync(tmpDir, { recursive: true });

  const dbPath = join(tmpDir, 'memory.db');
  const memory = await createKVMemory(dbPath);

  // Generate context
  const context = generateContext(tokens);
  const inputPath = join(tmpDir, 'input.txt');
  const outputPath = join(tmpDir, 'output.txt');
  writeFileSync(inputPath, context, 'utf-8');

  // Run optimization using library API
  const startTime = Date.now();

  // Initialize pruner
  const pruner = createSparsePruner();

  // Prune context (keep top 5%)
  const pruneResult = pruner.prune(context, 5);

  // Calculate results
  const tokensBefore = estimateTokens(context);
  const optimizedContext = pruneResult.prunedContext;
  const tokensAfter = estimateTokens(optimizedContext);
  const duration = Date.now() - startTime;

  // Write output
  writeFileSync(outputPath, optimizedContext, 'utf-8');

  const result = {
    tokensBefore,
    tokensAfter,
    reduction: (tokensBefore - tokensAfter) / tokensBefore,
  };

  // Cleanup
  await memory.close();
  rmSync(tmpDir, { recursive: true, force: true });

  return {
    name,
    tokens_before: result.tokensBefore,
    tokens_after: result.tokensAfter,
    reduction: result.reduction,
    duration_ms: duration,
  };
}

// Main benchmark runner
async function runBenchmark() {
  console.log('🧠 Sparn Token Reduction Benchmark\n');
  console.log('━'.repeat(60));

  const results = {
    timestamp: new Date().toISOString(),
    benchmark: 'token-reduction',
    results: {},
  };

  // Run benchmarks
  results.results.small = await benchmarkSize('Small', 1000);
  results.results.medium = await benchmarkSize('Medium', 10000);
  results.results.large = await benchmarkSize('Large', 100000);

  // Display results
  console.log(`\n${'━'.repeat(60)}`);
  console.log('📈 Results Summary\n');

  for (const [_size, data] of Object.entries(results.results)) {
    const reduction = (data.reduction * 100).toFixed(1);
    console.log(`${data.name}:`);
    console.log(`  Before: ${data.tokens_before.toLocaleString()} tokens`);
    console.log(`  After:  ${data.tokens_after.toLocaleString()} tokens`);
    console.log(`  Reduction: ${reduction}%`);
    console.log(`  Duration: ${data.duration_ms}ms`);
    console.log();
  }

  // Save results
  const resultsDir = join(process.cwd(), 'benchmarks', 'results');
  mkdirSync(resultsDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const resultsPath = join(resultsDir, `token-reduction-${timestamp}.json`);
  writeFileSync(resultsPath, JSON.stringify(results, null, 2));

  console.log(`✓ Results saved to ${resultsPath}\n`);
  console.log('━'.repeat(60));
}

// Run
runBenchmark().catch(console.error);
