#!/usr/bin/env node

/**
 * Run All Benchmarks
 * Executes all benchmark suites and generates a summary report.
 */

import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

// Run a single benchmark script
function runBenchmark(script) {
  return new Promise((resolve, reject) => {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Running ${script}...`);
    console.log('='.repeat(60));

    const child = spawn('node', [script], {
      stdio: 'inherit',
      cwd: process.cwd(),
    });

    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Benchmark ${script} failed with code ${code}`));
      }
    });

    child.on('error', reject);
  });
}

// Main runner
async function main() {
  console.log('🧠 Running All Sparn Benchmarks\n');
  console.log('This will take a few minutes...\n');

  const startTime = Date.now();

  try {
    // Run benchmarks
    await runBenchmark('benchmarks/token-reduction.js');
    await runBenchmark('benchmarks/processing-speed.js');

    const duration = Date.now() - startTime;

    // Generate summary
    console.log(`\n${'='.repeat(60)}`);
    console.log('✓ All Benchmarks Complete!');
    console.log('='.repeat(60));
    console.log(`\nTotal duration: ${(duration / 1000).toFixed(1)}s`);
    console.log(`\nResults saved to benchmarks/results/`);
    console.log('\nTo view results:');
    console.log('  ls -la benchmarks/results/');
    console.log('  cat benchmarks/results/<filename>.json\n');

    // Create summary
    const summary = {
      timestamp: new Date().toISOString(),
      duration_ms: duration,
      benchmarks: ['token-reduction', 'processing-speed'],
      status: 'complete',
    };

    const resultsDir = join(process.cwd(), 'benchmarks', 'results');
    mkdirSync(resultsDir, { recursive: true });
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const summaryPath = join(resultsDir, `summary-${timestamp}.json`);
    writeFileSync(summaryPath, JSON.stringify(summary, null, 2));
  } catch (error) {
    console.error('\n✗ Benchmark failed:', error.message);
    process.exit(1);
  }
}

main().catch(console.error);
