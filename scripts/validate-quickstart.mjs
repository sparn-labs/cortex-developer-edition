#!/usr/bin/env node
/**
 * Quickstart Validation Script (Node.js)
 * Tests all examples from quickstart.md to ensure they work
 */

import { spawn } from 'node:child_process';
import { access, mkdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Colors
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  reset: '\x1b[0m',
};

let testsPassed = 0;
let testsFailed = 0;

// Helper to run command
async function runCommand(command, args = [], cwd = process.cwd()) {
  return new Promise((resolve) => {
    const proc = spawn(command, args, {
      cwd,
      stdio: 'pipe',
      shell: true,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      resolve({
        success: code === 0,
        stdout,
        stderr,
        exitCode: code,
      });
    });

    proc.on('error', () => {
      resolve({
        success: false,
        stdout,
        stderr,
        exitCode: -1,
      });
    });
  });
}

// Helper to run test
async function runTest(name, testFn) {
  process.stdout.write(`Testing: ${name}... `);

  try {
    const result = await testFn();
    if (result) {
      console.log(`${colors.green}✓ PASS${colors.reset}`);
      testsPassed++;
    } else {
      console.log(`${colors.red}✗ FAIL${colors.reset}`);
      testsFailed++;
    }
  } catch (error) {
    console.log(`${colors.red}✗ FAIL${colors.reset} (${error.message})`);
    testsFailed++;
  }
}

// Helper to check file exists
async function fileExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  console.log('🧪 Validating Quickstart Examples...\n');

  const rootDir = join(__dirname, '..');
  const testDir = join(rootDir, `.test-quickstart-${Date.now()}`);
  const cliPath = join(rootDir, 'dist', 'cli', 'index.js');

  // Check if build exists
  console.log('📦 Checking build...');
  if (!(await fileExists(join(rootDir, 'dist')))) {
    console.log(`${colors.yellow}⚠ Build not found, please run: npm run build${colors.reset}\n`);
    process.exit(1);
  }
  console.log('');

  // Create test directory
  await mkdir(testDir, { recursive: true });

  console.log('🧪 Running Quickstart Validation Tests...\n');

  try {
    // Test 1: Init command
    await runTest('sparn init', async () => {
      const result = await runCommand('node', [cliPath, 'init', '--force'], testDir);
      return result.success;
    });

    // Test 2: Config file created
    await runTest('config.yaml created', async () => {
      return await fileExists(join(testDir, '.sparn', 'config.yaml'));
    });

    // Test 3: Database created
    await runTest('memory.db created', async () => {
      return await fileExists(join(testDir, '.sparn', 'memory.db'));
    });

    // Test 4: Config get
    await runTest('sparn config get', async () => {
      const result = await runCommand(
        'node',
        [cliPath, 'config', 'get', 'pruning.threshold'],
        testDir,
      );
      return result.success;
    });

    // Test 5: Config set
    await runTest('sparn config set', async () => {
      const result = await runCommand(
        'node',
        [cliPath, 'config', 'set', 'pruning.threshold', '10'],
        testDir,
      );
      return result.success;
    });

    // Test 6: Create sample context
    const testContext = `Sample context line 1
Sample context line 2
Error: Test error message
Sample context line 3
Sample context line 4`;
    await writeFile(join(testDir, 'test-context.txt'), testContext);

    // Test 7: Optimize from file
    await runTest('sparn optimize --input', async () => {
      const result = await runCommand(
        'node',
        [cliPath, 'optimize', '--input', 'test-context.txt', '--output', 'optimized.txt'],
        testDir,
      );
      return result.success;
    });

    // Test 8: Optimized output created
    await runTest('optimized output created', async () => {
      return await fileExists(join(testDir, 'optimized.txt'));
    });

    // Test 9: Stats command
    await runTest('sparn stats', async () => {
      const result = await runCommand('node', [cliPath, 'stats'], testDir);
      return result.success;
    });

    // Test 10: Stats with JSON
    await runTest('sparn stats --json', async () => {
      const result = await runCommand('node', [cliPath, 'stats', '--json'], testDir);
      return result.success;
    });

    // Test 11: Consolidate command
    await runTest('sparn consolidate', async () => {
      const result = await runCommand('node', [cliPath, 'consolidate'], testDir);
      return result.success;
    });

    // Test 12: Relay command
    await runTest('sparn relay echo', async () => {
      const result = await runCommand('node', [cliPath, 'relay', 'echo', 'test'], testDir);
      return result.success;
    });

    // Test 13: Help flag
    await runTest('sparn --help', async () => {
      const result = await runCommand('node', [cliPath, '--help'], testDir);
      return result.success;
    });

    // Test 14: Version flag
    await runTest('sparn --version', async () => {
      const result = await runCommand('node', [cliPath, '--version'], testDir);
      return result.success;
    });
  } finally {
    // Cleanup
    try {
      await rm(testDir, { recursive: true, force: true });
    } catch (e) {
      console.warn(`Warning: Could not clean up test directory: ${e.message}`);
    }
  }

  // Results
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📊 Quickstart Validation Results');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`Tests Passed: ${colors.green}${testsPassed}${colors.reset}`);
  console.log(`Tests Failed: ${colors.red}${testsFailed}${colors.reset}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  if (testsFailed === 0) {
    console.log(`${colors.green}✨ All tests passed! Quickstart is valid.${colors.reset}`);
    process.exit(0);
  } else {
    console.log(`${colors.red}⚠ Some tests failed. Check the output above.${colors.reset}`);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
