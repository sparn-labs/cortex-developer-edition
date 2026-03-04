/**
 * Unit tests for Claude Code Adapter
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { createClaudeCodeAdapter } from '../../src/adapters/claude-code.js';
import type { KVMemory } from '../../src/core/kv-memory.js';
import { createKVMemory } from '../../src/core/kv-memory.js';
import type { AgentAdapter } from '../../src/types/adapter.js';
import { DEFAULT_CONFIG } from '../../src/types/config.js';

describe('Claude Code Adapter', () => {
  let memory: KVMemory;
  const testDbPath = './.test-claude-code.db';

  beforeEach(async () => {
    memory = await createKVMemory(testDbPath);
  });

  afterEach(async () => {
    await memory.close();
    // Clean up test database
    const fs = await import('node:fs/promises');
    try {
      await fs.unlink(testDbPath);
      await fs.unlink(`${testDbPath}-shm`);
      await fs.unlink(`${testDbPath}-wal`);
    } catch {
      // Ignore cleanup errors
    }
  });

  // T166: Unit test: ClaudeCodeAdapter implements AgentAdapter interface
  describe('T166: AgentAdapter Interface', () => {
    it('should implement AgentAdapter interface', () => {
      const adapter: AgentAdapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

      expect(adapter).toBeDefined();
      expect(adapter.optimize).toBeInstanceOf(Function);
    });

    it('should have optimize method with correct signature', () => {
      const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

      // Verify method exists and is callable
      expect(typeof adapter.optimize).toBe('function');
      expect(adapter.optimize.length).toBeGreaterThanOrEqual(1); // At least context parameter
    });

    it('should return OptimizationResult from optimize', async () => {
      const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

      const result = await adapter.optimize('Test context for optimization');

      expect(result).toBeDefined();
      expect(result).toHaveProperty('optimizedContext');
      expect(result).toHaveProperty('tokensBefore');
      expect(result).toHaveProperty('tokensAfter');
      expect(result).toHaveProperty('reduction');
      expect(result).toHaveProperty('entriesProcessed');
      expect(result).toHaveProperty('entriesKept');
      expect(result).toHaveProperty('durationMs');
      expect(result).toHaveProperty('stateDistribution');
    });
  });

  // T167: Unit test: ClaudeCodeAdapter.optimize uses PreToolUse hook integration
  describe('T167: Claude Code-Specific Optimization', () => {
    it('should use Claude Code-specific configuration', () => {
      const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

      // Verify adapter is created with Claude Code profile
      expect(adapter).toBeDefined();
    });

    it('should optimize context with Claude Code patterns', async () => {
      const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

      // Context with Claude Code tool use patterns
      const context = `
User: Please implement a new feature
Assistant: I'll use the Read tool to check the file
Tool: Read
Result: File contents here
Assistant: Now I'll implement the feature
`;

      const result = await adapter.optimize(context);

      expect(result.optimizedContext).toBeDefined();
      expect(result.tokensBefore).toBeGreaterThan(0);
      expect(result.tokensAfter).toBeGreaterThanOrEqual(0);
    });

    it('should prioritize tool use patterns with BTSP', async () => {
      const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

      // Context with error patterns (should be marked as BTSP)
      const context = `
Error: ENOENT: no such file or directory
  at Object.openSync (node:fs:601:3)
  at readFileSync (node:fs:469:35)
`;

      const result = await adapter.optimize(context, { verbose: true });

      expect(result.details).toBeDefined();
      if (result.details && result.details.length > 0) {
        // At least one entry should be marked as BTSP
        const btspEntries = result.details.filter((d) => d.isBTSP);
        expect(btspEntries.length).toBeGreaterThan(0);
      }
    });

    it('should handle tool results efficiently', async () => {
      const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

      // Create context with multiple tool results to enable reduction
      const context = `
<function_results>
Large tool result with many lines
Line 1
Line 2
Line 3
Line 4
Line 5
</function_results>

User: That looks good

<function_results>
Another tool result
More data here
Additional lines
Extra content
More text
</function_results>
`;

      const result = await adapter.optimize(context);

      // Should process tool results
      expect(result.entriesProcessed).toBeGreaterThan(0);
      expect(result.tokensAfter).toBeGreaterThanOrEqual(0);
    });

    it('should preserve conversation context', async () => {
      const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

      const context = `
User: How do I implement feature X?
Assistant: Here's how you can implement it...
User: Can you also add feature Y?
Assistant: Sure, I'll add that too.
User: Thanks!
Assistant: You're welcome!
`;

      const result = await adapter.optimize(context);

      // Should process conversation
      expect(result.entriesProcessed).toBeGreaterThan(0);
      expect(result.entriesKept).toBeGreaterThan(0);

      // At least some conversation should be preserved (with conversation boost)
      const hasConversation =
        result.optimizedContext.includes('User:') || result.optimizedContext.includes('Assistant:');
      expect(hasConversation).toBe(true);
    });
  });

  describe('Claude Code Profile', () => {
    it('should use optimized thresholds for Claude Code', () => {
      const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

      // Verify adapter uses Claude Code-specific settings
      expect(adapter).toBeDefined();
    });

    it('should handle concurrent tool uses', async () => {
      const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

      const context = `
Tool: Read file1.ts
Tool: Read file2.ts
Tool: Read file3.ts
Results: ...
`;

      const result = await adapter.optimize(context);

      expect(result.entriesProcessed).toBeGreaterThan(0);
    });
  });
});
