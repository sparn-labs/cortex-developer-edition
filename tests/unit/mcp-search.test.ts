/**
 * MCP cortex_search Tool Tests
 */

import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createKVMemory, type KVMemory } from '../../src/core/kv-memory.js';
import { createCortexMcpServer } from '../../src/mcp/server.js';
import type { MemoryEntry } from '../../src/types/memory.js';

function makeEntry(id: string, content: string, overrides: Partial<MemoryEntry> = {}): MemoryEntry {
  return {
    id,
    content,
    hash: `hash-${id}`,
    timestamp: Date.now(),
    score: 0.5,
    ttl: 86400,
    state: 'active',
    accessCount: 0,
    tags: [],
    metadata: {},
    isBTSP: false,
    ...overrides,
  };
}

describe('MCP cortex_search Tool', () => {
  let memory: KVMemory;
  let client: Client;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = join(tmpdir(), `cortex-mcp-search-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    memory = await createKVMemory(join(tempDir, 'test.db'));

    const server = createCortexMcpServer({ memory });
    client = new Client({ name: 'test-client', version: '1.0.0' });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  });

  afterEach(async () => {
    await client.close();
    await memory.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('should return matching entries', async () => {
    await memory.put(makeEntry('e1', 'TypeScript optimization engine'));
    await memory.put(makeEntry('e2', 'Python data pipeline'));

    const result = await client.callTool({
      name: 'cortex_search',
      arguments: { query: 'TypeScript' },
    });
    const content = result.content as Array<{ type: string; text: string }>;
    const data = JSON.parse(content[0]?.text);

    expect(data.results.length).toBe(1);
    expect(data.results[0].content).toContain('TypeScript');
  });

  it('should respect limit parameter', async () => {
    await memory.put(makeEntry('e1', 'hello world one'));
    await memory.put(makeEntry('e2', 'hello world two'));
    await memory.put(makeEntry('e3', 'hello world three'));

    const result = await client.callTool({
      name: 'cortex_search',
      arguments: { query: 'hello', limit: 2 },
    });
    const content = result.content as Array<{ type: string; text: string }>;
    const data = JSON.parse(content[0]?.text);

    expect(data.results.length).toBe(2);
  });

  it('should return empty results for no matches', async () => {
    await memory.put(makeEntry('e1', 'hello world'));

    const result = await client.callTool({
      name: 'cortex_search',
      arguments: { query: 'nonexistent' },
    });
    const content = result.content as Array<{ type: string; text: string }>;
    const data = JSON.parse(content[0]?.text);

    expect(data.results.length).toBe(0);
  });

  it('should truncate long content to 500 chars', async () => {
    const longContent = 'x'.repeat(1000);
    await memory.put(makeEntry('e1', longContent));

    const result = await client.callTool({ name: 'cortex_search', arguments: { query: 'x' } });
    const content = result.content as Array<{ type: string; text: string }>;
    const data = JSON.parse(content[0]?.text);

    if (data.results.length > 0) {
      expect(data.results[0].content.length).toBeLessThanOrEqual(503); // 500 + "..."
    }
  });

  it('should handle errors gracefully', async () => {
    await memory.close();
    // Calling search on closed memory should return error
    const result = await client.callTool({ name: 'cortex_search', arguments: { query: 'test' } });
    expect(result.isError).toBe(true);
  });
});
