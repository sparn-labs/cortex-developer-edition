/**
 * Context Parser - Shared utilities for parsing agent contexts into memory entries
 *
 * Extracted from claude-code adapter to enable reuse across:
 * - Adapters (claude-code, generic)
 * - Real-time pipeline (streaming context)
 * - Hooks (pre-prompt, post-tool-result)
 */

import { randomUUID } from 'node:crypto';
import type { MemoryEntry } from '../types/memory.js';
import { hashContent } from './hash.js';

/**
 * Block type classification for Claude Code context
 */
export type BlockType = 'conversation' | 'tool' | 'result' | 'other';

/**
 * Parse Claude Code context into memory entries
 * Handles conversation turns, tool uses, and results
 * @param context - Raw context string
 * @returns Array of memory entries
 */
export function parseClaudeCodeContext(context: string): MemoryEntry[] {
  // Auto-detect JSONL format: check if first non-empty line starts with '{'
  const firstNonEmpty = context.split('\n').find((line) => line.trim().length > 0);
  if (firstNonEmpty?.trim().startsWith('{')) {
    const jsonlEntries = parseJSONLContext(context);
    if (jsonlEntries.length > 0) return jsonlEntries;
    // Fall through to text parser if JSONL parse returned empty
  }

  const entries: MemoryEntry[] = [];
  const now = Date.now();

  // Split by conversation turns and tool boundaries
  const lines = context.split('\n');
  let currentBlock: string[] = [];
  let blockType: BlockType = 'other';

  for (const line of lines) {
    const trimmed = line.trim();

    // Detect conversation turns
    if (trimmed.startsWith('User:') || trimmed.startsWith('Assistant:')) {
      if (currentBlock.length > 0) {
        entries.push(createEntry(currentBlock.join('\n'), blockType, now));
        currentBlock = [];
      }
      blockType = 'conversation';
      currentBlock.push(line);
    }
    // Detect tool calls
    else if (
      trimmed.includes('<function_calls>') ||
      trimmed.includes('<invoke>') ||
      trimmed.includes('<tool_use>')
    ) {
      if (currentBlock.length > 0) {
        entries.push(createEntry(currentBlock.join('\n'), blockType, now));
        currentBlock = [];
      }
      blockType = 'tool';
      currentBlock.push(line);
    }
    // Detect tool results
    else if (trimmed.includes('<function_results>') || trimmed.includes('</function_results>')) {
      if (currentBlock.length > 0 && blockType !== 'result') {
        entries.push(createEntry(currentBlock.join('\n'), blockType, now));
        currentBlock = [];
      }
      blockType = 'result';
      currentBlock.push(line);
    }
    // Continue current block
    else if (currentBlock.length > 0) {
      currentBlock.push(line);
    }
    // Start new block if line has content
    else if (trimmed.length > 0) {
      currentBlock.push(line);
      blockType = 'other';
    }
  }

  // Add final block
  if (currentBlock.length > 0) {
    entries.push(createEntry(currentBlock.join('\n'), blockType, now));
  }

  return entries.filter((e) => e.content.trim().length > 0);
}

/**
 * Create a memory entry from a content block
 * @param content - Block content
 * @param type - Block type
 * @param baseTime - Base timestamp
 * @returns Memory entry
 */
export function createEntry(content: string, type: BlockType, baseTime: number): MemoryEntry {
  const tags: string[] = [type];

  // Assign initial score based on type
  let initialScore = 0.5;
  if (type === 'conversation') initialScore = 0.8; // Prioritize conversation
  if (type === 'tool') initialScore = 0.7; // Tool calls are important
  if (type === 'result') initialScore = 0.4; // Results can be verbose

  return {
    id: randomUUID(),
    content,
    hash: hashContent(content),
    timestamp: baseTime,
    score: initialScore,
    state: initialScore >= 0.7 ? 'active' : initialScore >= 0.3 ? 'ready' : 'silent',
    ttl: 24 * 3600, // 24 hours default
    accessCount: 0,
    tags,
    metadata: { type },
    isBTSP: false,
  };
}

/**
 * Parsed JSONL message structure
 */
export interface JSONLMessage {
  role?: string;
  content?:
    | string
    | Array<{
        type: string;
        text?: string;
        name?: string;
        input?: unknown;
        content?: string | Array<{ type: string; text?: string }>;
      }>;
  type?: string;
  tool_use?: { name: string; input: unknown };
  tool_result?: { content: string | Array<{ type: string; text?: string }> };
}

/**
 * Parse a single JSONL line into a message
 * @param line - Single JSON line
 * @returns Parsed message or null on failure
 */
export function parseJSONLLine(line: string): JSONLMessage | null {
  const trimmed = line.trim();
  if (trimmed.length === 0) return null;

  try {
    return JSON.parse(trimmed) as JSONLMessage;
  } catch {
    return null;
  }
}

/**
 * Extract text content from a JSONL message content field
 */
function extractContent(content: JSONLMessage['content']): string {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((block) => {
        if (block.type === 'text' && block.text) return block.text;
        if (block.type === 'tool_use' && block.name) return `[tool_use: ${block.name}]`;
        if (block.type === 'tool_result') {
          if (typeof block.content === 'string') return block.content;
          if (Array.isArray(block.content)) {
            return block.content
              .filter((c) => c.type === 'text' && c.text)
              .map((c) => c.text)
              .join('\n');
          }
        }
        return '';
      })
      .filter((s) => s.length > 0)
      .join('\n');
  }
  return '';
}

/**
 * Classify a JSONL message into a BlockType
 */
function classifyJSONLMessage(msg: JSONLMessage): BlockType {
  // Check for tool_use blocks in content array
  if (Array.isArray(msg.content)) {
    const hasToolUse = msg.content.some((b) => b.type === 'tool_use');
    const hasToolResult = msg.content.some((b) => b.type === 'tool_result');
    if (hasToolUse) return 'tool';
    if (hasToolResult) return 'result';
  }

  if (msg.type === 'tool_use' || msg.tool_use) return 'tool';
  if (msg.type === 'tool_result' || msg.tool_result) return 'result';

  if (msg.role === 'user' || msg.role === 'assistant') return 'conversation';

  return 'other';
}

/**
 * Parse JSONL context into memory entries
 * Handles Claude Code transcript format (one JSON object per line)
 *
 * @param context - Raw JSONL context string
 * @returns Array of memory entries, or empty array if parsing fails
 */
export function parseJSONLContext(context: string): MemoryEntry[] {
  const entries: MemoryEntry[] = [];
  const now = Date.now();
  const lines = context.split('\n');

  for (const line of lines) {
    const msg = parseJSONLLine(line);
    if (!msg) continue;

    const content = extractContent(msg.content);
    if (!content || content.trim().length === 0) continue;

    const blockType = classifyJSONLMessage(msg);
    entries.push(createEntry(content, blockType, now));
  }

  return entries;
}

/**
 * Parse generic context (fallback for non-Claude-Code agents)
 * Splits on double newlines, treats as paragraphs
 * @param context - Raw context string
 * @returns Array of memory entries
 */
export function parseGenericContext(context: string): MemoryEntry[] {
  const entries: MemoryEntry[] = [];
  const now = Date.now();

  // Split on double newlines (paragraph boundaries)
  const blocks = context.split(/\n\n+/);

  for (const block of blocks) {
    const trimmed = block.trim();
    if (trimmed.length === 0) continue;

    entries.push(createEntry(trimmed, 'other', now));
  }

  return entries;
}
