/**
 * Context Parser Tests
 */

import { describe, expect, it } from 'vitest';
import {
  createEntry,
  parseClaudeCodeContext,
  parseGenericContext,
  parseJSONLContext,
  parseJSONLLine,
} from '../../src/utils/context-parser.js';

describe('Context Parser', () => {
  describe('createEntry', () => {
    it('should create conversation entry with correct initial score', () => {
      const entry = createEntry('User: Hello', 'conversation', Date.now());

      expect(entry.content).toBe('User: Hello');
      expect(entry.score).toBe(0.8);
      expect(entry.state).toBe('active');
      expect(entry.tags).toContain('conversation');
      expect(entry.isBTSP).toBe(false);
    });

    it('should create tool entry with correct initial score', () => {
      const entry = createEntry('<function_calls>', 'tool', Date.now());

      expect(entry.score).toBe(0.7);
      expect(entry.state).toBe('active'); // score >= 0.7 is active
      expect(entry.tags).toContain('tool');
    });

    it('should create result entry with correct initial score', () => {
      const entry = createEntry('Result data', 'result', Date.now());

      expect(entry.score).toBe(0.4);
      expect(entry.state).toBe('ready');
      expect(entry.tags).toContain('result');
    });

    it('should generate unique IDs for each entry', () => {
      const entry1 = createEntry('Test 1', 'conversation', Date.now());
      const entry2 = createEntry('Test 2', 'conversation', Date.now());

      expect(entry1.id).not.toBe(entry2.id);
    });
  });

  describe('parseClaudeCodeContext', () => {
    it('should parse conversation turns', () => {
      const context = `User: Hello, how are you?
Assistant: I'm doing well, thank you!`;

      const entries = parseClaudeCodeContext(context);

      expect(entries.length).toBeGreaterThanOrEqual(2);
      expect(entries[0]?.content).toContain('User: Hello');
      expect(entries[0]?.tags).toContain('conversation');
    });

    it('should parse tool calls', () => {
      const context = `<function_calls>
<invoke name="read_file">
  <parameter name="path">test.ts</parameter>
</invoke>
</function_calls>`;

      const entries = parseClaudeCodeContext(context);

      expect(entries.length).toBeGreaterThan(0);
      expect(entries[0]?.tags).toContain('tool');
    });

    it('should filter empty entries', () => {
      const context = 'User: Hello\n\n\n\nAssistant: Hi';

      const entries = parseClaudeCodeContext(context);

      // Should only have non-empty entries
      entries.forEach((entry) => {
        expect(entry.content.trim().length).toBeGreaterThan(0);
      });
    });
  });

  describe('parseJSONLLine', () => {
    it('should parse valid JSON line', () => {
      const msg = parseJSONLLine('{"role":"user","content":"Hello"}');
      expect(msg).not.toBeNull();
      expect(msg?.role).toBe('user');
      expect(msg?.content).toBe('Hello');
    });

    it('should return null for empty line', () => {
      expect(parseJSONLLine('')).toBeNull();
      expect(parseJSONLLine('   ')).toBeNull();
    });

    it('should return null for malformed JSON', () => {
      expect(parseJSONLLine('{invalid json}')).toBeNull();
      expect(parseJSONLLine('not json at all')).toBeNull();
    });
  });

  describe('parseJSONLContext', () => {
    it('should parse user/assistant messages', () => {
      const context = [
        '{"role":"user","content":"Hello world"}',
        '{"role":"assistant","content":"Hi there!"}',
      ].join('\n');

      const entries = parseJSONLContext(context);
      expect(entries.length).toBe(2);
      expect(entries[0]?.content).toBe('Hello world');
      expect(entries[0]?.tags).toContain('conversation');
      expect(entries[1]?.content).toBe('Hi there!');
      expect(entries[1]?.tags).toContain('conversation');
    });

    it('should handle content arrays with text blocks', () => {
      const context = JSON.stringify({
        role: 'assistant',
        content: [
          { type: 'text', text: 'First part' },
          { type: 'text', text: 'Second part' },
        ],
      });

      const entries = parseJSONLContext(context);
      expect(entries.length).toBe(1);
      expect(entries[0]?.content).toContain('First part');
      expect(entries[0]?.content).toContain('Second part');
    });

    it('should detect tool_use blocks', () => {
      const context = JSON.stringify({
        role: 'assistant',
        content: [
          { type: 'text', text: 'Let me read that file' },
          { type: 'tool_use', name: 'read_file', input: { path: 'test.ts' } },
        ],
      });

      const entries = parseJSONLContext(context);
      expect(entries.length).toBe(1);
      expect(entries[0]?.tags).toContain('tool');
    });

    it('should detect tool_result blocks', () => {
      const context = JSON.stringify({
        role: 'user',
        content: [{ type: 'tool_result', content: 'File contents here' }],
      });

      const entries = parseJSONLContext(context);
      expect(entries.length).toBe(1);
      expect(entries[0]?.tags).toContain('result');
    });

    it('should filter empty content', () => {
      const context = ['{"role":"user","content":""}', '{"role":"user","content":"Hello"}'].join(
        '\n',
      );

      const entries = parseJSONLContext(context);
      expect(entries.length).toBe(1);
    });

    it('should handle malformed lines gracefully', () => {
      const context = [
        '{"role":"user","content":"Hello"}',
        '{invalid json}',
        '{"role":"assistant","content":"World"}',
      ].join('\n');

      const entries = parseJSONLContext(context);
      expect(entries.length).toBe(2);
    });

    it('should assign correct scores: conversation 0.8, tool 0.7, result 0.4', () => {
      const userMsg = '{"role":"user","content":"Hello"}';
      const toolMsg = JSON.stringify({
        role: 'assistant',
        content: [{ type: 'tool_use', name: 'read', input: {} }],
      });
      const resultMsg = JSON.stringify({
        role: 'user',
        content: [{ type: 'tool_result', content: 'result data' }],
      });

      const context = [userMsg, toolMsg, resultMsg].join('\n');
      const entries = parseJSONLContext(context);

      expect(entries[0]?.score).toBe(0.8); // conversation
      expect(entries[1]?.score).toBe(0.7); // tool
      expect(entries[2]?.score).toBe(0.4); // result
    });
  });

  describe('parseClaudeCodeContext JSONL auto-detect', () => {
    it('should auto-detect JSONL when first line starts with {', () => {
      const context = '{"role":"user","content":"Hello from JSONL"}';
      const entries = parseClaudeCodeContext(context);

      expect(entries.length).toBe(1);
      expect(entries[0]?.content).toBe('Hello from JSONL');
    });

    it('should use text parser when first line starts with User:', () => {
      const context = 'User: Hello from text format';
      const entries = parseClaudeCodeContext(context);

      expect(entries.length).toBe(1);
      expect(entries[0]?.content).toContain('User: Hello');
    });

    it('should fall back to text parser when JSONL parse returns empty', () => {
      // First line starts with { but content is empty -> JSONL returns 0 entries -> fallback
      const context = '{"role":"user","content":""}\nUser: Fallback text';
      const entries = parseClaudeCodeContext(context);

      expect(entries.length).toBeGreaterThan(0);
    });
  });

  describe('parseGenericContext', () => {
    it('should split on double newlines', () => {
      const context = 'First paragraph\n\nSecond paragraph\n\nThird paragraph';

      const entries = parseGenericContext(context);

      expect(entries.length).toBe(3);
      expect(entries[0]?.content).toBe('First paragraph');
      expect(entries[1]?.content).toBe('Second paragraph');
    });

    it('should filter empty blocks', () => {
      const context = 'First\n\n\n\nSecond';

      const entries = parseGenericContext(context);

      expect(entries.length).toBe(2);
    });
  });
});
