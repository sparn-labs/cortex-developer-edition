/**
 * Post-tool compression tests — validates all compression strategies
 * introduced/improved in v1.3.0
 */

import { describe, expect, it } from 'vitest';
import {
  getThreshold,
  type SessionStats,
  summarizeBash,
  summarizeFileRead,
  summarizeGlob,
  summarizeSearch,
  summarizeWebFetch,
  summarizeWebSearch,
} from '../../../src/hooks/post-tool-result.js';

// ─── getThreshold (adaptive) ──────────────────────────────────────

describe('getThreshold', () => {
  const baseStats = (totalTokensBefore: number): SessionStats => ({
    sessionId: 'test',
    outputsCompressed: 0,
    totalTokensBefore,
    totalTokensAfter: 0,
    lastUpdated: Date.now(),
    perTool: {},
  });

  it('should return per-tool base threshold for small sessions', () => {
    const stats = baseStats(0);
    expect(getThreshold('Bash', stats)).toBe(2000);
    expect(getThreshold('Read', stats)).toBe(2500);
    expect(getThreshold('Grep', stats)).toBe(2000);
    expect(getThreshold('Glob', stats)).toBe(1500);
    expect(getThreshold('WebFetch', stats)).toBe(1500);
    expect(getThreshold('WebSearch', stats)).toBe(1000);
  });

  it('should return BASE_THRESHOLD for unknown tools', () => {
    expect(getThreshold('UnknownTool', baseStats(0))).toBe(3000);
  });

  it('should apply 0.75x multiplier at >100K tokens', () => {
    const stats = baseStats(150000);
    expect(getThreshold('Bash', stats)).toBe(1500); // 2000 * 0.75
    expect(getThreshold('WebSearch', stats)).toBe(750); // 1000 * 0.75
  });

  it('should apply 0.5x multiplier at >300K tokens', () => {
    const stats = baseStats(400000);
    expect(getThreshold('Bash', stats)).toBe(1000); // 2000 * 0.5
    expect(getThreshold('Read', stats)).toBe(1250); // 2500 * 0.5
  });

  it('should apply 0.33x multiplier at >500K tokens', () => {
    const stats = baseStats(600000);
    expect(getThreshold('Bash', stats)).toBe(660); // floor(2000 * 0.33)
    expect(getThreshold('Glob', stats)).toBe(500); // max(500, floor(1500 * 0.33 = 495)) → 500
  });

  it('should never go below 500', () => {
    const stats = baseStats(1000000);
    // WebSearch: 1000 * 0.33 = 330, clamped to 500
    expect(getThreshold('WebSearch', stats)).toBe(500);
  });
});

// ─── summarizeBash ────────────────────────────────────────────────

describe('summarizeBash', () => {
  it('should detect test output', () => {
    const text = 'Running tests...\n5 pass\n1 fail\n0 skip';
    const result = summarizeBash(text, 'npm test');
    expect(result).toContain('Test output summary');
    expect(result).toContain('4 lines');
  });

  it('should detect TypeScript errors', () => {
    const text =
      'src/a.ts(1,1): error TS2304: foo\nsrc/b.ts(2,2): error TS2304: bar\nsrc/c.ts(3,3): error TS1005: baz';
    const result = summarizeBash(text, 'tsc');
    expect(result).toContain('TypeScript');
    expect(result).toContain('3 errors');
    expect(result).toContain('TS2304(2)');
  });

  it('should detect npm install output', () => {
    const text = 'npm warn deprecated\nadded 150 packages in 5s\n3 vulnerabilities';
    const result = summarizeBash(text, 'npm install');
    expect(result).toContain('npm:');
    expect(result).toContain('150 added');
    expect(result).toContain('3 vulnerabilities');
  });

  it('should detect git diff', () => {
    const text =
      'diff --git a/foo.ts b/foo.ts\n--- a/foo.ts\n+++ b/foo.ts\n@@ -1 +1 @@\n-old\n+new\ndiff --git a/bar.ts b/bar.ts\n--- a/bar.ts\n+++ b/bar.ts';
    const result = summarizeBash(text, 'git diff');
    expect(result).toContain('Git diff');
    expect(result).toContain('2 files changed');
  });

  it('should detect git log', () => {
    const text =
      'commit abc123def4567890123456789012345678901234\nAuthor: Test\nDate: Mon Jan 1\n\n    Initial commit\n\ncommit def4567890123456789012345678901234abcdef12\nAuthor: Test\nDate: Mon Jan 2\n\n    Second commit';
    const result = summarizeBash(text, 'git log');
    expect(result).toContain('Git log');
    expect(result).toContain('2 commits');
    expect(result).toContain('Initial commit');
  });

  it('should detect git status', () => {
    const text =
      'On branch main\nChanges not staged for commit:\n\tmodified:   src/foo.ts\n\tmodified:   src/bar.ts\nUntracked files:\n\tnew-file.ts';
    const result = summarizeBash(text, 'git status');
    expect(result).toContain('Git status');
    expect(result).toContain('modified');
  });

  it('should handle ls/find output by grouping extensions', () => {
    const text = 'foo.ts\nbar.ts\nbaz.js\nREADME.md\npackage.json';
    const result = summarizeBash(text, 'ls');
    expect(result).toContain('5 files listed');
    expect(result).toContain('.ts(2)');
  });

  it('should detect JSON with lower threshold (>1000 chars)', () => {
    const bigObj: Record<string, string> = {};
    for (let i = 0; i < 50; i++) {
      bigObj[`key_${i}`] = `value_${i}_padding_to_make_it_bigger`;
    }
    const text = JSON.stringify(bigObj);
    const result = summarizeBash(text, 'curl api');
    expect(result).toContain('JSON object');
    expect(result).toContain('50 keys');
  });

  it('should detect JSON arrays', () => {
    const arr = Array.from({ length: 40 }, (_, i) => ({
      id: i,
      name: `item_${i}_with_extra_padding`,
    }));
    const text = JSON.stringify(arr);
    expect(text.length).toBeGreaterThan(1000);
    const result = summarizeBash(text, 'curl api');
    expect(result).toContain('JSON array');
    expect(result).toContain('40 items');
    expect(result).toContain('id');
  });

  it('should use improved generic fallback with head/tail', () => {
    const lines = Array.from({ length: 100 }, (_, i) => `output line ${i}`);
    const text = lines.join('\n');
    const result = summarizeBash(text, 'some-unknown-command');
    expect(result).toContain('100 lines');
    expect(result).toContain('First 3:');
    expect(result).toContain('last:');
  });

  it('should detect errors in build output', () => {
    const lines = Array.from({ length: 100 }, (_, i) =>
      i === 50 ? 'error: something failed' : `output line ${i}`,
    );
    const text = lines.join('\n');
    const result = summarizeBash(text, 'some-unknown-command');
    expect(result).toContain('Build output summary');
    expect(result).toContain('1 errors/warnings');
  });
});

// ─── summarizeFileRead ────────────────────────────────────────────

describe('summarizeFileRead', () => {
  it('should handle JSON config files', () => {
    const text = JSON.stringify({
      name: 'test',
      version: '1.0',
      scripts: { build: 'tsc' },
      dependencies: {},
    });
    const result = summarizeFileRead(text, 'package.json');
    expect(result).toContain('JSON object');
    expect(result).toContain('name');
    expect(result).toContain('version');
  });

  it('should handle JSON arrays', () => {
    const text = JSON.stringify([{ id: 1 }, { id: 2 }, { id: 3 }]);
    const result = summarizeFileRead(text, 'data.json');
    expect(result).toContain('JSON array');
    expect(result).toContain('3 items');
  });

  it('should handle YAML config files', () => {
    const text = 'name: test\nversion: 1.0\nscripts:\n  build: tsc\ndependencies:\n  foo: ^1.0';
    const result = summarizeFileRead(text, 'config.yaml');
    expect(result).toContain('YAML');
    expect(result).toContain('name');
    expect(result).toContain('version');
  });

  it('should handle markdown files with headings', () => {
    const text =
      '# Title\n\nSome text\n\n## Section 1\n\nContent\n\n## Section 2\n\nMore content\n\n### Subsection';
    const result = summarizeFileRead(text, 'README.md');
    expect(result).toContain('Markdown');
    expect(result).toContain('# Title');
    expect(result).toContain('## Section 1');
  });

  it('should detect code exports and functions', () => {
    const text =
      'import { foo } from "bar";\n\nexport function doSomething() {}\nexport class MyClass {}\nexport interface MyInterface {}';
    const result = summarizeFileRead(text, 'src/module.ts');
    expect(result).toContain('1 imports');
    expect(result).toContain('Exports:');
    expect(result).toContain('Functions:');
    expect(result).toContain('Classes:');
    expect(result).toContain('Types:');
  });

  it('should detect interfaces and types', () => {
    const text = 'interface SessionStats {\n  id: string;\n}\ntype Mode = "fast" | "slow";\n';
    const result = summarizeFileRead(text, 'types.ts');
    expect(result).toContain('Types:');
    expect(result).toContain('interface SessionStats');
  });
});

// ─── summarizeWebFetch ────────────────────────────────────────────

describe('summarizeWebFetch', () => {
  it('should extract headings from markdown content', () => {
    const text =
      '# Main Title\n\nSome text\n\n## Getting Started\n\nMore text\n\n## API Reference\n\nDocs here\n\n### Methods\n';
    const result = summarizeWebFetch(text, 'https://example.com/docs');
    expect(result).toContain('WebFetch');
    expect(result).toContain('example.com/docs');
    expect(result).toContain('Outline:');
    expect(result).toContain('Main Title');
    expect(result).toContain('Getting Started');
  });

  it('should count links', () => {
    const text =
      '# Page\n\n[Link 1](https://a.com) and [Link 2](https://b.com)\n\nMore [Link 3](https://c.com)';
    const result = summarizeWebFetch(text, 'https://example.com');
    expect(result).toContain('3 links');
  });

  it('should count code blocks', () => {
    const text =
      '# Code\n\n```js\nconsole.log("hello");\n```\n\nMore text\n\n```ts\nconst x = 1;\n```\n';
    const result = summarizeWebFetch(text, 'https://example.com');
    expect(result).toContain('2 code blocks');
  });

  it('should handle content with no headings', () => {
    const text = 'Just plain text\nwith multiple lines\nand no headings';
    const result = summarizeWebFetch(text, 'https://example.com');
    expect(result).toContain('WebFetch');
    expect(result).toContain('3 lines');
  });
});

// ─── summarizeWebSearch ───────────────────────────────────────────

describe('summarizeWebSearch', () => {
  it('should extract markdown link titles', () => {
    const text =
      '- [Result One](https://a.com)\n- [Result Two](https://b.com)\n- [Result Three](https://c.com)';
    const result = summarizeWebSearch(text, 'test query');
    expect(result).toContain('WebSearch');
    expect(result).toContain('test query');
    expect(result).toContain('3 results');
    expect(result).toContain('Result One');
    expect(result).toContain('Result Two');
  });

  it('should extract bold titles', () => {
    const text = '1. **First Result** - description\n2. **Second Result** - description';
    const result = summarizeWebSearch(text, 'my search');
    expect(result).toContain('2 results');
    expect(result).toContain('First Result');
  });

  it('should extract heading titles', () => {
    const text = '## Search Results\n\n# Best Answer\n\nSome content\n\n# Second Answer\n';
    const result = summarizeWebSearch(text, 'question');
    expect(result).toContain('results');
  });

  it('should limit to top 5 results', () => {
    const lines = Array.from(
      { length: 10 },
      (_, i) => `- [Result ${i + 1}](https://example.com/${i})`,
    );
    const result = summarizeWebSearch(lines.join('\n'), 'query');
    expect(result).toContain('10 results');
    expect(result).toContain('Result 1');
    expect(result).toContain('Result 5');
    expect(result).not.toContain('Result 6');
  });

  it('should fallback for unstructured output', () => {
    const text = 'Some unstructured search output\nwith no recognized patterns\nacross three lines';
    const result = summarizeWebSearch(text, 'query');
    expect(result).toContain('3 lines');
  });
});

// ─── summarizeSearch (Grep) ───────────────────────────────────────

describe('summarizeSearch', () => {
  it('should group results by file', () => {
    const text = 'src/a.ts:10:match1\nsrc/a.ts:20:match2\nsrc/b.ts:5:match3';
    const result = summarizeSearch(text, 'pattern');
    expect(result).toContain('3 matches');
    expect(result).toContain('2 files');
    expect(result).toContain('src/a.ts (2)');
  });

  it('should handle non-file results', () => {
    const text = 'result1\nresult2\nresult3';
    const result = summarizeSearch(text, 'pattern');
    expect(result).toContain('3 result lines');
  });
});

// ─── summarizeGlob ────────────────────────────────────────────────

describe('summarizeGlob', () => {
  it('should group by directory', () => {
    const text = 'src/a.ts\nsrc/b.ts\nlib/c.ts\nlib/d.ts\nlib/e.ts';
    const result = summarizeGlob(text);
    expect(result).toContain('5 files');
    expect(result).toContain('2 directories');
    expect(result).toContain('lib/ (3)');
  });
});
