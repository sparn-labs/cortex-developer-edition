import { beforeEach, describe, expect, it } from 'vitest';
import { createBTSPEmbedder } from '../../src/core/btsp-embedder.js';

describe('BTSPEmbedder', () => {
  let embedder: ReturnType<typeof createBTSPEmbedder>;

  beforeEach(() => {
    embedder = createBTSPEmbedder();
  });

  it('identifies error patterns', () => {
    const errorContents = [
      'Error: Cannot read property of undefined',
      'TypeError: x is not a function',
      'ReferenceError: y is not defined',
      'ENOENT: no such file or directory',
      'Exception in thread "main"',
    ];

    for (const content of errorContents) {
      const isBTSP = embedder.detectBTSP(content);
      expect(isBTSP).toBe(true);
    }
  });

  it('identifies stack traces', () => {
    const stackTrace = `
Error: Something went wrong
    at functionName (file.js:10:5)
    at Object.<anonymous> (file.js:20:3)
    at Module._compile (module.js:652:30)
    `;

    const isBTSP = embedder.detectBTSP(stackTrace);
    expect(isBTSP).toBe(true);
  });

  it('identifies git diff new files', () => {
    const gitDiffNew = `
diff --git a/src/new-file.ts b/src/new-file.ts
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/src/new-file.ts
@@ -0,0 +1,10 @@
+export function newFunction() {
+  return true;
+}
    `;

    const isBTSP = embedder.detectBTSP(gitDiffNew);
    expect(isBTSP).toBe(true);
  });

  it('identifies merge conflicts', () => {
    const mergeConflict = `
<<<<<<< HEAD
const value = "version A";
=======
const value = "version B";
>>>>>>> feature-branch
    `;

    const isBTSP = embedder.detectBTSP(mergeConflict);
    expect(isBTSP).toBe(true);
  });

  it('sets isBTSP=true, state=active, score=1.0', () => {
    const content = 'Error: Critical failure detected';

    const entry = embedder.createBTSPEntry(content);

    expect(entry.isBTSP).toBe(true);
    expect(entry.state).toBe('active');
    expect(entry.score).toBe(1.0);
    expect(entry.content).toBe(content);
    expect(entry.id).toBeDefined();
    expect(entry.hash).toBeDefined();
    expect(entry.timestamp).toBeGreaterThan(0);
  });

  it('does not flag normal content as BTSP', () => {
    const normalContents = [
      'This is a regular log message',
      'User logged in successfully',
      'Processing data...',
      'Test passed',
    ];

    for (const content of normalContents) {
      const isBTSP = embedder.detectBTSP(content);
      expect(isBTSP).toBe(false);
    }
  });
});
