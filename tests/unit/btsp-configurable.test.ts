/**
 * Configurable BTSP Patterns Tests
 */

import { describe, expect, it } from 'vitest';
import { createBTSPEmbedder } from '../../src/core/btsp-embedder.js';

describe('Configurable BTSP Patterns', () => {
  it('should detect default patterns without config', () => {
    const btsp = createBTSPEmbedder();
    expect(btsp.detectBTSP('fatal error occurred')).toBe(true);
    expect(btsp.detectBTSP('hello world')).toBe(false);
  });

  it('should detect custom pattern', () => {
    const btsp = createBTSPEmbedder({
      customPatterns: ['DEPLOY_FAILURE'],
    });
    expect(btsp.detectBTSP('DEPLOY_FAILURE in production')).toBe(true);
    expect(btsp.detectBTSP('normal operation')).toBe(false);
  });

  it('should silently ignore invalid regex patterns', () => {
    const btsp = createBTSPEmbedder({
      customPatterns: ['[invalid regex(', 'valid_pattern'],
    });
    // Should not throw, and valid pattern should work
    expect(btsp.detectBTSP('valid_pattern detected')).toBe(true);
  });

  it('should merge custom patterns with defaults', () => {
    const btsp = createBTSPEmbedder({
      customPatterns: ['CUSTOM_EVENT'],
    });
    // Default still works
    expect(btsp.detectBTSP('TypeError: something')).toBe(true);
    // Custom also works
    expect(btsp.detectBTSP('CUSTOM_EVENT fired')).toBe(true);
  });

  it('should handle empty customPatterns array', () => {
    const btsp = createBTSPEmbedder({ customPatterns: [] });
    // Default patterns still work
    expect(btsp.detectBTSP('fatal error')).toBe(true);
    expect(btsp.detectBTSP('hello')).toBe(false);
  });

  it('should handle undefined config (backward compat)', () => {
    const btsp = createBTSPEmbedder(undefined);
    expect(btsp.detectBTSP('critical failure')).toBe(true);
  });
});
