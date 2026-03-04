import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'cli/index': 'src/cli/index.ts',
    'daemon/index': 'src/daemon/index.ts',
    'hooks/pre-prompt': 'src/hooks/pre-prompt.ts',
    'hooks/post-tool-result': 'src/hooks/post-tool-result.ts',
    'hooks/stop-docs-refresh': 'src/hooks/stop-docs-refresh.ts',
    'mcp/index': 'src/mcp/index.ts',
    'cli/dashboard': 'src/cli/dashboard/app.tsx',
  },
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  shims: true,
  minify: false,
  target: 'es2022',
  outDir: 'dist',
  outExtension({ format }) {
    return {
      js: format === 'cjs' ? '.cjs' : '.js',
    };
  },
});
