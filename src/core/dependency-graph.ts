/**
 * Dependency Graph Analyzer
 *
 * Analyzes TypeScript/JavaScript import/export relationships to build
 * a dependency graph. Uses regex-based parsing (no AST dependency needed)
 * for lightweight, fast analysis.
 *
 * Integrates with engram scoring to identify hot paths and prioritize
 * files for context loading.
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';
import { estimateTokens } from '../utils/tokenizer.js';

export interface DependencyNode {
  filePath: string;
  exports: string[];
  imports: DependencyEdge[];
  callers: string[];
  engram_score: number;
  lastModified: number;
  tokenEstimate: number;
}

export interface DependencyEdge {
  source: string;
  target: string;
  symbols: string[];
}

export interface GraphAnalysis {
  entryPoints: string[];
  hotPaths: string[];
  orphans: string[];
  totalTokens: number;
  optimizedTokens: number;
}

export interface DependencyGraphConfig {
  /** Project root directory */
  projectRoot: string;
  /** Maximum depth for traversal (default: Infinity) */
  maxDepth?: number;
  /** File extensions to analyze (default: ['.ts', '.tsx', '.js', '.jsx']) */
  extensions?: string[];
  /** Directories to ignore (default: ['node_modules', 'dist', '.git', '.cortex']) */
  ignoreDirs?: string[];
}

export interface DependencyGraph {
  /** Build the full dependency graph */
  build(): Promise<Map<string, DependencyNode>>;

  /** Get graph analysis with entry points, hot paths, orphans */
  analyze(): Promise<GraphAnalysis>;

  /** Get subgraph focused on a specific module/pattern */
  focus(pattern: string): Promise<Map<string, DependencyNode>>;

  /** Get files needed starting from an entry point, up to maxDepth */
  getFilesFromEntry(entryPoint: string, maxDepth?: number): Promise<string[]>;

  /** Get the full node map (after build) */
  getNodes(): Map<string, DependencyNode>;
}

// Import/export parsing patterns
const IMPORT_PATTERNS = [
  // import { Foo, Bar } from './module'
  /import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/g,
  // import type { Foo, Bar } from './module'
  /import\s+type\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/g,
  // import Foo from './module'
  /import\s+(\w+)\s+from\s+['"]([^'"]+)['"]/g,
  // import type Foo from './module'
  /import\s+type\s+(\w+)\s+from\s+['"]([^'"]+)['"]/g,
  // import * as Foo from './module'
  /import\s+\*\s+as\s+(\w+)\s+from\s+['"]([^'"]+)['"]/g,
  // import './module' (side-effect)
  /import\s+['"]([^'"]+)['"]/g,
  // export { Foo } from './module' (re-export as import edge)
  /export\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/g,
  // export type { Foo } from './module'
  /export\s+type\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/g,
  // export * from './module'
  /export\s+\*\s+from\s+['"]([^'"]+)['"]/g,
  // require('./module')
  /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
];

const EXPORT_PATTERNS = [
  // export { Foo, Bar }
  /export\s+\{([^}]+)\}/g,
  // export function/class/const/let/var/type/interface
  /export\s+(?:default\s+)?(?:function|class|const|let|var|type|interface|enum)\s+(\w+)/g,
  // export default
  /export\s+default\s+/g,
];

/**
 * Parse imports from file content
 */
function parseImports(content: string, filePath: string): DependencyEdge[] {
  const edges: DependencyEdge[] = [];
  const seen = new Set<string>();

  for (const pattern of IMPORT_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    const matches = [...content.matchAll(regex)];

    for (const match of matches) {
      if (pattern.source.includes('\\*\\s+from')) {
        // export * from './module' — only 1 capture group (the path)
        const target = match[1] || '';
        if (!target || (!target.startsWith('.') && !target.startsWith('/'))) continue;
        const key = `${filePath}->${target}`;
        if (!seen.has(key)) {
          seen.add(key);
          edges.push({ source: filePath, target, symbols: ['*'] });
        }
      } else if (pattern.source.includes('from')) {
        // Named/default imports with from clause
        const symbolsRaw = match[1] || '';
        const target = match[2] || '';

        if (!target || (target.startsWith('.') === false && !target.startsWith('/'))) {
          continue; // Skip external packages
        }

        const symbols = symbolsRaw
          .split(',')
          .map(
            (s) =>
              s
                .trim()
                .split(/\s+as\s+/)[0]
                ?.trim() || '',
          )
          .filter(Boolean);

        const key = `${filePath}->${target}`;
        if (!seen.has(key)) {
          seen.add(key);
          edges.push({ source: filePath, target, symbols });
        }
      } else if (pattern.source.includes('require')) {
        const target = match[1] || '';
        if (!target || (!target.startsWith('.') && !target.startsWith('/'))) {
          continue;
        }
        const key = `${filePath}->${target}`;
        if (!seen.has(key)) {
          seen.add(key);
          edges.push({ source: filePath, target, symbols: [] });
        }
      } else {
        const target = match[1] || '';
        if (!target || (!target.startsWith('.') && !target.startsWith('/'))) {
          continue;
        }
        const key = `${filePath}->${target}`;
        if (!seen.has(key)) {
          seen.add(key);
          edges.push({ source: filePath, target, symbols: [] });
        }
      }
    }
  }

  return edges;
}

/**
 * Parse exports from file content
 */
function parseExports(content: string): string[] {
  const exportsList: string[] = [];

  for (const pattern of EXPORT_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    const matches = [...content.matchAll(regex)];

    for (const match of matches) {
      if (match[1]) {
        const symbols = match[1]
          .split(',')
          .map(
            (s) =>
              s
                .trim()
                .split(/\s+as\s+/)[0]
                ?.trim() || '',
          )
          .filter(Boolean);
        exportsList.push(...symbols);
      } else {
        exportsList.push('default');
      }
    }
  }

  return [...new Set(exportsList)];
}

/**
 * Resolve a relative import path to an absolute file path
 */
function resolveImportPath(
  importPath: string,
  fromFile: string,
  projectRoot: string,
  extensions: string[],
): string | null {
  // Remove .js/.ts extension from import if present
  const cleanImport = importPath.replace(/\.(js|ts|tsx|jsx)$/, '');

  const baseDir = join(projectRoot, fromFile, '..');
  const candidates = [
    ...extensions.map((ext) => resolve(baseDir, `${cleanImport}${ext}`)),
    ...extensions.map((ext) => resolve(baseDir, cleanImport, `index${ext}`)),
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return relative(projectRoot, candidate).replace(/\\/g, '/');
    }
  }

  return null;
}

/**
 * Recursively collect all source files
 */
function collectFiles(
  dir: string,
  projectRoot: string,
  extensions: string[],
  ignoreDirs: string[],
): string[] {
  const files: string[] = [];

  try {
    const entries = readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!ignoreDirs.includes(entry.name)) {
          files.push(...collectFiles(fullPath, projectRoot, extensions, ignoreDirs));
        }
      } else if (entry.isFile() && extensions.includes(extname(entry.name))) {
        files.push(relative(projectRoot, fullPath).replace(/\\/g, '/'));
      }
    }
  } catch {
    // Skip inaccessible directories
  }

  return files;
}

/**
 * Create a dependency graph analyzer
 */
export function createDependencyGraph(config: DependencyGraphConfig): DependencyGraph {
  const {
    projectRoot,
    maxDepth = 50,
    extensions = ['.ts', '.tsx', '.js', '.jsx'],
    ignoreDirs = ['node_modules', 'dist', '.git', '.cortex', 'coverage'],
  } = config;

  const nodes = new Map<string, DependencyNode>();
  let built = false;

  async function build(): Promise<Map<string, DependencyNode>> {
    nodes.clear();

    // Collect all source files
    const files = collectFiles(projectRoot, projectRoot, extensions, ignoreDirs);

    // Parse each file
    for (const filePath of files) {
      const fullPath = join(projectRoot, filePath);

      try {
        const content = readFileSync(fullPath, 'utf-8');
        const stat = statSync(fullPath);

        const exports = parseExports(content);
        const imports = parseImports(content, filePath);

        // Resolve import targets to actual file paths
        const resolvedImports: DependencyEdge[] = [];
        for (const imp of imports) {
          const resolved = resolveImportPath(imp.target, filePath, projectRoot, extensions);
          if (resolved) {
            resolvedImports.push({ ...imp, target: resolved });
          }
        }

        nodes.set(filePath, {
          filePath,
          exports,
          imports: resolvedImports,
          callers: [], // Populated in second pass
          engram_score: 0,
          lastModified: stat.mtimeMs,
          tokenEstimate: estimateTokens(content),
        });
      } catch {
        // Skip files that can't be read
      }
    }

    // Second pass: populate callers
    for (const [filePath, node] of nodes) {
      for (const imp of node.imports) {
        const targetNode = nodes.get(imp.target);
        if (targetNode && !targetNode.callers.includes(filePath)) {
          targetNode.callers.push(filePath);
        }
      }
    }

    built = true;
    return nodes;
  }

  async function analyze(): Promise<GraphAnalysis> {
    if (!built) await build();

    const entryPoints: string[] = [];
    const orphans: string[] = [];
    const callerCounts = new Map<string, number>();

    for (const [filePath, node] of nodes) {
      // Entry points: files with no callers (typically index.ts, CLI entry, etc.)
      if (node.callers.length === 0 && node.imports.length > 0) {
        entryPoints.push(filePath);
      }

      // Orphans: files with no callers AND no imports (truly isolated)
      if (node.callers.length === 0 && node.imports.length === 0) {
        orphans.push(filePath);
      }

      // Count how many files import each module
      callerCounts.set(filePath, node.callers.length);
    }

    // Hot paths: files imported by the most other files
    const sortedByCallers = [...callerCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .filter(([, count]) => count > 0);

    const hotPaths = sortedByCallers.slice(0, 10).map(([path]) => path);

    // Token calculations
    const totalTokens = [...nodes.values()].reduce((sum, n) => sum + n.tokenEstimate, 0);
    const hotPathTokens = hotPaths.reduce(
      (sum, path) => sum + (nodes.get(path)?.tokenEstimate || 0),
      0,
    );

    return {
      entryPoints,
      hotPaths,
      orphans,
      totalTokens,
      optimizedTokens: hotPathTokens,
    };
  }

  async function focus(pattern: string): Promise<Map<string, DependencyNode>> {
    if (!built) await build();

    const matching = new Map<string, DependencyNode>();
    const lowerPattern = pattern.toLowerCase();

    for (const [filePath, node] of nodes) {
      if (filePath.toLowerCase().includes(lowerPattern)) {
        matching.set(filePath, node);

        // Also include direct dependencies and callers
        for (const imp of node.imports) {
          const depNode = nodes.get(imp.target);
          if (depNode) {
            matching.set(imp.target, depNode);
          }
        }

        for (const caller of node.callers) {
          const callerNode = nodes.get(caller);
          if (callerNode) {
            matching.set(caller, callerNode);
          }
        }
      }
    }

    return matching;
  }

  async function getFilesFromEntry(
    entryPoint: string,
    depth: number = maxDepth,
  ): Promise<string[]> {
    if (!built) await build();

    const visited = new Set<string>();
    const queue: Array<{ path: string; depth: number }> = [{ path: entryPoint, depth: 0 }];

    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) break;

      if (visited.has(item.path) || item.depth > depth) continue;
      visited.add(item.path);

      const node = nodes.get(item.path);
      if (node) {
        for (const imp of node.imports) {
          if (!visited.has(imp.target)) {
            queue.push({ path: imp.target, depth: item.depth + 1 });
          }
        }
      }
    }

    return [...visited];
  }

  function getNodes(): Map<string, DependencyNode> {
    return nodes;
  }

  return {
    build,
    analyze,
    focus,
    getFilesFromEntry,
    getNodes,
  };
}
