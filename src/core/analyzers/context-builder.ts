/**
 * Builds the shared AnalysisContext used by all analyzers.
 * Collects files, detects stack, parses git log, builds dependency graph.
 */

import { execFileSync, execSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, extname, join, relative, resolve } from 'node:path';
import { createDependencyGraph } from '../dependency-graph.js';
import { createCortexIgnore } from './cortexignore.js';
import type { AnalysisContext, AnalyzeThresholds, GitLogEntry } from './types.js';
import { DEFAULT_THRESHOLDS } from './types.js';

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.cs', '.sql', '.json', '.md']);

const IGNORE_DIRS = new Set([
  'node_modules',
  'dist',
  '.git',
  '.cortex',
  'coverage',
  '.next',
  'bin',
  'obj',
  '.vs',
  '.vscode',
]);

function collectSourceFiles(
  dir: string,
  projectRoot: string,
  ignore: import('./cortexignore.js').CortexIgnore,
): Map<string, string> {
  const files = new Map<string, string>();

  function walk(current: string): void {
    try {
      const entries = readdirSync(current, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = join(current, entry.name);
        if (entry.isDirectory()) {
          if (!IGNORE_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
            walk(fullPath);
          }
        } else if (entry.isFile()) {
          const ext = extname(entry.name);
          if (SOURCE_EXTENSIONS.has(ext)) {
            const relPath = relative(projectRoot, fullPath).replace(/\\/g, '/');
            if (!ignore.isFileExcluded(relPath)) {
              try {
                const stat = statSync(fullPath);
                if (stat.size < 1_000_000) {
                  files.set(relPath, readFileSync(fullPath, 'utf-8'));
                }
              } catch {
                // Skip unreadable files
              }
            }
          }
        }
      }
    } catch {
      // Skip inaccessible directories
    }
  }

  walk(dir);
  return files;
}

function detectStack(files: Map<string, string>, projectRoot: string): Set<string> {
  const tags = new Set<string>();
  const exts = new Set<string>();

  for (const path of files.keys()) {
    exts.add(extname(path));
  }

  if (exts.has('.ts') || exts.has('.tsx') || exts.has('.js') || exts.has('.jsx')) {
    tags.add('typescript');
  }
  if (exts.has('.tsx') || exts.has('.jsx')) {
    tags.add('react');
  }
  if (exts.has('.cs')) {
    tags.add('dotnet');
  }
  if (exts.has('.sql')) {
    tags.add('sql');
  }

  // Check package.json for React
  const pkgPath = join(projectRoot, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = readFileSync(pkgPath, 'utf-8');
      if (pkg.includes('"react"')) {
        tags.add('react');
      }
    } catch {
      // ignore
    }
  }

  return tags;
}

function parseGitLog(projectRoot: string): { available: boolean; entries: GitLogEntry[] } {
  try {
    const gitDir = join(projectRoot, '.git');
    if (!existsSync(gitDir)) {
      return { available: false, entries: [] };
    }

    const raw = execSync('git log --name-only --pretty=format:"%H|%aI" -n 100', {
      cwd: projectRoot,
      encoding: 'utf-8',
      timeout: 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const entries: GitLogEntry[] = [];
    let current: GitLogEntry | null = null;

    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) {
        if (current) {
          entries.push(current);
          current = null;
        }
        continue;
      }

      if (trimmed.includes('|')) {
        if (current) entries.push(current);
        const [hash, date] = trimmed.replace(/"/g, '').split('|');
        current = { hash: hash || '', date: date || '', filesChanged: [] };
      } else if (current) {
        current.filesChanged.push(trimmed);
      }
    }

    if (current) entries.push(current);

    return { available: true, entries };
  } catch {
    return { available: false, entries: [] };
  }
}

export async function buildAnalysisContext(
  projectRoot: string,
  thresholds?: Partial<AnalyzeThresholds>,
): Promise<AnalysisContext> {
  const config: AnalyzeThresholds = { ...DEFAULT_THRESHOLDS, ...thresholds };

  const ignore = createCortexIgnore(projectRoot, config.excludePatterns);
  const files = collectSourceFiles(projectRoot, projectRoot, ignore);

  const extensions = new Set<string>();
  for (const path of files.keys()) {
    extensions.add(extname(path));
  }

  const stackTags = detectStack(files, projectRoot);

  const graph = createDependencyGraph({ projectRoot });
  const nodes = await graph.build();
  const graphAnalysis = await graph.analyze();

  const { available: gitAvailable, entries: gitLog } = parseGitLog(projectRoot);

  return {
    projectRoot,
    files,
    extensions,
    dependencyGraph: graph,
    graphAnalysis,
    nodes,
    stackTags,
    gitAvailable,
    gitLog,
    config,
    ignore,
  };
}

/**
 * Build context for only the files changed since a git ref.
 * Full dependency graph is still built (needed for ARCH checks).
 */
export async function buildChangedFilesContext(
  projectRoot: string,
  since = 'HEAD~1',
  thresholds?: Partial<AnalyzeThresholds>,
): Promise<AnalysisContext> {
  const config: AnalyzeThresholds = { ...DEFAULT_THRESHOLDS, ...thresholds };
  const ignore = createCortexIgnore(projectRoot, config.excludePatterns);

  // Get changed files from git
  let changedFiles: string[] = [];
  try {
    const diffOutput = execFileSync('git', ['diff', '--name-only', since], {
      cwd: projectRoot,
      encoding: 'utf-8',
      timeout: 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const cachedOutput = execFileSync('git', ['diff', '--name-only', '--cached'], {
      cwd: projectRoot,
      encoding: 'utf-8',
      timeout: 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const allChanged = new Set([
      ...diffOutput
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean),
      ...cachedOutput
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean),
    ]);
    changedFiles = [...allChanged];
  } catch {
    // Git not available or ref invalid — fall back to full context
    return buildAnalysisContext(projectRoot, thresholds);
  }

  // Read only changed files that are source files and not ignored
  const files = new Map<string, string>();
  for (const relPath of changedFiles) {
    const ext = extname(relPath);
    if (!SOURCE_EXTENSIONS.has(ext)) continue;
    if (ignore.isFileExcluded(relPath)) continue;

    const fullPath = join(projectRoot, relPath);
    try {
      if (existsSync(fullPath)) {
        const stat = statSync(fullPath);
        if (stat.size < 1_000_000) {
          files.set(relPath, readFileSync(fullPath, 'utf-8'));
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  const extensions = new Set<string>();
  for (const path of files.keys()) {
    extensions.add(extname(path));
  }

  const stackTags = detectStack(files, projectRoot);

  // Full dependency graph still needed for arch checks
  const graph = createDependencyGraph({ projectRoot });
  const nodes = await graph.build();
  const graphAnalysis = await graph.analyze();

  const { available: gitAvailable, entries: gitLog } = parseGitLog(projectRoot);

  return {
    projectRoot,
    files,
    extensions,
    dependencyGraph: graph,
    graphAnalysis,
    nodes,
    stackTags,
    gitAvailable,
    gitLog,
    config,
    ignore,
  };
}

/**
 * Build context for a single file.
 * Full dependency graph is still built (needed for coupling analysis).
 */
export async function buildSingleFileContext(
  projectRoot: string,
  filePath: string,
  thresholds?: Partial<AnalyzeThresholds>,
): Promise<AnalysisContext> {
  const config: AnalyzeThresholds = { ...DEFAULT_THRESHOLDS, ...thresholds };
  const ignore = createCortexIgnore(projectRoot, config.excludePatterns);

  const files = new Map<string, string>();
  const relPath = filePath.startsWith(projectRoot)
    ? relative(projectRoot, filePath).replace(/\\/g, '/')
    : filePath.replace(/\\/g, '/');

  // Prevent path traversal — resolved path must stay within projectRoot
  const fullPath = resolve(projectRoot, relPath);
  if (!fullPath.startsWith(projectRoot)) {
    // Path escapes project root — return empty context
    const graph = createDependencyGraph({ projectRoot });
    const nodes = await graph.build();
    const graphAnalysis = await graph.analyze();
    const { available: gitAvailable, entries: gitLog } = parseGitLog(projectRoot);
    return {
      projectRoot,
      files,
      extensions: new Set(),
      dependencyGraph: graph,
      graphAnalysis,
      nodes,
      stackTags: new Set(),
      gitAvailable,
      gitLog,
      config,
      ignore,
    };
  }

  try {
    if (existsSync(fullPath)) {
      files.set(relPath, readFileSync(fullPath, 'utf-8'));
    }
  } catch {
    // Skip unreadable file
  }

  const extensions = new Set<string>();
  for (const path of files.keys()) {
    extensions.add(extname(path));
  }

  const stackTags = detectStack(files, projectRoot);

  // Full dependency graph still needed for coupling analysis
  const graph = createDependencyGraph({ projectRoot });
  const nodes = await graph.build();
  const graphAnalysis = await graph.analyze();

  const { available: gitAvailable, entries: gitLog } = parseGitLog(projectRoot);

  return {
    projectRoot,
    files,
    extensions,
    dependencyGraph: graph,
    graphAnalysis,
    nodes,
    stackTags,
    gitAvailable,
    gitLog,
    config,
    ignore,
  };
}

export function getProjectName(projectRoot: string): string {
  const pkgPath = join(projectRoot, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      if (typeof pkg.name === 'string') return pkg.name;
    } catch {
      // fall through
    }
  }
  return basename(projectRoot);
}
