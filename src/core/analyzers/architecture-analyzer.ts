/**
 * Architecture Analyzer (25 pts)
 *
 * Checks coupling, cohesion, cycles, god files, inheritance depth,
 * git hotspots, orphans, and layer violations.
 */

import type { AnalysisContext, Analyzer, AnalyzerFinding, CategoryResult } from './types.js';

export function createArchitectureAnalyzer(): Analyzer {
  return {
    category: 'architecture',
    name: 'Architecture',
    maxPoints: 25,

    async analyze(context: AnalysisContext): Promise<CategoryResult> {
      const findings: AnalyzerFinding[] = [];
      let deductions = 0;

      // ARCH-001: High afferent coupling (Ca > threshold)
      deductions += checkAfferentCoupling(context, findings);

      // ARCH-002: High efferent coupling (Ce > threshold)
      deductions += checkEfferentCoupling(context, findings);

      // ARCH-003: Instability ratio
      deductions += checkInstability(context, findings);

      // ARCH-004: Dependency cycles
      deductions += checkCycles(context, findings);

      // ARCH-005: Low cohesion (LCOM4 heuristic)
      deductions += checkCohesion(context, findings);

      // ARCH-006: Deep inheritance
      deductions += checkInheritanceDepth(context, findings);

      // ARCH-007: God files
      deductions += checkGodFiles(context, findings);

      // ARCH-008: Git hotspots
      deductions += checkGitHotspots(context, findings);

      // ARCH-009: Orphaned files
      deductions += checkOrphans(context, findings);

      // ARCH-010: Layer violations
      deductions += checkLayerViolations(context, findings);

      const score = Math.max(0, 25 - deductions);

      return {
        category: 'architecture',
        name: 'Architecture',
        maxPoints: 25,
        score,
        isNA: false,
        findings,
      };
    },
  };
}

function isSharedDefinitionFile(filePath: string): boolean {
  // Type definition files and library entry points are designed to be widely imported
  if (filePath.startsWith('src/types/') || filePath.endsWith('/types.ts')) return true;
  if (filePath === 'src/index.ts') return true;
  return false;
}

function checkAfferentCoupling(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let total = 0;
  const threshold = context.config.maxCouplingCa;

  for (const [filePath, node] of context.nodes) {
    if (node.callers.length > threshold) {
      // Type definition files are designed to have many callers
      if (isSharedDefinitionFile(filePath)) continue;
      const deduction = Math.min(0.5, 3);
      total += deduction;
      findings.push({
        ruleId: 'ARCH-001',
        title: 'High afferent coupling',
        description: `${filePath} has ${node.callers.length} callers (threshold: ${threshold})`,
        severity: 'major',
        filePath,
        suggestion: `Consider splitting this module into smaller, focused units.`,
        deduction,
        fixable: false,
        fixType: 'refactor',
      });
    }
  }

  return Math.min(total, 3);
}

function checkEfferentCoupling(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let total = 0;
  const threshold = context.config.maxCouplingCe;

  for (const [filePath, node] of context.nodes) {
    if (node.imports.length > threshold) {
      // Library entry points re-export everything by design
      if (isSharedDefinitionFile(filePath)) continue;
      const deduction = Math.min(0.5, 3);
      total += deduction;
      findings.push({
        ruleId: 'ARCH-002',
        title: 'High efferent coupling',
        description: `${filePath} imports ${node.imports.length} modules (threshold: ${threshold})`,
        severity: 'major',
        filePath,
        suggestion: `Reduce dependencies by consolidating related imports or using dependency injection.`,
        deduction,
        fixable: false,
        fixType: 'refactor',
      });
    }
  }

  return Math.min(total, 3);
}

function checkInstability(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let total = 0;

  // Flag instability > 0.8 on files that have callers (i.e., are "core" modules)
  for (const [filePath, node] of context.nodes) {
    const ca = node.callers.length;
    const ce = node.imports.length;
    if (ca + ce === 0) continue;

    const instability = ce / (ca + ce);
    if (instability > 0.8 && ca >= 3) {
      total += 0.4;
      findings.push({
        ruleId: 'ARCH-003',
        title: 'High instability on core module',
        description: `${filePath} has instability ${instability.toFixed(2)} (Ca=${ca}, Ce=${ce}) — highly unstable despite being depended upon.`,
        severity: 'minor',
        filePath,
        suggestion: `Reduce outgoing dependencies to improve stability for this widely-used module.`,
        deduction: 0.4,
        fixable: false,
        fixType: 'refactor',
      });
    }
  }

  return Math.min(total, 2);
}

interface DFSState {
  cycles: string[][];
  visited: Set<string>;
  stack: Set<string>;
  path: string[];
  nodes: Map<string, { imports: Array<{ target: string }> }>;
}

function dfsVisit(node: string, state: DFSState): void {
  if (state.cycles.length >= 5) return;
  state.visited.add(node);
  state.stack.add(node);
  state.path.push(node);

  const nodeData = state.nodes.get(node);
  if (nodeData) {
    for (const imp of nodeData.imports) {
      if (state.stack.has(imp.target)) {
        const cycleStart = state.path.indexOf(imp.target);
        if (cycleStart >= 0) {
          state.cycles.push([...state.path.slice(cycleStart), imp.target]);
        }
      } else if (!state.visited.has(imp.target)) {
        dfsVisit(imp.target, state);
      }
    }
  }

  state.path.pop();
  state.stack.delete(node);
}

function checkCycles(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  const state: DFSState = {
    cycles: [],
    visited: new Set(),
    stack: new Set(),
    path: [],
    nodes: context.nodes,
  };

  for (const filePath of context.nodes.keys()) {
    if (!state.visited.has(filePath)) dfsVisit(filePath, state);
  }

  let total = 0;
  for (const cycle of state.cycles) {
    total += 1;
    findings.push({
      ruleId: 'ARCH-004',
      title: 'Dependency cycle detected',
      description: `Circular dependency: ${cycle.join(' → ')}`,
      severity: 'critical',
      filePath: cycle[0],
      suggestion: `Break the cycle by extracting shared types/interfaces into a separate module.`,
      deduction: 1,
      fixable: false,
      fixType: 'refactor',
    });
  }

  return Math.min(total, 5);
}

function checkCohesion(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let total = 0;

  for (const [filePath, content] of context.files) {
    if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx')) continue;

    // LCOM4 heuristic: count exported groups that don't reference each other
    const exportMatches = [
      ...content.matchAll(/export\s+(?:function|class|const|interface|type|enum)\s+(\w+)/g),
    ];
    const exportNames = exportMatches.map((m) => m[1]).filter(Boolean);

    if (exportNames.length < 5) continue;

    // Check how many exports reference other exports
    let connectedPairs = 0;
    for (let i = 0; i < exportNames.length; i++) {
      for (let j = i + 1; j < exportNames.length; j++) {
        const name1 = exportNames[i] as string;
        const name2 = exportNames[j] as string;
        // Check if one references the other in the source
        const regex1 = new RegExp(`\\b${name1}\\b`);
        const regex2 = new RegExp(`\\b${name2}\\b`);
        // Find body sections (rough heuristic)
        if (regex2.test(content) && regex1.test(content)) {
          connectedPairs++;
        }
      }
    }

    const maxPairs = (exportNames.length * (exportNames.length - 1)) / 2;
    const cohesionRatio = maxPairs > 0 ? connectedPairs / maxPairs : 1;

    if (cohesionRatio < 0.2 && exportNames.length >= 8) {
      total += 0.5;
      findings.push({
        ruleId: 'ARCH-005',
        title: 'Low cohesion',
        description: `${filePath} has ${exportNames.length} exports with low interconnection (cohesion: ${(cohesionRatio * 100).toFixed(0)}%)`,
        severity: 'major',
        filePath,
        suggestion: `Split into multiple focused modules based on related functionality.`,
        deduction: 0.5,
        fixable: false,
        fixType: 'refactor',
      });
    }
  }

  return Math.min(total, 3);
}

function checkInheritanceDepth(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let total = 0;
  const classExtends = new Map<string, string>();

  for (const [filePath, content] of context.files) {
    if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx') && !filePath.endsWith('.cs'))
      continue;

    const matches = [...content.matchAll(/class\s+(\w+)\s+extends\s+(\w+)/g)];
    for (const match of matches) {
      const className = match[1];
      const parentClass = match[2];
      if (className && parentClass) {
        classExtends.set(className, parentClass);
      }
    }
  }

  // Trace inheritance depth
  for (const [className] of classExtends) {
    let depth = 0;
    let current: string | undefined = className;
    const visited = new Set<string>();

    while (current && classExtends.has(current) && !visited.has(current)) {
      visited.add(current);
      current = classExtends.get(current);
      depth++;
    }

    if (depth > context.config.maxDIT) {
      total += 0.5;
      findings.push({
        ruleId: 'ARCH-006',
        title: 'Deep inheritance tree',
        description: `Class ${className} has inheritance depth ${depth} (threshold: ${context.config.maxDIT})`,
        severity: 'minor',
        suggestion: `Prefer composition over inheritance to reduce coupling.`,
        deduction: 0.5,
        fixable: false,
        fixType: 'refactor',
      });
    }
  }

  return Math.min(total, 2);
}

function checkGodFiles(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let total = 0;

  for (const [filePath, content] of context.files) {
    if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx') && !filePath.endsWith('.js'))
      continue;

    const lines = content.split('\n').length;
    const node = context.nodes.get(filePath);
    const exports = node?.exports.length ?? 0;
    const imports = node?.imports.length ?? 0;

    if (lines > 500 && exports > 20 && imports > 15) {
      total += 1;
      findings.push({
        ruleId: 'ARCH-007',
        title: 'God file detected',
        description: `${filePath}: ${lines} lines, ${exports} exports, ${imports} imports`,
        severity: 'major',
        filePath,
        suggestion: `Break into smaller, focused modules. Extract related exports into their own files.`,
        deduction: 1,
        fixable: false,
        fixType: 'refactor',
      });
    }
  }

  return Math.min(total, 3);
}

function checkGitHotspots(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  if (!context.gitAvailable || context.gitLog.length === 0) return 0;

  // Count file change frequency
  const churnCount = new Map<string, number>();
  for (const entry of context.gitLog) {
    for (const file of entry.filesChanged) {
      churnCount.set(file, (churnCount.get(file) ?? 0) + 1);
    }
  }

  // Find high-churn files that also have high complexity
  let total = 0;
  const sorted = [...churnCount.entries()].sort((a, b) => b[1] - a[1]);

  for (const [filePath, changes] of sorted.slice(0, 20)) {
    if (changes < 10) continue;

    // Only flag source code hotspots (not docs, configs, or generated files)
    if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx') && !filePath.endsWith('.js')) {
      continue;
    }

    const content = context.files.get(filePath);
    if (!content) continue;

    const lines = content.split('\n').length;
    if (lines > 200) {
      total += 0.5;
      findings.push({
        ruleId: 'ARCH-008',
        title: 'Git hotspot',
        description: `${filePath}: ${changes} changes in recent history with ${lines} lines — high churn + complexity`,
        severity: 'major',
        filePath,
        suggestion: `Stabilize this frequently-changed file by extracting volatile parts.`,
        deduction: 0.5,
        fixable: false,
        fixType: 'refactor',
      });
    }
  }

  return Math.min(total, 2);
}

function checkOrphans(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  const orphans = context.graphAnalysis.orphans;
  if (orphans.length === 0) return 0;

  // Only flag source code orphans (not configs, tests, benchmarks, or standalone scripts)
  const codeOrphans = orphans.filter((f) => {
    if (!(f.endsWith('.ts') || f.endsWith('.tsx') || f.endsWith('.js') || f.endsWith('.jsx'))) {
      return false;
    }
    // Exclude config files, test files, benchmarks, and standalone entry points
    if (f.includes('.config.') || f.includes('.test.') || f.includes('.spec.')) return false;
    if (f.includes('__tests__') || f.startsWith('tests/') || f.startsWith('benchmarks/')) {
      return false;
    }
    // Exclude hook entry points (invoked externally, not imported)
    if (f.startsWith('src/hooks/') && !f.includes('/index.')) return false;
    return true;
  });

  if (codeOrphans.length === 0) return 0;

  const deduction = Math.min(codeOrphans.length * 0.1, 1);
  findings.push({
    ruleId: 'ARCH-009',
    title: 'Orphaned files',
    description: `${codeOrphans.length} source files with no imports or callers: ${codeOrphans.slice(0, 5).join(', ')}${codeOrphans.length > 5 ? '...' : ''}`,
    severity: 'info',
    suggestion: `Review orphaned files — they may be dead code that can be removed.`,
    deduction,
    fixable: true,
    fixType: 'remove-code',
  });

  return deduction;
}

function checkLayerViolations(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  const rules = context.config.layerRules;
  if (Object.keys(rules).length === 0) return 0;

  let total = 0;

  for (const [filePath, node] of context.nodes) {
    for (const [layer, forbidden] of Object.entries(rules)) {
      if (!filePath.includes(`/${layer}/`) && !filePath.startsWith(`${layer}/`)) continue;

      for (const imp of node.imports) {
        for (const forbiddenLayer of forbidden) {
          if (
            imp.target.includes(`/${forbiddenLayer}/`) ||
            imp.target.startsWith(`${forbiddenLayer}/`)
          ) {
            total += 0.25;
            findings.push({
              ruleId: 'ARCH-010',
              title: 'Layer violation',
              description: `${filePath} (${layer}) imports from forbidden layer ${forbiddenLayer}: ${imp.target}`,
              severity: 'minor',
              filePath,
              suggestion: `Move shared logic to a common/shared layer accessible by both.`,
              deduction: 0.25,
              fixable: false,
              fixType: 'refactor',
            });
          }
        }
      }
    }
  }

  return Math.min(total, 1);
}
