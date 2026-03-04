/**
 * Graph Command - Analyze dependency graph
 */

import { resolve } from 'node:path';
import type { GraphAnalysis } from '../../core/dependency-graph.js';
import { createDependencyGraph } from '../../core/dependency-graph.js';

export interface GraphCommandOptions {
  entry?: string;
  depth?: number;
  focus?: string;
  json?: boolean;
}

export interface GraphCommandResult {
  analysis: GraphAnalysis;
  json?: string;
  nodeCount: number;
}

export async function graphCommand(options: GraphCommandOptions): Promise<GraphCommandResult> {
  const projectRoot = resolve(process.cwd());

  const graph = createDependencyGraph({
    projectRoot,
    maxDepth: options.depth,
  });

  await graph.build();

  let nodes = graph.getNodes();

  if (options.focus) {
    nodes = await graph.focus(options.focus);
  }

  if (options.entry) {
    const allNodes = graph.getNodes();
    if (!allNodes.has(options.entry)) {
      throw new Error(
        `Entry point not found in graph: ${options.entry}. Available: ${[...allNodes.keys()].slice(0, 5).join(', ')}${allNodes.size > 5 ? '...' : ''}`,
      );
    }
    const files = await graph.getFilesFromEntry(options.entry, options.depth);
    const entryNodes = new Map<string, typeof nodes extends Map<string, infer V> ? V : never>();
    for (const f of files) {
      const node = nodes.get(f);
      if (node) entryNodes.set(f, node);
    }
    nodes = entryNodes;
  }

  const analysis = await graph.analyze();

  const result: GraphCommandResult = {
    analysis,
    nodeCount: nodes.size,
  };

  if (options.json) {
    result.json = JSON.stringify(
      {
        analysis,
        nodeCount: nodes.size,
        nodes: Object.fromEntries(
          [...nodes.entries()].map(([k, v]) => [
            k,
            {
              exports: v.exports,
              imports: v.imports.map((i) => i.target),
              callers: v.callers,
              tokens: v.tokenEstimate,
            },
          ]),
        ),
      },
      null,
      2,
    );
  }

  return result;
}
