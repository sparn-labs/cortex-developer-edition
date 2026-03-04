/**
 * Docs Command - Auto-generate CLAUDE.md
 */

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { DependencyGraph } from '../../core/dependency-graph.js';
import { createDependencyGraph } from '../../core/dependency-graph.js';
import { createDocsGenerator } from '../../core/docs-generator.js';

export interface DocsCommandOptions {
  output?: string;
  includeGraph?: boolean;
  json?: boolean;
}

export interface DocsCommandResult {
  content: string;
  outputPath?: string;
  message: string;
}

export async function docsCommand(options: DocsCommandOptions): Promise<DocsCommandResult> {
  const projectRoot = resolve(process.cwd());

  const generator = createDocsGenerator({
    projectRoot,
    includeGraph: options.includeGraph !== false,
  });

  let graph: DependencyGraph | undefined;
  if (options.includeGraph !== false) {
    graph = createDependencyGraph({ projectRoot });
    await graph.build();
  }

  const content = await generator.generate(graph);

  if (options.json) {
    return {
      content,
      message: `CLAUDE.md generated (${content.split('\n').length} lines)`,
    };
  }

  const outputPath = options.output || resolve(projectRoot, 'CLAUDE.md');

  // Write output
  writeFileSync(outputPath, content, 'utf-8');

  return {
    content,
    outputPath,
    message: `CLAUDE.md generated at ${outputPath} (${content.split('\n').length} lines)`,
  };
}
