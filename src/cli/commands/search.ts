/**
 * Search Command - Hybrid FTS5 + ripgrep search
 */

import { resolve } from 'node:path';
import type { IndexStats, SearchResult } from '../../core/search-engine.js';
import { createSearchEngine } from '../../core/search-engine.js';

export interface SearchCommandOptions {
  query?: string;
  subcommand?: 'init' | 'refresh';
  glob?: string;
  maxResults?: number;
  json?: boolean;
}

export interface SearchCommandResult {
  results?: SearchResult[];
  indexStats?: IndexStats;
  json?: string;
  message?: string;
}

export async function searchCommand(options: SearchCommandOptions): Promise<SearchCommandResult> {
  const projectRoot = resolve(process.cwd());
  const dbPath = resolve(projectRoot, '.cortex', 'search.db');
  const engine = createSearchEngine(dbPath);

  try {
    await engine.init(projectRoot);

    if (options.subcommand === 'init' || options.subcommand === 'refresh') {
      const stats =
        options.subcommand === 'refresh' ? await engine.refresh() : await engine.index();

      const result: SearchCommandResult = {
        indexStats: stats,
        message: `Indexed ${stats.filesIndexed} files (${stats.totalLines} lines) in ${stats.duration}ms`,
      };

      if (options.json) {
        result.json = JSON.stringify(stats, null, 2);
      }

      return result;
    }

    if (!options.query) {
      return { message: 'No search query provided. Usage: cortex search "query"' };
    }

    const results = await engine.search(options.query, {
      maxResults: options.maxResults || 10,
      fileGlob: options.glob,
      includeContext: true,
    });

    const cmdResult: SearchCommandResult = { results };

    if (options.json) {
      cmdResult.json = JSON.stringify(results, null, 2);
    }

    return cmdResult;
  } finally {
    await engine.close();
  }
}
