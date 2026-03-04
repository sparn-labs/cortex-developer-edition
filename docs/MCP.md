# Cortex MCP Server Configuration Guide

Cortex exposes its neuroscience-inspired context optimization as an MCP (Model Context Protocol) server, enabling integration with Claude Desktop, VS Code, Cursor, and other MCP-compatible clients.

## Quick Start

### 1. Install Cortex

```bash
npm install -g @sparn/cortex
```

### 2. Configure Your MCP Client

#### Claude Desktop

Add to `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cortex": {
      "command": "node",
      "args": ["/path/to/cortex/dist/mcp/index.js"],
      "env": {
        "CORTEX_DB_PATH": "/path/to/.cortex/memory.db"
      }
    }
  }
}
```

If installed globally via npm:

```json
{
  "mcpServers": {
    "cortex": {
      "command": "npx",
      "args": ["@sparn/cortex-mcp"]
    }
  }
}
```

#### VS Code / Cursor

Add to your workspace `.vscode/mcp.json`:

```json
{
  "servers": {
    "cortex": {
      "command": "node",
      "args": ["./node_modules/@sparn/cortex/dist/mcp/index.js"]
    }
  }
}
```

### 3. Run the Server Manually (Optional)

```bash
# Using npm script
npm run mcp:server

# Or directly
node dist/mcp/index.js
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CORTEX_DB_PATH` | `.cortex/memory.db` | Path to the SQLite database file |

## Available Tools

### cortex_optimize

Optimize context using the neuroscience-inspired pipeline (BTSP detection, engram scoring, confidence states, sparse pruning).

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `context` | string | Yes | The context text to optimize |
| `dryRun` | boolean | No | If true, do not persist to memory (default: false) |
| `verbose` | boolean | No | If true, include per-entry details (default: false) |
| `threshold` | number | No | Custom pruning threshold 0-100 (overrides config) |

**Example response:**

```json
{
  "optimizedContext": "Important function definition\nAPI endpoint configuration",
  "tokensBefore": 150,
  "tokensAfter": 95,
  "reduction": "36.7%",
  "entriesProcessed": 5,
  "entriesKept": 3,
  "durationMs": 12,
  "stateDistribution": {
    "active": 1,
    "ready": 2,
    "silent": 0
  }
}
```

### cortex_stats

Get optimization statistics from the memory store.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `reset` | boolean | No | If true, clear all statistics (default: false) |

**Example response:**

```json
{
  "totalCommands": 42,
  "totalTokensSaved": 85000,
  "averageReduction": "63.2%",
  "recentOptimizations": [
    {
      "timestamp": "2026-02-23T10:30:00.000Z",
      "tokensBefore": 5000,
      "tokensAfter": 1800,
      "entriesPruned": 15,
      "durationMs": 23,
      "reduction": "64.0%"
    }
  ]
}
```

### cortex_consolidate

Run memory consolidation (sleep replay). Removes decayed entries and merges duplicates.

**Parameters:** None

**Example response:**

```json
{
  "entriesBefore": 150,
  "entriesAfter": 95,
  "decayedRemoved": 30,
  "duplicatesRemoved": 25,
  "compressionRatio": "63.3%",
  "durationMs": 45,
  "vacuumCompleted": true
}
```

## Programmatic Usage

You can also create the MCP server programmatically:

```typescript
import { createKVMemory } from '@sparn/cortex';
import { createCortexMcpServer } from '@sparn/cortex';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const memory = await createKVMemory('./my-project/.cortex/memory.db');
const server = createCortexMcpServer({ memory });

const transport = new StdioServerTransport();
await server.connect(transport);
```

## Architecture

The MCP server acts as a bridge between MCP clients and Cortex's core optimization engine:

```
MCP Client (Claude Desktop, VS Code, etc.)
    |
    | JSON-RPC over stdio
    |
Cortex MCP Server (src/mcp/server.ts)
    |
    |-- cortex_optimize  --> GenericAdapter --> Optimization Pipeline
    |-- cortex_stats     --> KVMemory --> optimization_stats table
    |-- cortex_consolidate --> SleepCompressor --> KVMemory
    |
SQLite Database (.cortex/memory.db)
```

## Troubleshooting

### Server not showing up in Claude Desktop

1. Verify the path in `claude_desktop_config.json` is absolute
2. Check that the build is up to date: `npm run build`
3. Restart Claude Desktop completely (quit from system tray, not just close window)

### Checking server logs

The MCP server logs to stderr. For Claude Desktop, check:

- **macOS:** `~/Library/Logs/Claude/mcp-server-cortex.log`
- **Windows:** `%LOCALAPPDATA%\Claude\Logs\mcp-server-cortex.log`

### Database issues

If you encounter database errors, try:

```bash
# Remove and recreate the database
rm .cortex/memory.db
node dist/mcp/index.js
```
