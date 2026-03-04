/**
 * Dashboard command parser — pure function, no React.
 *
 * Parses raw input string into structured command with name, positionals, and flags.
 * Handles quoted strings, --flag value, --boolean, -f value.
 * No Commander (it calls process.exit on errors which would kill the TUI).
 */

export interface ParsedCommand {
  name: string;
  positionals: string[];
  flags: Record<string, string | true>;
}

/** Tokenize input respecting quoted strings. */
function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inQuote: string | null = null;

  for (const ch of input) {
    if (inQuote) {
      if (ch === inQuote) {
        inQuote = null;
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      inQuote = ch;
    } else if (ch === ' ' || ch === '\t') {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

export function parseCommand(input: string): ParsedCommand | null {
  const trimmed = input.trim();
  if (trimmed.length === 0) return null;

  const tokens = tokenize(trimmed);
  const first = tokens[0];
  if (!first) return null;

  const name = first.toLowerCase();
  const positionals: string[] = [];
  const flags: Record<string, string | true> = {};

  let i = 1;
  while (i < tokens.length) {
    const token = tokens[i];
    if (!token) {
      i++;
      continue;
    }

    if (token.startsWith('--')) {
      const key = token.slice(2);
      const next = tokens[i + 1];
      if (next !== undefined && !next.startsWith('-')) {
        flags[key] = next;
        i += 2;
      } else {
        flags[key] = true;
        i++;
      }
    } else if (token.startsWith('-') && token.length === 2) {
      const key = token.slice(1);
      const next = tokens[i + 1];
      if (next !== undefined && !next.startsWith('-')) {
        flags[key] = next;
        i += 2;
      } else {
        flags[key] = true;
        i++;
      }
    } else {
      positionals.push(token);
      i++;
    }
  }

  return { name, positionals, flags };
}
