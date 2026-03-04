# ADR-001: Multi-dimensional Codebase Analyzer Architecture

## Status
Accepted

## Context
Cortex needed a comprehensive codebase health analysis tool beyond token optimization. The analyzer must assess code quality, architecture, security, and conventions using a scoring system.

## Decision
Implement a modular analyzer system with:
- 6 independent analyzers (Architecture, Quality, Database, Security, Tokens, Tests/Docs)
- Regex/heuristic-based static analysis (no AST) for lightweight execution
- N/A weight redistribution when categories don't apply
- S-to-Zero grading scale (10 tiers)
- Factory function pattern (`createXxxAnalyzer()`) consistent with codebase conventions

## Consequences
- Fast execution (~2s for full analysis) without heavy AST dependencies
- Some false positives from regex-based detection (mitigated by per-rule caps and file exclusions)
- Easy to add new analyzers by implementing the `Analyzer` interface
- Scoring system properly handles projects that don't use all technologies (e.g., no SQL)
