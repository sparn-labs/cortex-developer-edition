# Contributing to Cortex

Thank you for your interest in contributing to Cortex! This document provides guidelines and instructions for contributing to the project.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Development Setup](#development-setup)
- [Constitution](#constitution)
- [TDD Workflow](#tdd-workflow)
- [Contribution Process](#contribution-process)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)

---

## Code of Conduct

This project follows a simple code of conduct: **Be respectful and constructive**. We welcome contributions from developers of all experience levels.

---

## Development Setup

### Prerequisites

- **Node.js**: ≥18.0.0
- **npm**: ≥9.0.0 (comes with Node.js)
- **Git**: For version control

### Clone and Install

```bash
# Clone the repository
git clone https://github.com/sparn-labs/cortex.git
cd cortex

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test

# Run linter
npm run lint
```

### Available Scripts

```bash
npm run build        # Build with tsup (CJS + ESM + DTS)
npm run dev          # Watch mode for development
npm test             # Run all tests with vitest
npm run test:watch   # Run tests in watch mode
npm run lint         # Check code with biome
npm run lint:fix     # Fix linting issues automatically
npm run typecheck    # TypeScript type checking (no emit)
```

### Verify Installation

```bash
# Run init command
node dist/cli/index.js init

# Check that .cortex/ directory was created
ls -la .cortex/

# Run tests
npm test
```

---

## Constitution

Cortex follows a strict **Constitution** with 9 articles that govern all development. **All contributions must comply with these articles.**

### The 9 Articles

1. **CLI-First, Library-Second**: CLI must work perfectly before library API
2. **Algorithm Fidelity**: All optimizations must be deterministic and explainable
3. **Test-First Development (TDD)**: Tests written before implementation
4. **Agent-Agnostic Design**: Support multiple AI agents via adapters
5. **Complementary to RTK**: Work alongside RTK, not replace it
6. **Minimal Dependencies**: Only essential dependencies
7. **Simplicity First**: Avoid over-engineering
8. **Brand Consistency**: Follow color scheme and UI patterns
9. **Production-Quality TypeScript**: Strict mode, no `any` types

📄 **Full Constitution**: [`.specify/memory/constitution.md`](.specify/memory/constitution.md)

---

## TDD Workflow

Cortex uses **strict Test-Driven Development (TDD)**. This is not optional.

### The Red-Green-Refactor Cycle

```
1. 🔴 RED: Write failing test
   ↓
2. Run test → verify it FAILS
   ↓
3. 🟢 GREEN: Write minimal code to pass
   ↓
4. Run test → verify it PASSES
   ↓
5. ♻️  REFACTOR: Improve code while tests stay green
   ↓
6. Repeat
```

### Example TDD Flow

```typescript
// 1. 🔴 RED: Write test FIRST
describe('SparsePruner', () => {
  it('should keep only top 5% of entries', () => {
    const pruner = createSparsePruner({ threshold: 5 });
    const entries = createTestEntries(100);

    const result = pruner.prune(entries);

    expect(result.kept.length).toBe(5); // WILL FAIL - not implemented yet
  });
});

// 2. Run test → see it FAIL
// $ npm test
// ❌ FAIL: createSparsePruner is not defined

// 3. 🟢 GREEN: Implement minimal code
export function createSparsePruner(config: SparsePrunerConfig): SparsePruner {
  function prune(entries: MemoryEntry[]): PruneResult {
    const threshold = Math.ceil(entries.length * (config.threshold / 100));
    const kept = entries.slice(0, threshold);
    const removed = entries.slice(threshold);

    return { kept, removed };
  }

  return { prune };
}

// 4. Run test → see it PASS
// $ npm test
// ✅ PASS: should keep only top 5% of entries

// 5. ♻️ REFACTOR: Add TF-IDF scoring
// (Tests still pass after refactoring)
```

### TDD Rules

✅ **DO**:
- Write tests before implementation
- Confirm tests fail before implementing
- Keep tests simple and focused
- Test one thing per test
- Use descriptive test names

❌ **DON'T**:
- Write implementation before tests
- Skip the "verify failure" step
- Write tests after implementation
- Test multiple things in one test
- Use vague test names like "it works"

---

## Contribution Process

### 1. Find or Create an Issue

- Check [GitHub Issues](https://github.com/sparn-labs/cortex/issues) for open tasks
- Comment on an issue to claim it
- For new features, create an issue first to discuss

### 2. Fork and Branch

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/cortex.git
cd cortex

# Create a feature branch
git checkout -b feature/your-feature-name
```

### 3. Follow TDD

```bash
# 1. Write tests first
vim tests/unit/your-feature.test.ts

# 2. Verify tests fail
npm test

# 3. Implement feature
vim src/core/your-feature.ts

# 4. Verify tests pass
npm test

# 5. Ensure all tests still pass
npm test

# 6. Check types
npm run typecheck

# 7. Lint code
npm run lint:fix
```

### 4. Commit

```bash
# Stage changes
git add tests/unit/your-feature.test.ts
git add src/core/your-feature.ts

# Commit with descriptive message
git commit -m "feat: add sparse pruning with TF-IDF scoring

- Implement createSparsePruner factory
- Add TF-IDF relevance calculation
- Add sqrt term frequency capping
- Tests: 5 unit tests covering edge cases"
```

### 5. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create Pull Request on GitHub
# - Use descriptive title
# - Reference issue number (#123)
# - Describe what changed and why
# - Include test results
```

### 6. Code Review

- Respond to reviewer feedback
- Make requested changes
- Push updates to same branch
- PR updates automatically

---

## Project Structure

```
cortex/
├── src/
│   ├── core/              # Optimization modules (library)
│   │   ├── kv-memory.ts          # Key-value memory store
│   │   ├── sparse-pruner.ts      # Relevance filtering
│   │   ├── engram-scorer.ts      # Time-based decay scoring
│   │   ├── confidence-states.ts  # Entry classification (active/ready/silent)
│   │   ├── btsp-embedder.ts      # Critical event detection
│   │   └── sleep-compressor.ts   # Periodic consolidation
│   ├── adapters/          # Agent-specific adapters
│   │   ├── generic.ts            # Generic agent adapter
│   │   └── claude-code.ts        # Claude Code adapter
│   ├── cli/               # CLI commands
│   │   ├── commands/             # Command implementations
│   │   └── ui/                   # UI components (colors, banner)
│   ├── types/             # TypeScript interfaces
│   └── utils/             # Shared utilities
├── tests/
│   ├── unit/              # Unit tests (isolated modules)
│   └── integration/       # Integration tests (full workflows)
├── docs/                  # Documentation
├── specs/
│   └── 001-cortex-core/    # Project specifications
└── dist/                  # Build output (gitignored)
```

---

## Testing

### Test Organization

- **Unit Tests** (`tests/unit/`): Test individual modules in isolation
- **Integration Tests** (`tests/integration/`): Test full command workflows

### Writing Tests

```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

describe('ModuleName', () => {
  beforeEach(() => {
    // Setup before each test
  });

  afterEach(() => {
    // Cleanup after each test
  });

  it('should do something specific', () => {
    // Arrange
    const input = createTestData();

    // Act
    const result = moduleFunction(input);

    // Assert
    expect(result).toBe(expected);
  });
});
```

### Test Coverage Goals

- **Unit Tests**: >90% coverage for core modules
- **Integration Tests**: All CLI commands have happy path + error cases
- **Edge Cases**: Test boundaries, empty inputs, invalid data

### Running Tests

```bash
# Run all tests
npm test

# Run specific test file
npm test tests/unit/sparse-pruner.test.ts

# Run tests in watch mode
npm run test:watch

# Run tests with coverage (if configured)
npm test -- --coverage
```

---

## Code Style

### TypeScript

- **Strict Mode**: Enabled (`noUncheckedIndexedAccess`, `strictNullChecks`)
- **No `any` types**: Use proper types or `unknown`
- **Explicit return types**: On all public functions
- **Optional chaining**: Use `?.` for potentially undefined values
- **Nullish coalescing**: Use `??` instead of `||` for null/undefined

```typescript
// ✅ Good
export function calculateScore(entry: MemoryEntry): number {
  const count = entry.metadata?.count ?? 0;
  return count * 0.5;
}

// ❌ Bad
export function calculateScore(entry: any) {
  return entry.metadata.count * 0.5; // No type safety, no null handling
}
```

### Formatting

Cortex uses **Biome** for linting and formatting:

```bash
# Auto-fix issues
npm run lint:fix

# Check without fixing
npm run lint
```

### Naming Conventions

- **Files**: kebab-case (`sparse-pruner.ts`)
- **Interfaces**: PascalCase (`MemoryEntry`)
- **Functions**: camelCase (`calculateScore`)
- **Constants**: UPPER_SNAKE_CASE (`DEFAULT_TTL`)
- **Private functions**: camelCase with leading underscore (`_internalHelper`)

### Comments

- **JSDoc**: Required for all public APIs
- **Inline comments**: Only when necessary to explain "why", not "what"
- **TODO comments**: Discouraged; create issues instead

```typescript
/**
 * Calculate TF-IDF relevance score for a memory entry
 * @param entry - Memory entry to score
 * @param allEntries - All entries for IDF calculation
 * @returns Relevance score (0.0-1.0)
 */
export function scoreEntry(entry: MemoryEntry, allEntries: MemoryEntry[]): number {
  // ... implementation
}
```

---

## Commit Messages

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring (no behavior change)
- `perf`: Performance improvement
- `chore`: Build process, dependencies, etc.

### Examples

```bash
# Feature with body
git commit -m "feat(sparse-pruner): add TF-IDF scoring

Implement term frequency-inverse document frequency algorithm
for relevance scoring. Uses sqrt capping to prevent common
words from dominating scores.

Closes #42"

# Simple fix
git commit -m "fix(engram-scorer): handle zero TTL edge case"

# Test addition
git commit -m "test(btsp): add stack trace detection tests"

# Documentation
git commit -m "docs: update NEUROSCIENCE.md with BTSP examples"
```

---

## Questions?

- **Issues**: [GitHub Issues](https://github.com/sparn-labs/cortex/issues)
- **Discussions**: [GitHub Discussions](https://github.com/sparn-labs/cortex/discussions)
- **Email**: [Your contact email]

---

**Thank you for contributing to Cortex!**
