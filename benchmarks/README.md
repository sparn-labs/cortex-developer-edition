# Sparn Benchmarks

Performance benchmarks for Sparn's context optimization.

## Running Benchmarks

```bash
# Run all benchmarks
node benchmarks/run-all.js

# Run specific benchmark
node benchmarks/token-reduction.js
node benchmarks/processing-speed.js
node benchmarks/memory-usage.js
```

## Benchmark Categories

### 1. Token Reduction (`token-reduction.js`)
Measures token reduction percentage across different context sizes:
- Small context (1K tokens)
- Medium context (10K tokens)
- Large context (100K tokens)

**Expected Results:**
- 60-90% reduction across all sizes
- Higher reduction on verbose/redundant content
- Lower reduction on highly compact content

### 2. Processing Speed (`processing-speed.js`)
Measures optimization duration in milliseconds:
- Time to parse context
- Time to apply neuroscience principles
- Time to write optimized output

**Expected Results:**
- Small: <100ms
- Medium: <500ms
- Large: <2000ms

### 3. Memory Usage (`memory-usage.js`)
Measures memory footprint during optimization:
- Peak memory usage
- Memory per entry
- Database growth rate

**Expected Results:**
- Linear memory growth with context size
- Efficient database compaction
- Minimal memory leaks

## Interpreting Results

Results are saved to `benchmarks/results/` as JSON files:

```json
{
  "timestamp": "2026-02-22T15:30:00.000Z",
  "benchmark": "token-reduction",
  "results": {
    "small": { "reduction": 0.75, "tokens_before": 1000, "tokens_after": 250 },
    "medium": { "reduction": 0.82, "tokens_before": 10000, "tokens_after": 1800 },
    "large": { "reduction": 0.88, "tokens_before": 100000, "tokens_after": 12000 }
  }
}
```

## CI Integration

Benchmarks run automatically on:
- Pull requests (regression detection)
- Nightly builds (long-term tracking)
- Release candidates (performance validation)

Regressions >10% trigger build failures.
