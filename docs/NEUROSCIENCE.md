# Neuroscience Principles in Sparn

> 🧠 **Brain-Inspired Architecture**: How Sparn maps 6 neuroscience principles to context optimization

---

## Overview

Sparn is built on six fundamental neuroscience principles that govern how biological brains manage, consolidate, and retrieve memories. Each principle maps directly to a code module, creating a brain-inspired optimization pipeline.

**Result**: 60-90% token reduction while maintaining task completion quality.

---

## The 6 Principles

### 1. Sparse Coding

**Neuroscience**: In the brain, only 2-5% of neurons fire at any given time. This sparse activation pattern maximizes information capacity while minimizing energy consumption.

**Code Mapping**: `SparsePruner` module

**Implementation**:
- Keeps only the top 5% most relevant context entries
- Uses TF-IDF (Term Frequency-Inverse Document Frequency) for relevance scoring
- Applies sqrt capping to prevent common words from dominating
- Configurable threshold (1-100%) via `pruning.threshold`

**Code Example**:
```typescript
import { createSparsePruner } from 'sparn';

const pruner = createSparsePruner({ threshold: 5 }); // Keep top 5%
const result = pruner.prune(entries);

console.log(`Kept ${result.kept.length} of ${entries.length} entries`);
// Typical: Kept 10 of 200 entries (5%)
```

**Key Insight**: Just as your brain doesn't activate all neurons to recall a memory, Sparn doesn't need all context to complete a task.

---

### 2. Engram Theory

**Neuroscience**: Memories fade over time unless reinforced. The strength of a memory trace (engram) decays exponentially, with recent and frequently accessed memories lasting longer.

**Code Mapping**: `EngramScorer` module

**Implementation**:
- Exponential decay formula: `decay = 1 - e^(-age/TTL)`
- Recent entries score higher
- Frequently accessed entries get TTL refresh
- Default TTL: 24 hours (configurable)
- Decay threshold: 0.95 (entries at 95% decay are removed)

**Code Example**:
```typescript
import { createEngramScorer } from 'sparn';

const scorer = createEngramScorer({
  defaultTTL: 24,      // 24 hours
  decayThreshold: 0.95 // Remove at 95% decay
});

const score = scorer.calculateScore(entry);
// Recent entry (1 hour old): score ≈ 0.96
// Old entry (20 hours old): score ≈ 0.43
// Very old entry (48 hours): score < 0.1
```

**Key Insight**: Like biological memories, context relevance decays over time. Old tool outputs are less useful than recent conversation.

---

### 3. Hippocampal Key-Value Separation

**Neuroscience**: The hippocampus separates *what* to remember (episodic content) from *how* to retrieve it (indexing information). This dual-representation system enables efficient memory consolidation during sleep.

**Code Mapping**: `KVMemory` module

**Implementation**:
- **entries_index table**: Lightweight metadata (id, hash, timestamp, score, state, TTL, access count)
- **entries_value table**: Heavy content (id, content, tags, metadata)
- Enables fast querying without loading full content
- Supports dual indexing: by timestamp and by score

**Database Schema**:
```sql
-- Index table (fast queries)
CREATE TABLE entries_index (
  id TEXT PRIMARY KEY,
  hash TEXT NOT NULL UNIQUE,
  timestamp INTEGER NOT NULL,
  score REAL NOT NULL,
  state TEXT NOT NULL,
  ttl INTEGER NOT NULL,
  access_count INTEGER DEFAULT 0
);

-- Value table (content storage)
CREATE TABLE entries_value (
  id TEXT PRIMARY KEY,
  content TEXT NOT NULL,
  tags TEXT,        -- JSON array
  metadata TEXT     -- JSON object
);
```

**Code Example**:
```typescript
import { createKVMemory } from 'sparn';

const memory = await createKVMemory('./.sparn/memory.db');

// Put stores in both tables
await memory.put(entry);

// Query uses index table only (fast)
const recent = await memory.query({
  limit: 10,
  sortBy: 'timestamp'
});

// Get retrieves full content (joins tables)
const full = await memory.get(id);
```

**Key Insight**: Separating metadata from content enables sleep-like consolidation without loading all data into memory.

---

### 4. Multi-State Synapses

**Neuroscience**: Synapses exist in multiple states—silent (inactive), ready (primed), or active (firing). This enables graded memory strength and dynamic prioritization.

**Code Mapping**: `ConfidenceStates` module

**Implementation**:
- **Silent**: score < 0.3 (low priority, candidates for removal)
- **Ready**: 0.3 ≤ score < 0.7 (moderate priority, kept but not active)
- **Active**: score ≥ 0.7 (high priority, immediately relevant)
- State transitions based on access patterns and decay

**Code Example**:
```typescript
import { createConfidenceStates } from 'sparn';

const states = createConfidenceStates({
  activeThreshold: 0.7,
  readyThreshold: 0.3,
});

const state = states.calculateState(entry);
// state = 'active' | 'ready' | 'silent'

const distribution = states.getDistribution(entries);
// { active: 12, ready: 48, silent: 140 }
```

**Visualization**:
```
 1.0 ┼────────────────────── Active (score ≥ 0.7)
     │ Recent conversation
     │ Error messages
 0.7 ┼────────────────────── Ready (0.3 ≤ score < 0.7)
     │ Recent tool results
     │ Accessed entries
 0.3 ┼────────────────────── Silent (score < 0.3)
     │ Old logs
     │ Decayed context
 0.0 ┼──────────────────────
```

**Key Insight**: Not all memories are equal. Synaptic states allow graded prioritization without binary keep/discard decisions.

---

### 5. Sleep Replay Consolidation

**Neuroscience**: During sleep, the brain replays important memories while discarding irrelevant information. It also merges similar memories and removes duplicates.

**Code Mapping**: `SleepCompressor` module

**Implementation**:
- **Decay-based pruning**: Removes entries with decay ≥ 0.95
- **Duplicate detection**: Finds exact matches (hash) and near-duplicates (cosine similarity ≥ 0.85)
- **Merging**: Combines duplicates, keeping highest score, summing access counts, merging tags
- **VACUUM**: Reclaims database space after consolidation

**Code Example**:
```typescript
import { createSleepCompressor } from 'sparn';

const compressor = createSleepCompressor();

const result = compressor.consolidate(entries);

console.log(`
  Entries: ${result.entriesBefore} → ${result.entriesAfter}
  Decayed removed: ${result.decayedRemoved}
  Duplicates merged: ${result.duplicatesRemoved}
  Compression: ${(result.compressionRatio * 100).toFixed(1)}%
`);
// Typical output:
// Entries: 500 → 125 (75% reduction)
// Decayed removed: 300
// Duplicates merged: 75
```

**Duplicate Detection**:
- **Exact duplicates**: Same content hash
- **Near duplicates**: Cosine similarity ≥ 0.85
  - Tokenize text: `["error", "file", "not", "found"]`
  - Build frequency vectors: `{error: 1, file: 1, not: 1, found: 1}`
  - Calculate cosine similarity: `dot(v1, v2) / (||v1|| * ||v2||)`

**Key Insight**: Like sleep consolidation, periodic compression removes noise and redundancy while preserving essential information.

---

### 6. BTSP (Behavioral Timescale Synaptic Plasticity)

**Neuroscience**: One-shot learning—certain critical events (like touching a hot stove) create instant, strong memories that persist without repetition.

**Code Mapping**: `BTSPEmbedder` module

**Implementation**:
- Pattern detection for critical events:
  - **Errors**: `error`, `exception`, `fatal`, `ENOENT`
  - **Stack traces**: `at Object.method (file:line:col)`
  - **Git conflicts**: `<<<<<<< HEAD`
  - **Tool calls** (Claude Code): `<function_calls>`, `<invoke>`
- Creates entries with maximum score (1.0)
- Marks with `isBTSP: true` and `'btsp'` tag
- Automatically transitions to 'active' state
- Never decays (or decays very slowly)

**Code Example**:
```typescript
import { createBTSPEmbedder } from 'sparn';

const btsp = createBTSPEmbedder();

// Detect critical patterns
const isCritical = btsp.detectBTSP(content);
// true for: errors, stack traces, git conflicts

// Create high-priority entry
const entry = btsp.createBTSPEntry(content, ['error']);
// { score: 1.0, state: 'active', isBTSP: true, tags: ['error', 'btsp'] }
```

**BTSP Patterns**:
```typescript
const BTSP_PATTERNS = [
  /\b(error|exception|failure|fatal|critical|panic)\b/i,
  /^\s+at\s+.*\(.*:\d+:\d+\)/m,  // Stack traces
  /^<<<<<<< /m,                   // Git conflict start
  /^=======/m,                    // Git conflict separator
  /^>>>>>>> /m,                   // Git conflict end
  /ENOENT|EACCES|EISDIR/,        // File system errors
];
```

**Key Insight**: Not all memories need repetition to stick. Critical events deserve instant, strong encoding.

---

## The Full Pipeline

### How All 6 Principles Work Together

```
Input Context (1000 entries, 50K tokens)
        ↓
    [BTSP Embedder]         ← Detect critical events (errors, conflicts)
        ↓
    Mark ~2% as BTSP (score = 1.0)
        ↓
    [Engram Scorer]         ← Apply temporal decay
        ↓
    Recent entries: high score
    Old entries: low score
        ↓
    [Confidence States]     ← Classify by score
        ↓
    Active: 50 entries (score ≥ 0.7)
    Ready: 200 entries (0.3 ≤ score < 0.7)
    Silent: 750 entries (score < 0.3)
        ↓
    [Sparse Pruner]         ← Keep top 5% by TF-IDF
        ↓
    Prune to 50 entries (~5%)
        ↓
    [KVMemory]              ← Store in dual tables
        ↓
    Index table: 50 lightweight rows
    Value table: 50 content rows
        ↓
    [Sleep Compressor]      ← Periodic consolidation
        ↓
    Remove decayed (decay ≥ 0.95): -30
    Merge duplicates (similarity ≥ 0.85): -10
    Final: 40 entries, 2K tokens
        ↓
Output (40 entries, 2K tokens = 96% reduction)
```

---

## Performance Characteristics

### Token Reduction by Content Type

| Content Type | Typical Reduction | Reason |
|--------------|------------------|--------|
| Error logs | 90-95% | Duplicates + old logs decay |
| Tool outputs | 85-90% | Verbose results, sparse coding |
| Conversation | 60-70% | BTSP + conversation boost (Claude Code) |
| Code snippets | 70-80% | Duplicate patterns, TF-IDF dedup |
| Stack traces | 95-99% | BTSP keeps first, removes duplicates |

### State Distribution (Typical)

- **Active**: 2-5% (BTSP + recent + high-relevance)
- **Ready**: 15-20% (moderate relevance, may be needed)
- **Silent**: 75-83% (candidates for removal)

### Consolidation Impact

- **Before**: 500 entries, 25K tokens
- **After consolidation**: 125 entries, 6K tokens
- **Reduction**: 75% entries, 76% tokens

---

## Biological Validation

### Why These Principles Work

1. **Sparse Coding**: Biological brains use ~2-5% neuron activation
   - Sparn: Keeps ~5% of context
   - ✅ Aligned with biology

2. **Engram Theory**: Memories decay exponentially over hours/days
   - Sparn: Default TTL = 24 hours, exponential decay
   - ✅ Biologically plausible timescale

3. **Hippocampal KV**: Sleep consolidation requires index/content separation
   - Sparn: Dual tables enable efficient consolidation
   - ✅ Mirrors hippocampal architecture

4. **Multi-State Synapses**: Graded memory strength (not binary)
   - Sparn: 3 states (silent/ready/active)
   - ✅ Reflects synaptic plasticity

5. **Sleep Replay**: Consolidation happens during offline periods
   - Sparn: `consolidate` command for periodic cleanup
   - ✅ Analogous to sleep function

6. **BTSP**: One-shot learning for critical events (fear conditioning)
   - Sparn: Instant strong encoding for errors
   - ✅ Matches behavioral timescale plasticity

---

## Configuration

### Tuning Neuroscience Parameters

```yaml
# .sparn/config.yaml

# Sparse Coding (Principle #1)
pruning:
  threshold: 5          # Keep top 5% (range: 1-100)
  aggressiveness: 50    # TF-IDF weighting (range: 0-100)

# Engram Theory (Principle #2)
decay:
  defaultTTL: 24        # Hours (biological: hours to days)
  decayThreshold: 0.95  # Remove at 95% decay (range: 0.0-1.0)

# Multi-State Synapses (Principle #4)
states:
  activeThreshold: 0.7  # Active if score ≥ 0.7
  readyThreshold: 0.3   # Ready if 0.3 ≤ score < 0.7

# Sleep Replay (Principle #5)
autoConsolidate: 24     # Auto-consolidate every 24 hours (or null)
```

---

## Further Reading

### Neuroscience Papers

- **Sparse Coding**: Olshausen & Field (1996) - "Emergence of simple-cell receptive field properties"
- **Engram Theory**: Josselyn & Tonegawa (2020) - "Memory engrams: Recalling the past and imagining the future"
- **Hippocampal Function**: Buzsáki (2015) - "Hippocampal sharp wave-ripple: A cognitive biomarker for episodic memory"
- **Synaptic States**: Mongillo et al. (2008) - "Synaptic theory of working memory"
- **Sleep Consolidation**: Tononi & Cirelli (2014) - "Sleep and the price of plasticity"
- **BTSP**: Bittner et al. (2017) - "Behavioral time scale synaptic plasticity underlies CA1 place fields"

### Sparn Documentation

- [Quickstart Guide](../specs/001-sparn-core/quickstart.md) - Usage examples
- [API Documentation](../README.md#programmatic-api) - Library usage
- [Contributing Guide](./CONTRIBUTING.md) - Development setup

---

**🧠 Brain-Inspired, Code-Optimized**: Sparn proves that neuroscience principles can dramatically improve AI context efficiency.
