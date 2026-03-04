/**
 * Cortex - Context optimization for AI coding agents
 *
 * Main library export for programmatic API usage.
 * Per Article I: CLI-First, Library-Second - all core modules are importable.
 */

export { createClaudeCodeAdapter } from './adapters/claude-code.js';
export { createGenericAdapter } from './adapters/generic.js';
export type { AnalysisHistory, AnalysisHistoryEntry } from './core/analyzers/analysis-history.js';
export { computeTrend, createAnalysisHistory } from './core/analyzers/analysis-history.js';
export { createArchitectureAnalyzer } from './core/analyzers/architecture-analyzer.js';
export type { AnalysisBaseline, BaselineFinding } from './core/analyzers/baseline.js';
export {
  diffFindings,
  fingerprint,
  loadBaseline,
  saveBaseline,
} from './core/analyzers/baseline.js';
export {
  buildAnalysisContext,
  buildChangedFilesContext,
  buildSingleFileContext,
  getProjectName,
} from './core/analyzers/context-builder.js';
export type { CortexIgnore, IgnoreRule } from './core/analyzers/cortexignore.js';
export { createCortexIgnore, parseCortexIgnore } from './core/analyzers/cortexignore.js';
export { createDatabaseAnalyzer } from './core/analyzers/database-analyzer.js';
export { createQualityAnalyzer } from './core/analyzers/quality-analyzer.js';
export {
  buildActionPlanItems,
  buildReport,
  generateJSONReport,
  generateMarkdownReport,
} from './core/analyzers/report-generator.js';
export { computeScore, mapGrade } from './core/analyzers/scoring.js';
export { createSecurityAnalyzer } from './core/analyzers/security-analyzer.js';
export { createTestDocsAnalyzer } from './core/analyzers/testdocs-analyzer.js';
export { createTokenAnalyzer } from './core/analyzers/token-analyzer.js';
// Analyzers
export type {
  ActionPlanItem,
  AnalysisCategory,
  AnalysisContext,
  AnalysisReport,
  Analyzer,
  AnalyzerFinding,
  AnalyzeThresholds,
  CategoryResult,
  FixType,
  Grade,
  ScoreResult,
  Severity,
} from './core/analyzers/types.js';
export { DEFAULT_THRESHOLDS } from './core/analyzers/types.js';
export type { BTSPEmbedder, BTSPEmbedderConfig } from './core/btsp-embedder.js';
export { createBTSPEmbedder } from './core/btsp-embedder.js';
export type { BudgetPruner, BudgetPrunerConfig } from './core/budget-pruner.js';
export { createBudgetPruner, createBudgetPrunerFromConfig } from './core/budget-pruner.js';
// v1.5.0 — Legal & Regulatory Compliance Analyzer
export { runComplyAudit } from './core/comply/engine.js';
export { generateComplyJSON, generateComplyMarkdown } from './core/comply/report.js';
export { computeComplyScore, mapComplyGrade } from './core/comply/scorer.js';
export type {
  ComplianceFramework,
  ComplyAuditOptions,
  ComplyFinding,
  ComplyGrade,
  ComplyLayerResult,
  ComplyLayerScore,
  ComplyRemediationRoadmap,
  ComplyReport,
  ComplySeverity,
  DataFlowSummary,
  FrameworkComplianceMatrix,
  RegulatoryReference,
} from './core/comply/types.js';
export { COMPLY_LAYER_NAMES, COMPLY_LAYER_WEIGHTS } from './core/comply/types.js';
export type { ConfidenceStates, ConfidenceStatesConfig } from './core/confidence-states.js';
export { createConfidenceStates } from './core/confidence-states.js';
export type {
  ContextPipeline,
  ContextPipelineConfig,
  ContextPipelineStats,
} from './core/context-pipeline.js';
export { createContextPipeline } from './core/context-pipeline.js';
// v1.4.0 — Debt Tracker
export type {
  DebtSeverity,
  DebtStats,
  DebtStatus,
  DebtTracker,
  TechDebt,
} from './core/debt-tracker.js';
export { createDebtTracker } from './core/debt-tracker.js';
// v1.4.0 — Dependency Graph
export type {
  DependencyEdge,
  DependencyGraph,
  DependencyGraphConfig,
  DependencyNode,
  GraphAnalysis,
} from './core/dependency-graph.js';
export { createDependencyGraph } from './core/dependency-graph.js';
// v1.4.0 — Docs Generator
export type { DocsGenerator, DocsGeneratorConfig } from './core/docs-generator.js';
export { createDocsGenerator } from './core/docs-generator.js';
export type { EngramScorer, EngramScorerConfig } from './core/engram-scorer.js';
export { createEngramScorer } from './core/engram-scorer.js';
export type {
  IncrementalOptimizer,
  IncrementalOptimizerConfig,
  IncrementalOptimizerState,
} from './core/incremental-optimizer.js';
export { createIncrementalOptimizer } from './core/incremental-optimizer.js';
export type { FTSResult, KVMemory } from './core/kv-memory.js';
// Core modules
export { createKVMemory } from './core/kv-memory.js';
export type { MetricsCollector, MetricsSnapshot } from './core/metrics.js';
export { createMetricsCollector, getMetrics } from './core/metrics.js';
// v1.4.0 — Search Engine
export type { IndexStats, SearchEngine, SearchOpts, SearchResult } from './core/search-engine.js';
export { createSearchEngine } from './core/search-engine.js';
// v1.4.0 — Enterprise Security Analyzer
export { runSecureAudit } from './core/secure/engine.js';
export { generateSecureJSON, generateSecureMarkdown } from './core/secure/report.js';
export { computeSecureScore, mapSecureGrade } from './core/secure/scorer.js';
export type {
  AttackSurface,
  ComplianceMatrix,
  LayerResult,
  RemediationRoadmap,
  SecureAuditOptions,
  SecureFinding,
  SecureGrade,
  SecureReport,
  SecureSeverity,
} from './core/secure/types.js';
export { LAYER_NAMES, LAYER_WEIGHTS } from './core/secure/types.js';
export type { SleepCompressor } from './core/sleep-compressor.js';
export { createSleepCompressor } from './core/sleep-compressor.js';
export type { SparsePruner, SparsePrunerConfig } from './core/sparse-pruner.js';
export { createSparsePruner } from './core/sparse-pruner.js';
// v1.4.0 — Workflow Planner
export type {
  CortexPlan,
  PlanExecConstraints,
  PlanStep,
  PlanVerifyResult,
  WorkflowPlanner,
} from './core/workflow-planner.js';
export { createWorkflowPlanner } from './core/workflow-planner.js';
export type {
  DaemonCommand,
  DaemonStartResult,
  DaemonStatusResult,
  DaemonStopResult,
} from './daemon/daemon-process.js';
export { createDaemonCommand } from './daemon/daemon-process.js';
// Daemon
export type { FilePosition, FileTracker } from './daemon/file-tracker.js';
export { createFileTracker } from './daemon/file-tracker.js';
export type {
  SessionStats,
  SessionWatcher,
  SessionWatcherConfig,
} from './daemon/session-watcher.js';
export { createSessionWatcher } from './daemon/session-watcher.js';
// MCP
export type { CortexMcpServerOptions } from './mcp/server.js';
export { createCortexMcpServer } from './mcp/server.js';
export type {
  AgentAdapter,
  OptimizationResult,
  OptimizeOptions,
} from './types/adapter.js';
export type {
  AgentType,
  AnalyzeConfig,
  CortexConfig,
  DecayConfig,
  PruningConfig,
  RealtimeConfig,
  StatesConfig,
  UIConfig,
} from './types/config.js';
export { DEFAULT_CONFIG } from './types/config.js';
export type { ConsolidateResult, DuplicateGroup } from './types/consolidate.js';
// Types
export type {
  ConfidenceState,
  MemoryEntry,
  MemoryQueryFilters,
  StateDistribution,
} from './types/memory.js';
export type { PruneResult } from './types/pruner.js';
export type { BlockType, JSONLMessage } from './utils/context-parser.js';
export {
  createEntry,
  parseClaudeCodeContext,
  parseGenericContext,
  parseJSONLContext,
  parseJSONLLine,
} from './utils/context-parser.js';
export { hashContent } from './utils/hash.js';
export type { Logger, LogLevel } from './utils/logger.js';
export { createLogger } from './utils/logger.js';
// Utilities
export type { TFIDFIndex } from './utils/tfidf.js';
export {
  calculateIDF,
  calculateTF,
  calculateTFIDF,
  createTFIDFIndex,
  scoreTFIDF,
  tokenize,
} from './utils/tfidf.js';
export {
  countTokensPrecise,
  estimateTokens,
  setPreciseTokenCounting,
} from './utils/tokenizer.js';
