/**
 * ASCII banner for Cortex CLI.
 * Displayed on `cortex init` and `cortex --version`.
 */

import { brainPink, neuralCyan, synapseViolet } from './colors.js';

/**
 * Cortex ASCII banner.
 */
export const BANNER = `
  _____  ____  ____  ______ _______  __
 / ____// __ \\/ __ \\/_  __// ____/ |/ /
/ /    / / / / /_/ / / /  / __/  |   /
/ /___/ /_/ / _, _/ / /  / /___ /   |
\\____/\\____/_/ |_| /_/  /_____//_/|_|
`;

/**
 * Tagline for banner.
 */
export const TAGLINE = '🧠 Context optimization for AI coding agents';

/**
 * Get formatted banner with color.
 *
 * @param version - Optional version string
 * @returns Formatted banner
 */
export function getBanner(version?: string): string {
  const versionStr = version ? synapseViolet(`v${version}`) : '';
  return `${neuralCyan(BANNER)}\n${brainPink(TAGLINE)}\n${versionStr ? `${versionStr}\n` : ''}`;
}
