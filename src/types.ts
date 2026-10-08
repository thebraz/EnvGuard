export const RULE_IDS = [
  'env/missing', 'env/unused', 'env/duplicate', 'env/conflict', 'env/malformed',
  'env/dynamic', 'env/source-syntax', 'env/required', 'env/schema', 'env/prohibited',
  'secret/hardcoded-token', 'secret/private-key', 'secret/credentials-url',
  'secret/hardcoded', 'secret/weak', 'secret/public-exposure',
  'git/env-tracked', 'git/env-not-ignored', 'git/unavailable', 'scan/skipped',
] as const;

export type RuleId = typeof RULE_IDS[number];
export type Severity = 'info' | 'warning' | 'error' | 'critical';
export interface SourceLocation { path: string; line?: number; column?: number }
export interface Finding {
  ruleId: RuleId;
  severity: Severity;
  message: string;
  variable?: string;
  location?: SourceLocation;
}
export interface EnvDefinition { name: string; value: string; location: SourceLocation }
export interface EnvUsage { name?: string; location: SourceLocation; dynamic?: boolean; provider?: 'process' | 'import-meta' }
export interface VariableSchema {
  required?: boolean;
  type?: 'string' | 'number' | 'boolean' | 'url';
  minLength?: number;
}
export interface Config {
  include: string[];
  exclude: string[];
  envFiles?: string[];
  templateFiles?: string[];
  required: string[];
  prohibited: string[];
  schema: Record<string, VariableSchema>;
  rules: Partial<Record<RuleId, boolean>>;
  severity: Partial<Record<RuleId, Severity>>;
  suppressions: Array<{ ruleId: RuleId; path?: string; line?: number; reason: string }>;
  failOn: Severity | 'none';
}
export interface ScanResult {
  version: string;
  command: string;
  summary: Record<Severity, number>;
  findings: Finding[];
  suppressed: number;
  disabled: number;
  filesScanned: number;
  exitCode: 0 | 1;
}
export const VERSION = '0.1.1';
export const SEVERITIES: Severity[] = ['info', 'warning', 'error', 'critical'];
export class EnvGuardError extends Error {}
