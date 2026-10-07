import { SEVERITIES, type ScanResult } from './types.js';

export function report(result: ScanResult, format: 'text' | 'json'): string {
  if (format === 'json') return `${JSON.stringify(result, null, 2)}\n`;
  const counts = [...SEVERITIES].reverse().filter(level => result.summary[level]).map(level => `${result.summary[level]} ${level}`).join(' · ');
  const lines = ['EnvGuard', '', counts || 'Checks passed.'];
  if (result.suppressed || result.disabled) lines.push(`${result.suppressed} suppressed · ${result.disabled} disabled findings`);
  for (const finding of result.findings) {
    lines.push('', `${finding.severity.toUpperCase()} ${finding.ruleId}`);
    if (finding.location) lines.push(`${finding.location.path}${finding.location.line ? `:${finding.location.line}` : ''}`);
    if (finding.variable) lines.push(finding.variable);
    lines.push(finding.message);
  }
  return `${lines.join('\n')}\n`;
}

export function errorReport(message: string, format: 'text' | 'json'): string {
  return format === 'json' ? `${JSON.stringify({ error: { code: 'execution-error', message }, exitCode: 2 })}\n` : `EnvGuard: ${message}\n`;
}
