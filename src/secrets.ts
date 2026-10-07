import { EnvGuardError, type Finding, type SourceLocation } from './types.js';

interface Assignment { name: string; value: string; location: SourceLocation; rawValue?: string }
interface SecretOptions { template?: boolean; environment?: boolean; assignments?: Assignment[] }
const MAX_SECRET_RECORDS = 20_000;

const PUBLIC_PREFIX = /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_)/i;
const WEAK = /^(?:password|passwd|admin|root|changeme|change[-_ ]?me|secret|development|develop|test|testing|default|123456(?:78|789|7890)?|qwerty|letmein|welcome)$/i;

function normalizedName(name: string): string {
  return name.replace(/([A-Z])([A-Z][a-z])/g, '$1_$2').replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[.-]/g, '_').toLowerCase();
}

export function isSensitiveName(name: string): boolean {
  const normalized = normalizedName(name);
  if (/(?:^|_)(?:name|path|file|filename|length|ttl|expiry|expiration|url|uri|endpoint|host|port)$/.test(normalized)) return false;
  return /(?:^|_)(?:password|passwd|pwd|secret|token|credentials?|private_key|api_key|access_key|signing_key|encryption_key|jwt_key)(?:_|$)/.test(normalized);
}

export function isPublicSecret(name: string): boolean {
  return PUBLIC_PREFIX.test(name) && isSensitiveName(name.replace(PUBLIC_PREFIX, ''));
}

export function isPlaceholder(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.length === 0 || WEAK.test(trimmed)
    || /^(?:placeholder|redacted|example|sample|dummy|todo|tbd|none|null|undefined|replace[-_ ]?me)$/i.test(trimmed)
    || /^(?:your[-_ ]|insert[-_ ]|replace[-_ ]|example[-_ ]|sample[-_ ]|dummy[-_ ])/i.test(trimmed)
    || /^<[^<>\n]+>$/.test(trimmed) || /^\$\{[^{}\n]+\}$/.test(trimmed)
    || /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(trimmed) || /^\{\{[^{}\n]+\}\}$/.test(trimmed)
    || /^(?:x{4,}|\*{4,})$/i.test(trimmed);
}

const TOKEN_RULES = [
  { pattern: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g, message: 'Possible GitHub access token is hardcoded.' },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g, message: 'Possible GitHub access token is hardcoded.' },
  { pattern: /\bglpat-[A-Za-z0-9_-]{20,100}\b/g, message: 'Possible GitLab access token is hardcoded.' },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,200}\b/g, message: 'Possible Slack access token is hardcoded.' },
];

function locations(text: string, path: string): (offset: number) => SourceLocation {
  const starts = [0];
  for (let offset = 0; offset < text.length; offset++) {
    if (text[offset] === '\n') starts.push(offset + 1);
  }
  return (offset: number): SourceLocation => {
    let low = 0;
    let high = starts.length;
    while (low + 1 < high) {
      const middle = Math.floor((low + high) / 2);
      if ((starts[middle] ?? 0) <= offset) low = middle; else high = middle;
    }
    return { path, line: low + 1, column: offset - (starts[low] ?? 0) + 1 };
  };
}

function decodeCredential(value: string): string {
  try { return decodeURIComponent(value); } catch { return value; }
}

function decodeQuoted(value: string, yaml: boolean): string {
  const body = value.slice(1, -1);
  if (value[0] === "'") return yaml ? body.replaceAll("''", "'") : body;
  const escapes: Record<string, string> = { '0': '\0', a: '\x07', b: '\b', t: '\t', n: '\n', v: '\v', f: '\f', r: '\r', e: '\x1b', ' ': ' ', '"': '"', '/': '/', '\\': '\\', N: '\x85', L: '\u2028', P: '\u2029' };
  return body.replace(/\\(?:U([0-9a-fA-F]{8})|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|([0abtnvfre "/\\NLP]))/g, (match, wide: string | undefined, unicode: string | undefined, hex: string | undefined, escape: string | undefined) => {
    const digits = wide ?? unicode ?? hex;
    if (digits !== undefined) {
      const point = Number.parseInt(digits, 16);
      return point <= 0x10ffff ? String.fromCodePoint(point) : match;
    }
    return escape !== undefined ? escapes[escape] ?? match : match;
  });
}

/** Lightweight context for structured configuration; JS/TS assignments come from its AST. */
function configurationAssignments(text: string, path: string): Assignment[] {
  if (!/\.(?:json|ya?ml|toml)$/i.test(path)) return [];
  const found: Assignment[] = [];
  if (/\.json$/i.test(path)) {
    try {
      const queue: unknown[] = [JSON.parse(text)];
      while (queue.length > 0) {
        const item = queue.pop();
        if (typeof item === 'string') { found.push({ name: '', value: item, location: { path } }); continue; }
        if (typeof item !== 'object' || item === null) continue;
        for (const [name, value] of Object.entries(item)) {
          if (typeof value === 'string') found.push({ name, value, location: { path } });
          else if (typeof value === 'object' && value !== null) queue.push(value);
        }
      }
      return found;
    } catch { /* Malformed structured data remains eligible for high-confidence scans. */ }
  }
  const sourceLines = text.split(/\r?\n/);
  for (let index = 0; index < sourceLines.length; index++) {
    const line = sourceLines[index] ?? '';
    const match = /^\s*["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]/.exec(line);
    if (!match || !isSensitiveName(match[1] ?? '')) continue;
    let value = line.slice(match[0].length).trim();
    let rawValue: string | undefined;
    if (value.startsWith('"') || value.startsWith("'")) {
      const yaml = /\.ya?ml$/i.test(path);
      const quoted = (value.startsWith('"') ? /^"(?:[^"\\]|\\.)*"/u : yaml ? /^'(?:[^']|'')*'/u : /^'[^']*'/u).exec(value)?.[0];
      if (!quoted) continue;
      rawValue = quoted.slice(1, -1);
      value = decodeQuoted(quoted, yaml);
    } else value = value.split(' #', 1)[0]?.trim() ?? '';
    if (rawValue === undefined && (value === '|' || value === '>' || value.startsWith('[') || value.startsWith('{'))) continue;
    found.push({ name: match[1] ?? '', value, rawValue, location: { path, line: index + 1, column: line.indexOf(match[1] ?? '') + 1 } });
  }
  return found;
}

/** Candidate values stay inside analysis and are never part of a finding. */
export function analyzeSecrets(text: string, path: string, options: SecretOptions = {}): { findings: Finding[]; secrets: string[] } {
  const findings: Finding[] = [];
  const candidates = new Set<string>();
  const emitted = new Set<string>();
  const locatedCandidates = new Set<string>();
  const locate = locations(text, path);
  const assignments = options.assignments ?? configurationAssignments(text, path);
  const retainCandidate = (candidate: string): void => {
    if (candidate.length === 0) return;
    if (!candidates.has(candidate) && candidates.size >= MAX_SECRET_RECORDS) throw new EnvGuardError('Secret analysis exceeds the 20,000 candidate limit.');
    candidates.add(candidate);
  };
  const add = (ruleId: Finding['ruleId'], severity: Finding['severity'], message: string, location: SourceLocation, candidate: string): void => {
    retainCandidate(candidate);
    const candidateKey = `${ruleId}\0${location.path}\0${candidate}`;
    if (location.line === undefined && locatedCandidates.has(candidateKey)) return;
    locatedCandidates.add(candidateKey);
    const key = `${ruleId}\0${location.path}\0${location.line ?? 0}\0${candidate}`;
    if (emitted.has(key)) return;
    if (findings.length >= MAX_SECRET_RECORDS) throw new EnvGuardError('Secret analysis exceeds the 20,000 finding limit.');
    emitted.add(key);
    findings.push({ ruleId, severity, message, location });
  };
  const formats = (source: string, locationAt: (offset: number) => SourceLocation): boolean => {
    let detected = false;
    for (const rule of TOKEN_RULES) {
      rule.pattern.lastIndex = 0;
      for (const match of source.matchAll(rule.pattern)) {
        detected = true;
        add('secret/hardcoded-token', 'critical', rule.message, locationAt(match.index), match[0]);
      }
    }
    const markers = [...source.matchAll(/-----(BEGIN|END) (?:(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/g)];
    for (let index = 0; index < markers.length; index++) {
      const match = markers[index];
      if (!match || match[1] !== 'BEGIN') continue;
      detected = true;
      const next = markers[index + 1];
      const materialEnd = next ? next.index + (next[1] === 'END' ? next[0].length : 0) : source.length;
      add('secret/private-key', 'critical', 'Possible private-key material is present.', locationAt(match.index), source.slice(match.index, materialEnd));
      const body = source.slice(match.index + match[0].length, next?.index ?? source.length)
        .split(/\r\n|[\n\r\u2028\u2029]/).map(line => line.replace(/\s/g, '')).filter(line => /^[A-Za-z0-9+/=_-]+$/.test(line));
      for (const line of body) retainCandidate(line);
      retainCandidate(body.join(''));
      retainCandidate(body.filter(line => !line.startsWith('=')).join(''));
    }
    for (const match of source.matchAll(/\b[A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/[^\s"'`<>]{1,4096}/g)) {
      const authority = match[0].slice(match[0].indexOf('://') + 3).split(/[/?#]/, 1)[0] ?? '';
      const at = authority.lastIndexOf('@');
      if (at < 0) continue;
      const credentials = authority.slice(0, at);
      const separator = credentials.indexOf(':');
      if (separator < 0) continue;
      const password = decodeCredential(credentials.slice(separator + 1));
      if (password.length === 0 || (options.template && isPlaceholder(password))) continue;
      detected = true;
      add('secret/credentials-url', 'error', 'URL contains embedded credentials.', locationAt(match.index), match[0]);
      retainCandidate(password);
      retainCandidate(credentials);
    }
    return detected;
  };

  formats(text, locate);
  for (const assignment of assignments) {
    const { name, value, location, rawValue } = assignment;
    if (isSensitiveName(name) || isPublicSecret(name)) {
      retainCandidate(value);
      if (rawValue !== undefined) retainCandidate(rawValue);
    }
    if (isPublicSecret(name)) add('secret/public-exposure', 'critical', 'Client-visible environment configuration has a sensitive name.', location, value);
    const knownFormat = formats(value, () => location);
    if (!isSensitiveName(name) || value.trim().length === 0) continue;
    const awsKey = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/.exec(value);
    if (awsKey && /(?:aws|access[_-]?key)/i.test(name)) {
      add('secret/hardcoded-token', 'warning', 'Possible cloud access identifier is hardcoded; inspect the associated credentials.', location, awsKey[0]);
      continue;
    }
    if (options.template && isPlaceholder(value)) continue;
    const symbolicReference = /^\$\{[^{}\n]+\}$/.test(value.trim()) || /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(value.trim());
    if (WEAK.test(value.trim()) || (isPlaceholder(value) && !symbolicReference) || (!isPlaceholder(value) && value.trim().length < 8)) {
      add('secret/weak', 'error', 'Sensitive configuration contains a weak or default value.', location, value);
    } else if (!knownFormat && !isPlaceholder(value) && !options.environment) {
      add('secret/hardcoded', 'error', 'A literal is assigned to a sensitive configuration name.', location, value);
    }
  }
  return { findings, secrets: [...candidates] };
}
