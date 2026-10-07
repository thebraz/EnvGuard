import { EnvGuardError, type Finding, type SourceLocation } from './types.js';

const MAX_ENV_RECORDS = 10_000;

export interface EnvDefinition {
  name: string;
  value: string;
  location: SourceLocation & { line: number; column: number };
}

/** Parse dotenv without retaining source lines in diagnostics. */
export function parseEnv(text: string, path: string): { definitions: EnvDefinition[]; findings: Finding[] } {
  const source = text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
  const definitions: EnvDefinition[] = [];
  const findings: Finding[] = [];
  const previous = new Map<string, string>();
  let offset = 0;
  let line = 1;
  let column = 1;

  const finding = (item: Finding): void => {
    if (findings.length >= MAX_ENV_RECORDS) throw new EnvGuardError('Environment file exceeds the 10,000 finding limit.');
    findings.push(item);
  };

  const advance = (): string => {
    const character = source[offset++] ?? '';
    if (character === '\n') { line++; column = 1; } else { column++; }
    return character;
  };
  const horizontal = (): void => {
    while (source[offset] === ' ' || source[offset] === '\t') advance();
  };
  const skipLine = (): void => {
    while (offset < source.length && source[offset] !== '\n') advance();
    if (source[offset] === '\n') advance();
  };
  const malformed = (location: SourceLocation): void => {
    finding({ ruleId: 'env/malformed', severity: 'error', message: 'Malformed environment definition.', location });
  };

  while (offset < source.length) {
    horizontal();
    if (source[offset] === '\n' || source[offset] === '#') { skipLine(); continue; }
    if (offset >= source.length) break;
    if (source.startsWith('export', offset) && /[ \t]/.test(source[offset + 6] ?? '')) {
      for (let count = 0; count < 6; count++) advance();
      horizontal();
    }
    const location = { path, line, column };
    const nameStart = offset;
    if (!/[A-Za-z_]/.test(source[offset] ?? '')) { malformed(location); skipLine(); continue; }
    advance();
    while (/[A-Za-z0-9_]/.test(source[offset] ?? '')) advance();
    const name = source.slice(nameStart, offset);
    horizontal();
    if (source[offset] !== '=') { malformed(location); skipLine(); continue; }
    advance();
    horizontal();
    let value = '';
    let valid = true;
    const quote = source[offset];
    if (quote === '"' || quote === "'" || quote === '`') {
      advance();
      let closed = false;
      const pieces: string[] = [];
      while (offset < source.length) {
        const character = advance();
        if (character === '\0') valid = false;
        if (character === quote) { closed = true; break; }
        if (character === '\\' && offset < source.length) {
          const next = source[offset] ?? '';
          if (next === quote || next === '\\') { pieces.push(advance()); continue; }
          if (quote === '"' && (next === 'n' || next === 'r' || next === 't')) {
            advance();
            pieces.push(next === 'n' ? '\n' : next === 'r' ? '\r' : '\t');
            continue;
          }
        }
        pieces.push(character);
      }
      value = pieces.join('');
      horizontal();
      if (!closed || (offset < source.length && source[offset] !== '\n' && source[offset] !== '#')) valid = false;
      skipLine();
    } else {
      const valueStart = offset;
      while (offset < source.length && source[offset] !== '\n' && source[offset] !== '#') {
        if (advance() === '\0') valid = false;
      }
      value = source.slice(valueStart, offset).trimEnd();
      skipLine();
    }
    if (!valid) { malformed(location); continue; }
    if (definitions.length >= MAX_ENV_RECORDS) throw new EnvGuardError('Environment file exceeds the 10,000 definition limit.');
    if (previous.has(name)) {
      finding({ ruleId: 'env/duplicate', severity: 'warning', message: 'Environment variable is defined more than once.', location });
      if (previous.get(name) !== value) {
        finding({ ruleId: 'env/conflict', severity: 'error', message: 'Repeated environment definitions contain conflicting values.', location });
      }
    }
    previous.set(name, value);
    definitions.push({ name, value, location });
  }
  return { definitions, findings };
}
