import type { NetworkConnection, PacketFrame } from './types';

export type DisplayFilterRecord =
  | { kind: 'packet'; packet: PacketFrame }
  | { kind: 'connection'; connection: NetworkConnection };
export type DisplayFilterError = { message: string; token: string; position: number };
export type CompiledDisplayFilter = (record: DisplayFilterRecord) => boolean;

type Value = { type: 'number' | 'boolean' | 'string' | 'address' | 'group'; value?: number | boolean | string };
type Literal = { type: 'number' | 'boolean' | 'string'; value: number | boolean | string };
type Token = { kind: 'word' | 'number' | 'string' | 'symbol' | 'error' | 'end'; text: string; position: number; value?: string; message?: string };

const MAX_SOURCE_LENGTH = 2048;
const MAX_TOKENS = 256;
const MAX_NESTING = 64;
const MAX_SET_SIZE = 128;

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  const error = (message: string, text: string, position: number): Token[] => [
    ...tokens,
    { kind: 'error', text, position, message },
    { kind: 'end', text: '<end>', position: source.length },
  ];
  let i = 0;
  while (i < source.length) {
    if (/\s/.test(source[i])) { i++; continue; }
    if (tokens.length === MAX_TOKENS) return error('Token limit exceeded', '<token-limit>', i);
    const position = i;
    const rest = source.slice(i);
    const word = /^[a-z_][a-z_0-9.]*/i.exec(rest);
    const number = /^[0-9]+/.exec(rest);
    if (word) { tokens.push({ kind: 'word', text: word[0], position }); i += word[0].length; continue; }
    if (number) { tokens.push({ kind: 'number', text: number[0], position }); i += number[0].length; continue; }
    if (source[i] === '"') {
      i++;
      let value = '';
      while (i < source.length && source[i] !== '"') {
        if (source[i] === '\\') {
          i++;
          if (i >= source.length || (source[i] !== '\\' && source[i] !== '"')) return error('Invalid string escape', source[i] ?? '<end>', i);
        }
        value += source[i++];
      }
      if (i >= source.length) return error('Unterminated string', '<end>', i);
      i++;
      tokens.push({ kind: 'string', text: source.slice(position, i), value, position });
      continue;
    }
    const symbol = /^(==|!=|>=|<=|[><(),{}])/.exec(rest);
    if (symbol) { tokens.push({ kind: 'symbol', text: symbol[0], position }); i += symbol[0].length; continue; }
    return error('Unexpected token', source[i], position);
  }
  tokens.push({ kind: 'end', text: '<end>', position: source.length });
  return tokens;
}

function valueAt(record: DisplayFilterRecord, path: string): Value | undefined {
  if (record.kind === 'packet') {
    if (path === 'frame.len') return { type: 'number', value: record.packet.length };
    const field = record.packet.fields.find(f => f.path.toLowerCase() === path);
    if (!field) return undefined;
    if (field.type === 'group') return { type: 'group' };
    if (field.type === 'uint' && typeof field.value === 'number') return { type: 'number', value: field.value };
    if (field.type === 'bool' && typeof field.value === 'boolean') return { type: 'boolean', value: field.value };
    if ((field.type === 'str' || field.type === 'addr') && typeof field.value === 'string') return { type: field.type === 'str' ? 'string' : 'address', value: field.value };
    return { type: 'group' };
  }
  const c = record.connection;
  const values: Record<string, Value> = {
    'connection.protocol': { type: 'string', value: c.protocol },
    'connection.transport': { type: 'string', value: c.transportProtocol },
    'connection.local_addr': { type: 'address', value: c.localAddr },
    'connection.local_port': { type: 'number', value: c.localPort },
    'connection.remote_addr': { type: 'address', value: c.remoteAddr },
    'connection.remote_port': { type: 'number', value: c.remotePort },
    'connection.process': { type: 'string', value: c.processName },
  };
  return Object.prototype.hasOwnProperty.call(values, path) ? values[path] : undefined;
}

function compare(value: Value | undefined, operator: string, literal: Literal): boolean {
  if (!value || value.value === undefined || value.type === 'group') return false;
  if ((value.type === 'string' || value.type === 'address') && literal.type === 'string') {
    const left = String(value.value).toLowerCase();
    const right = String(literal.value).toLowerCase();
    if (operator === '==') return left === right;
    if (operator === '!=') return left !== right;
    return false;
  }
  if (value.type !== literal.type) return false;
  if (operator === '==') return value.value === literal.value;
  if (operator === '!=') return value.value !== literal.value;
  if (value.type !== 'number') return false;
  const left = value.value as number;
  const right = literal.value as number;
  switch (operator) {
    case '>': return left > right;
    case '<': return left < right;
    case '>=': return left >= right;
    case '<=': return left <= right;
    default: return false;
  }
}

class Parser {
  private index = 0;
  constructor(private readonly tokens: Token[]) {}
  private peek(): Token {
    const token = this.tokens[this.index];
    if (token.kind === 'error') throw { message: token.message, token: token.text, position: token.position };
    return token;
  }
  private take(): Token { const token = this.peek(); this.index++; return token; }
  private fail(token = this.peek()): never { throw { message: 'Unexpected token', token: token.text, position: token.position }; }
  private keyword(word: string): boolean { return this.peek().kind === 'word' && this.peek().text.toLowerCase() === word; }
  private symbol(symbol: string): boolean { return this.peek().kind === 'symbol' && this.peek().text === symbol; }
  private expectSymbol(symbol: string): void { if (!this.symbol(symbol)) this.fail(); this.take(); }
  private literal(): Literal {
    const token = this.take();
    if (token.kind === 'number') return { type: 'number', value: Number(token.text) };
    if (token.kind === 'string') return { type: 'string', value: token.value! };
    if (token.kind === 'word' && /^(true|false)$/i.test(token.text)) return { type: 'boolean', value: token.text.toLowerCase() === 'true' };
    return this.fail(token);
  }
  parse(): CompiledDisplayFilter {
    const predicate = this.or(0);
    if (this.peek().kind !== 'end') this.fail();
    return predicate;
  }
  private or(depth: number): CompiledDisplayFilter {
    let left = this.and(depth);
    while (this.keyword('or')) {
      this.take();
      const right = this.and(depth);
      const previous = left;
      left = record => previous(record) || right(record);
    }
    return left;
  }
  private and(depth: number): CompiledDisplayFilter {
    let left = this.not(depth);
    while (this.keyword('and')) {
      this.take();
      const right = this.not(depth);
      const previous = left;
      left = record => previous(record) && right(record);
    }
    return left;
  }
  private not(depth: number): CompiledDisplayFilter {
    if (this.keyword('not')) {
      if (depth === MAX_NESTING) throw { message: 'Nesting limit exceeded', token: '<nesting-limit>', position: this.peek().position };
      this.take();
      const child = this.not(depth + 1);
      return record => !child(record);
    }
    if (this.symbol('(')) {
      if (depth === MAX_NESTING) throw { message: 'Nesting limit exceeded', token: '<nesting-limit>', position: this.peek().position };
      this.take();
      const child = this.or(depth + 1);
      this.expectSymbol(')');
      return child;
    }
    return this.atom();
  }
  private atom(): CompiledDisplayFilter {
    const path = this.take();
    if (path.kind !== 'word' || /^(and|or|not|in|contains|true|false)$/i.test(path.text)) return this.fail(path);
    const op = this.peek();
    let predicate: CompiledDisplayFilter;
    if (op.kind === 'symbol' && /^(==|!=|>=|<=|>|<)$/.test(op.text)) {
      this.take();
      const literal = this.literal();
      predicate = record => compare(valueAt(record, path.text.toLowerCase()), op.text, literal);
    } else if (this.keyword('contains')) {
      this.take();
      const literal = this.literal();
      predicate = record => {
        const value = valueAt(record, path.text.toLowerCase());
        return !!value && (value.type === 'string' || value.type === 'address') && literal.type === 'string'
          && typeof value.value === 'string' && value.value.toLowerCase().includes(String(literal.value).toLowerCase());
      };
    } else if (this.keyword('in')) {
      this.take();
      this.expectSymbol('{');
      const literals: Literal[] = [this.literal()];
      while (this.symbol(',')) {
        this.take();
        if (literals.length === MAX_SET_SIZE) throw { message: 'Set size limit exceeded', token: '<set-limit>', position: this.peek().position };
        literals.push(this.literal());
      }
      this.expectSymbol('}');
      const numbers = new Set(literals.filter((literal) => literal.type === 'number').map((literal) => literal.value as number));
      const booleans = new Set(literals.filter((literal) => literal.type === 'boolean').map((literal) => literal.value as boolean));
      const strings = new Set(literals.filter((literal) => literal.type === 'string').map((literal) => (literal.value as string).toLowerCase()));
      predicate = record => {
        const value = valueAt(record, path.text.toLowerCase());
        if (!value || value.value === undefined) return false;
        if (value.type === 'number') return numbers.has(value.value as number);
        if (value.type === 'boolean') return booleans.has(value.value as boolean);
        if (value.type === 'string' || value.type === 'address') return strings.has((value.value as string).toLowerCase());
        return false;
      };
    } else {
      predicate = record => valueAt(record, path.text.toLowerCase()) !== undefined;
    }
    return predicate;
  }
}

export function compileDisplayFilter(source: string): { ok: true; predicate: CompiledDisplayFilter } | { ok: false; error: DisplayFilterError } {
  if (source.length > MAX_SOURCE_LENGTH) return { ok: false, error: { message: 'Source length limit exceeded', token: '<source-limit>', position: MAX_SOURCE_LENGTH } };
  try {
    return { ok: true, predicate: new Parser(tokenize(source)).parse() };
  } catch (error) {
    return { ok: false, error: error as DisplayFilterError };
  }
}
