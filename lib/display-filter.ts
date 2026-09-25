import type { NetworkConnection, PacketFrame } from './types';

export type DisplayFilterRecord =
  | { kind: 'packet'; packet: PacketFrame }
  | { kind: 'connection'; connection: NetworkConnection };
export type DisplayFilterError = { message: string; token: string; position: number };
export type CompiledDisplayFilter = (record: DisplayFilterRecord) => boolean;

type Value = { type: 'number' | 'boolean' | 'string' | 'address' | 'group'; value?: number | boolean | string };
type Literal = { type: 'number' | 'boolean' | 'string'; value: number | boolean | string };
type Token = { kind: 'word' | 'number' | 'string' | 'symbol' | 'end'; text: string; position: number; value?: string };

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < source.length) {
    if (/\s/.test(source[i])) { i++; continue; }
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
          if (i >= source.length || (source[i] !== '\\' && source[i] !== '"')) throw { message: 'Invalid string escape', token: source[i] ?? '<end>', position: i };
        }
        value += source[i++];
      }
      if (i >= source.length) throw { message: 'Unterminated string', token: '<end>', position: i };
      i++;
      tokens.push({ kind: 'string', text: source.slice(position, i), value, position });
      continue;
    }
    const symbol = /^(==|!=|>=|<=|[><(),{}])/.exec(rest);
    if (symbol) { tokens.push({ kind: 'symbol', text: symbol[0], position }); i += symbol[0].length; continue; }
    throw { message: 'Unexpected token', token: source[i], position };
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
  private peek(): Token { return this.tokens[this.index]; }
  private take(): Token { return this.tokens[this.index++]; }
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
    const predicate = this.or();
    if (this.peek().kind !== 'end') this.fail();
    return predicate;
  }
  private or(): CompiledDisplayFilter {
    let left = this.and();
    while (this.keyword('or')) {
      this.take();
      const right = this.and();
      const previous = left;
      left = record => previous(record) || right(record);
    }
    return left;
  }
  private and(): CompiledDisplayFilter {
    let left = this.not();
    while (this.keyword('and')) {
      this.take();
      const right = this.not();
      const previous = left;
      left = record => previous(record) && right(record);
    }
    return left;
  }
  private not(): CompiledDisplayFilter {
    if (this.keyword('not')) {
      this.take();
      const child = this.not();
      return record => !child(record);
    }
    if (this.symbol('(')) {
      this.take();
      const child = this.or();
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
      while (this.symbol(',')) { this.take(); literals.push(this.literal()); }
      this.expectSymbol('}');
      predicate = record => {
        const value = valueAt(record, path.text.toLowerCase());
        return literals.some(literal => compare(value, '==', literal));
      };
    } else {
      predicate = record => valueAt(record, path.text.toLowerCase()) !== undefined;
    }
    return predicate;
  }
}

export function compileDisplayFilter(source: string): { ok: true; predicate: CompiledDisplayFilter } | { ok: false; error: DisplayFilterError } {
  try {
    return { ok: true, predicate: new Parser(tokenize(source)).parse() };
  } catch (error) {
    return { ok: false, error: error as DisplayFilterError };
  }
}
