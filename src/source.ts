import ts from 'typescript';
import { EnvGuardError, type EnvUsage, type Finding, type SourceLocation } from './types.js';

interface Scope {
  parent?: Scope;
  functionScope: boolean;
  bindings: Map<string, Binding>;
}

interface Binding {
  initializer?: ts.Expression;
  scope: Scope;
  constant: boolean;
  nativeProvider?: 'process' | 'namespace' | 'environment';
  projection?: string;
}

export interface SourceAnalysis {
  usages: EnvUsage[];
  assignments: Array<{ name: string; value: string; location: SourceLocation }>;
  literals: Array<{ name: string; value: string; location: SourceLocation }>;
  findings: Finding[];
}

function unwrap(expression: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
    || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression)
    || ts.isSatisfiesExpression(expression)) expression = expression.expression;
  return expression;
}

function literal(expression: ts.Expression | undefined): string | undefined {
  if (!expression) return undefined;
  const node = unwrap(expression);
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ? node.text : undefined;
}

function memberName(node: ts.PropertyAccessExpression | ts.ElementAccessExpression): string | undefined {
  return ts.isPropertyAccessExpression(node) ? node.name.text : literal(node.argumentExpression);
}

function propertyName(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) return name.text;
  return ts.isComputedPropertyName(name) ? literal(name.expression) : undefined;
}

export function analyzeSource(text: string, path: string): SourceAnalysis {
  const result: SourceAnalysis = { usages: [], assignments: [], literals: [], findings: [] };
  const syntaxFinding = (location?: SourceLocation): Finding => ({
    ruleId: 'env/source-syntax', severity: 'warning',
    message: 'Source could not be fully parsed; environment usage analysis may be incomplete.',
    location: location ?? { path },
  });

  try {
    const scriptKind = /\.tsx$/i.test(path) ? ts.ScriptKind.TSX
      : /\.jsx$/i.test(path) ? ts.ScriptKind.JSX
      : /\.[cm]?js$/i.test(path) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
    const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, scriptKind);
    const scopes = new WeakMap<ts.Node, Scope>();
    const root: Scope = { functionScope: true, bindings: new Map() };
    let nodeCount = 0;
    const location = (node: ts.Node): SourceLocation => {
      const point = source.getLineAndCharacterOfPosition(node.getStart(source));
      return { path, line: point.line + 1, column: point.character + 1 };
    };

    function bind(name: ts.BindingName, scope: Scope, initializer?: ts.Expression, constant = false,
      initializerScope = scope, nativeProvider?: Binding['nativeProvider'], projection?: string): void {
      if (ts.isIdentifier(name)) {
        scope.bindings.set(name.text, { initializer, scope: initializerScope, constant, nativeProvider, projection });
      } else {
        for (const element of name.elements) {
          if (ts.isBindingElement(element)) {
            const field = ts.isObjectBindingPattern(name) && !element.dotDotDotToken && ts.isIdentifier(element.name)
              ? element.propertyName ? propertyName(element.propertyName) : element.name.text : undefined;
            bind(element.name, scope, field === 'env' ? initializer : undefined, field === 'env' && constant,
              initializerScope, undefined, field);
          }
        }
      }
    }

    function nativeModule(expression: ts.Expression | undefined): boolean {
      const name = literal(expression);
      return name === 'process' || name === 'node:process';
    }

    function declare(node: ts.Node, incoming: Scope): void {
      if (++nodeCount > 100000) throw new EnvGuardError('Source AST exceeds the per-file complexity limit.');
      if (ts.isFunctionDeclaration(node) && node.name) bind(node.name, incoming);
      if (ts.isClassDeclaration(node) && node.name) bind(node.name, incoming);
      let scope = incoming;
      if (ts.isFunctionLike(node) || ts.isBlock(node) || ts.isCatchClause(node)
        || ts.isForStatement(node) || ts.isForOfStatement(node) || ts.isForInStatement(node)
        || ts.isClassLike(node) || ts.isCaseBlock(node)) {
        scope = { parent: incoming, functionScope: ts.isFunctionLike(node), bindings: new Map() };
      }
      scopes.set(node, scope);
      if (ts.isFunctionExpression(node) && node.name) bind(node.name, scope);
      if (ts.isClassExpression(node) && node.name) bind(node.name, scope);
      if (ts.isParameter(node)) bind(node.name, scope);
      if (ts.isVariableDeclaration(node)) {
        let target = scope;
        const list = node.parent;
        const blockScoped = !ts.isVariableDeclarationList(list) || (list.flags & ts.NodeFlags.BlockScoped) !== 0;
        if (!blockScoped) while (!target.functionScope && target.parent) target = target.parent;
        bind(node.name, target, node.initializer,
          ts.isVariableDeclarationList(list) && (list.flags & ts.NodeFlags.Const) !== 0, scope);
      }
      if (ts.isImportClause(node) && node.name) {
        bind(node.name, scope, undefined, true, scope,
          !node.isTypeOnly && nativeModule(node.parent.moduleSpecifier) ? 'process' : undefined);
      }
      if (ts.isImportSpecifier(node)) {
        const clause = node.parent.parent;
        const imported = node.propertyName?.text ?? node.name.text;
        const native = !node.isTypeOnly && !clause.isTypeOnly && nativeModule(clause.parent.moduleSpecifier);
        bind(node.name, scope, undefined, true, scope,
          native && imported === 'env' ? 'environment' : native && imported === 'default' ? 'process' : undefined);
      }
      if (ts.isNamespaceImport(node)) {
        const clause = node.parent;
        bind(node.name, scope, undefined, true, scope,
          !clause.isTypeOnly && nativeModule(clause.parent.moduleSpecifier) ? 'namespace' : undefined);
      }
      if (ts.isImportEqualsDeclaration(node)) {
        bind(node.name, scope, undefined, true, scope,
          !node.isTypeOnly && ts.isExternalModuleReference(node.moduleReference)
            && nativeModule(node.moduleReference.expression) ? 'process' : undefined);
      }
      ts.forEachChild(node, child => declare(child, scope));
    }
    declare(source, root);

    function binding(name: string, scope: Scope): Binding | undefined {
      let current: Scope | undefined = scope;
      while (current) {
        const found = current.bindings.get(name);
        if (found) return found;
        current = current.parent;
      }
      return undefined;
    }

    function processObject(expression: ts.Expression, scope: Scope, depth = 0, namespaceOnly = false): boolean {
      if (depth > 32) return false;
      const node = unwrap(expression);
      if (ts.isIdentifier(node)) {
        const found = binding(node.text, scope);
        if (!found) return !namespaceOnly && node.text === 'process';
        return found.nativeProvider === 'namespace' || (!namespaceOnly && found.nativeProvider === 'process')
          || (found.constant && !found.projection && !!found.initializer
            && processObject(found.initializer, found.scope, depth + 1, namespaceOnly));
      }
      if (namespaceOnly) return false;
      if (ts.isCallExpression(node)) {
        const called = unwrap(node.expression);
        return ts.isIdentifier(called) && called.text === 'require' && !binding('require', scope)
          && node.arguments.length === 1 && nativeModule(node.arguments[0]);
      }
      if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
        const base = unwrap(node.expression);
        if (memberName(node) === 'default') return processObject(base, scope, depth + 1, true);
        return memberName(node) === 'process' && ts.isIdentifier(base)
          && (base.text === 'global' || base.text === 'globalThis') && !binding(base.text, scope);
      }
      return false;
    }

    function environmentObject(expression: ts.Expression, scope: Scope, depth = 0): EnvUsage['provider'] {
      if (depth > 32) return undefined;
      const node = unwrap(expression);
      if (ts.isIdentifier(node)) {
        const found = binding(node.text, scope);
        if (found?.nativeProvider === 'environment') return 'process';
        if (found?.constant && found.projection === 'env' && found.initializer) {
          return processObject(found.initializer, found.scope) ? 'process' : undefined;
        }
        return found?.constant && found.initializer ? environmentObject(found.initializer, found.scope, depth + 1) : undefined;
      }
      if (!ts.isPropertyAccessExpression(node) && !ts.isElementAccessExpression(node)) return undefined;
      if (memberName(node) !== 'env') return undefined;
      const base = unwrap(node.expression);
      if (processObject(base, scope)) return 'process';
      return ts.isMetaProperty(base) && base.keywordToken === ts.SyntaxKind.ImportKeyword && base.name.text === 'meta' ? 'import-meta' : undefined;
    }

    function use(node: ts.Node, name?: string, provider?: EnvUsage['provider']): void {
      if (result.usages.length >= 20000) throw new EnvGuardError('Source environment usage exceeds the per-file limit.');
      const position = location(node);
      if (name !== undefined) result.usages.push({ name, location: position, provider });
      else {
        result.usages.push({ dynamic: true, location: position });
        result.findings.push({
          ruleId: 'env/dynamic', severity: 'info',
          message: 'Environment access cannot be resolved statically.', location: position,
        });
      }
    }

    function destructuring(name: ts.ObjectBindingPattern, provider?: EnvUsage['provider']): void {
      for (const element of name.elements) {
        if (element.dotDotDotToken) use(element);
        else use(element, element.propertyName ? propertyName(element.propertyName)
          : ts.isIdentifier(element.name) ? element.name.text : undefined, provider);
      }
    }

    function environmentDestructuring(name: ts.BindingName, value: ts.Expression | undefined, scope: Scope): void {
      if (!ts.isObjectBindingPattern(name) || !value) return;
      const provider = environmentObject(value, scope);
      if (provider) destructuring(name, provider);
      else if (processObject(value, scope)) {
        for (const element of name.elements) {
          if (!element.dotDotDotToken && element.propertyName && propertyName(element.propertyName) === 'env'
            && ts.isObjectBindingPattern(element.name)) destructuring(element.name, 'process');
        }
      }
    }

    function supportedUse(node: ts.Expression): boolean {
      const parent = node.parent;
      if ((ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent))
        && parent.expression === node) return true;
      if ((ts.isParenthesizedExpression(parent) || ts.isAsExpression(parent)
        || ts.isTypeAssertionExpression(parent) || ts.isNonNullExpression(parent)
        || ts.isSatisfiesExpression(parent)) && parent.expression === node) return true;
      if ((ts.isVariableDeclaration(parent) || ts.isParameter(parent)) && parent.initializer === node) {
        return ts.isObjectBindingPattern(parent.name) || (ts.isIdentifier(parent.name)
          && ts.isVariableDeclarationList(parent.parent) && (parent.parent.flags & ts.NodeFlags.Const) !== 0);
      }
      return ts.isBinaryExpression(parent) && parent.right === node
        && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken
        && ts.isObjectLiteralExpression(unwrap(parent.left));
    }

    function reference(node: ts.Identifier): boolean {
      const parent = node.parent;
      if ((ts.isPropertyAccessExpression(parent) && parent.name === node)
        || ((ts.isVariableDeclaration(parent) || ts.isParameter(parent) || ts.isBindingElement(parent)
          || ts.isFunctionDeclaration(parent) || ts.isFunctionExpression(parent)
          || ts.isClassDeclaration(parent) || ts.isClassExpression(parent)
          || ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent)
          || ts.isMethodDeclaration(parent) || ts.isImportClause(parent)
          || ts.isImportSpecifier(parent) || ts.isNamespaceImport(parent)
          || ts.isImportEqualsDeclaration(parent)) && parent.name === node)
        || (ts.isBindingElement(parent) && parent.propertyName === node)) return false;
      return true;
    }

    function assignment(name: string | undefined, value: ts.Expression | undefined, node: ts.Node): void {
      if (name === undefined || !value) return;
      const pending = [value];
      while (pending.length > 0) {
        const branch = unwrap(pending.pop()!);
        const decoded = literal(branch);
        if (decoded !== undefined) {
          if (result.assignments.length >= 20000) throw new EnvGuardError('Source literals exceed the per-file limit.');
          result.assignments.push({ name, value: decoded, location: location(node) });
        } else if (ts.isBinaryExpression(branch)
          && (branch.operatorToken.kind === ts.SyntaxKind.BarBarToken || branch.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)) {
          pending.push(branch.right, branch.left);
        } else if (ts.isConditionalExpression(branch)) pending.push(branch.whenFalse, branch.whenTrue);
      }
    }

    function visit(node: ts.Node): void {
      if (ts.isTypeNode(node)) return;
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
        if (result.literals.length >= 20000) throw new EnvGuardError('Source literals exceed the per-file limit.');
        result.literals.push({ name: '', value: node.text, location: location(node) });
      }
      const scope = scopes.get(node) ?? root;
      if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node))
        && environmentObject(node.expression, scope)) use(node, memberName(node), environmentObject(node.expression, scope));
      if (ts.isVariableDeclaration(node)) {
        environmentDestructuring(node.name, node.initializer, scope);
        if (ts.isIdentifier(node.name)) assignment(node.name.text, node.initializer, node);
      }
      if (ts.isParameter(node)) {
        environmentDestructuring(node.name, node.initializer, scope);
        if (ts.isIdentifier(node.name)) assignment(node.name.text, node.initializer, node);
      }
      if (ts.isBindingElement(node) && node.initializer) {
        assignment(node.propertyName ? propertyName(node.propertyName)
          : ts.isIdentifier(node.name) ? node.name.text : undefined, node.initializer, node);
      }
      if (ts.isPropertyAssignment(node) || ts.isPropertyDeclaration(node)) {
        assignment(propertyName(node.name), node.initializer, node);
      }
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const left = unwrap(node.left);
        if (ts.isIdentifier(left)) assignment(left.text, node.right, node);
        if (ts.isPropertyAccessExpression(left) || ts.isElementAccessExpression(left)) {
          assignment(memberName(left), node.right, node);
        }
        if (ts.isObjectLiteralExpression(left) && environmentObject(node.right, scope)) {
          for (const property of left.properties) {
            if (ts.isShorthandPropertyAssignment(property)) use(property, property.name.text, environmentObject(node.right, scope));
            else if (ts.isPropertyAssignment(property)) use(property, propertyName(property.name), environmentObject(node.right, scope));
            else use(property);
          }
        }
      }
      if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)
        || (ts.isIdentifier(node) && reference(node)) || ts.isParenthesizedExpression(node)
        || ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)
        || ts.isNonNullExpression(node) || ts.isSatisfiesExpression(node))
        && environmentObject(node, scope) && !supportedUse(node)) use(node);
      ts.forEachChild(node, visit);
    }
    visit(source);
    const diagnostics = (source as ts.SourceFile & { parseDiagnostics: readonly ts.DiagnosticWithLocation[] }).parseDiagnostics;
    if (diagnostics.length) {
      const point = source.getLineAndCharacterOfPosition(diagnostics[0]!.start ?? 0);
      result.findings.push(syntaxFinding({ path, line: point.line + 1, column: point.character + 1 }));
    }
  } catch (error) {
    if (error instanceof EnvGuardError) throw error;
    throw new EnvGuardError('Source parsing could not complete safely. Narrow the scan scope or simplify deeply nested syntax.');
  }
  return result;
}
