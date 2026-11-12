#!/usr/bin/env python3

"""Inspect an authorised source-code project and generate an analysis report.



Run ``python codex.py serve`` to open the local web interface, or use

``python codex.py analyze <folder-or-zip>`` to generate reports from a terminal.

"""



import argparse

import ast

import collections

import html

import json

import os

import pathlib

import re

import sys

import tempfile

import threading

import urllib.request

import zipfile

from http.server import BaseHTTPRequestHandler, HTTPServer

from urllib.parse import parse_qs



IGNORED_DIRS = {

          '.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist',

          'build', '.idea', 'out', '.pytest_cache', 'coverage', 'target', '.next',

}

LANGUAGE_BY_EXTENSION = {

          '.py': 'python',

          '.js': 'javascript',

          '.jsx': 'javascript',

          '.ts': 'typescript',

          '.tsx': 'typescript',

          '.java': 'java',

          '.sql': 'sql',

}

PYTHON_STDLIB = getattr(sys, 'stdlib_module_names', set())

HTTP_METHODS = {'get', 'post', 'put', 'delete', 'patch'}

MODERNIZATION_RULES = {

          'flask': 'Flask -> FastAPI: async support, type hints, auto-generated OpenAPI docs.',

          'django': 'Django: upgrade to latest LTS, add DRF + typed serializers.',

          'express': 'Express (callbacks) -> TypeScript + NestJS/Fastify for structure and validation.',

          'jquery': 'jQuery -> React/Vue component architecture.',

          'mysql': 'Raw MySQL driver -> SQLAlchemy/Prisma ORM + migrations (Alembic).',

          'pymysql': 'Raw PyMySQL driver -> SQLAlchemy ORM + Alembic migrations.',

          'sqlite3': 'SQLite -> PostgreSQL for concurrency, plus ORM + migrations.',

          'mongoose': 'Mongoose: add schema validation + TypeScript types (or Prisma).',

          'requests': 'Sync HTTP client -> httpx (async) when moving to FastAPI.',

}



def escape_html(s):

          return html.escape(str(s))



def mermaid_id(s):

          return 'n' + re.sub('\\W', '_', s)



def mermaid_label(s):

          return re.sub('[^A-Za-z0-9_./ -]', '_', str(s))[:100]





# Source scanning

def analyze(root):

          root = os.path.abspath(root)

          analysis = {

                    'root': root,

                    'files': [],

                    'imports': {},

                    'functions': {},

                    'endpoints': [],

                    'tables': {},

                    'fks': [],

                    'calls': {},

                    'findings': [],

                    'ext': collections.Counter(),

                    'infra': set(),

                    'classes': {},

          }

          paths = []

          for d, ds, fs in os.walk(root):

                    ds[:] = [x for x in ds if x not in IGNORED_DIRS]

                    paths += [os.path.join(d, f) for f in fs]

          for p in sorted(paths):

                    rel = os.path.relpath(p, root).replace(os.sep, '/')

                    base = os.path.basename(p)

                    if base in ('Dockerfile', 'docker-compose.yml', 'requirements.txt', 'package.json'):

                              analysis['infra'].add(base)

                    if base.lower().startswith('test') or '/test' in rel:

                              analysis['infra'].add('tests')

                    lang = LANGUAGE_BY_EXTENSION.get(os.path.splitext(p)[1].lower())

                    if not lang:

                              continue

                    with open(p, encoding='utf-8', errors='ignore') as source_file:

                              src = source_file.read()

                    analysis['files'].append(dict(path=rel, lang=lang, loc=len(src.splitlines())))

                    scan_security(analysis, rel, src)

                    scan_sql(analysis, rel, src)

                    if lang == 'python':

                              analyze_python(analysis, rel, src)

                    elif lang in ('javascript', 'typescript'):

                              analyze_javascript(analysis, rel, src)

                    elif lang == 'java':

                              analyze_java(analysis, rel, src)

          resolve_imports(analysis)

          build_call_graph(analysis)

          analysis['stack'] = detect_tech_stack(analysis)

          return analysis



def scan_security(analysis, rel, src):

          pats = [('(password|secret|api[_-]?key|token)\\s*[=:]\\s*[\\\'"][^\\\'"]{4,}[\\\'"]', 'high', 'Hard-coded secret/credential'), ('\\beval\\(', 'high', 'Use of eval()'), ('(execute|query)\\(\\s*f?[\\\'"][^\\\'"]*(SELECT|INSERT|UPDATE|DELETE)[^\\\'"]*(\\{|%s|\\\'\\s*\\+)', 'high', 'Possible SQL injection (string-built query)'), ('debug\\s*=\\s*True', 'medium', 'Debug mode enabled')]

          for pat, sev, msg in pats:

                    for m in re.finditer(pat, src, re.I):

                              analysis['findings'].append((sev, f'{rel}:{src[:m.start()].count(chr(10)) + 1}', msg))



def scan_sql(analysis, rel, src):

          for m in re.finditer('CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?[`"\\[]?(\\w+)[`"\\]]?\\s*\\((.*?)\\)\\s*;', src, re.I | re.S):

                    t, cols = (m.group(1), [])

                    for part in re.sub('\\([^)]*\\)', '', m.group(2)).split(','):

                              tok = part.split()

                              if not tok or tok[0].upper() in ('PRIMARY', 'FOREIGN', 'CONSTRAINT', 'UNIQUE', 'KEY', 'INDEX'):

                                        continue

                              cols.append((tok[0], tok[1] if len(tok) > 1 else 'text', 'PRIMARY' in part.upper()))

                              r = re.search('REFERENCES\\s+[`"]?(\\w+)', part, re.I)

                              if r:

                                        analysis['fks'].append((t, r.group(1)))

                    analysis['tables'][t] = dict(cols=cols, src=rel)



def analyze_python(analysis, rel, src):

          try:

                    tree = ast.parse(src)

          except SyntaxError:

                    analysis['findings'].append(('high', rel, 'Not valid Python 3 (likely Python 2 legacy) - migration needed'))

                    return

          imps = set()

          for n in ast.walk(tree):

                    if isinstance(n, ast.Import):

                              imps.update((a.name for a in n.names))

                    elif isinstance(n, ast.ImportFrom):

                              if n.module:

                                        imps.add(n.module)

                              else:

                                        imps.update((a.name for a in n.names))

          analysis['imports'][rel] = imps

          for n in ast.walk(tree):

                    if isinstance(n, ast.ClassDef):

                              analysis.setdefault('classes', {})[f'{rel}:{n.name}'] = dict(name=n.name, kind='class', file=rel, line=n.lineno, package='')

          for n in ast.walk(tree):

                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):

                              cx = 1 + sum((isinstance(x, (ast.If, ast.For, ast.While, ast.Try, ast.ExceptHandler, ast.BoolOp, ast.comprehension)) for x in ast.walk(n)))

                              key = f'{rel}:{n.name}'

                              analysis['functions'][key] = dict(name=n.name, file=rel, line=n.lineno, cx=cx, doc=ast.get_docstring(n) or '')

                              analysis['calls'][key] = {c.func.id if isinstance(c.func, ast.Name) else c.func.attr for c in ast.walk(n) if isinstance(c, ast.Call) and isinstance(c.func, (ast.Name, ast.Attribute))}

                              for d in n.decorator_list:

                                        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and (d.func.attr in HTTP_METHODS | {'route'}) and d.args and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str):

                                                  methods = [d.func.attr.upper()] if d.func.attr != 'route' else ['GET']

                                                  for kw in d.keywords:

                                                            if kw.arg == 'methods':

                                                                      methods = [ast.unparse(x).strip('\'"') for x in getattr(kw.value, 'elts', [])]

                                                  for mt in methods:

                                                            analysis['endpoints'].append(dict(method=mt, path=d.args[0].value, handler=key, file=rel, line=n.lineno, doc=ast.get_docstring(n) or ''))

                    elif isinstance(n, ast.ClassDef):

                              bases = [ast.unparse(b) for b in n.bases]

                              if not any((b.endswith(('Model', 'Base')) for b in bases)):

                                        continue

                              tname, cols = (n.name, [])

                              for s in n.body:

                                        if isinstance(s, ast.Assign) and isinstance(s.targets[0], ast.Name) and isinstance(s.value, ast.Call):

                                                  v, k = (ast.unparse(s.value), s.targets[0].id)

                                                  if k == '__tablename__':

                                                            continue

                                                  if 'Column' in v or 'Field' in v or 'ForeignKey' in v:

                                                            typ = re.search('(?:Column|models)\\.?\\(?\\s*(?:db\\.)?(\\w+)', v)

                                                            cols.append((k, typ.group(1) if typ else 'field', 'primary_key=True' in v))

                                                            f = re.search('ForeignKey\\(\\s*[\\\'"]?([\\w\\.]+)', v)

                                                            if f:

                                                                      analysis['fks'].append((tname, f.group(1).split('.')[0]))

                                        elif isinstance(s, ast.Assign) and getattr(s.targets[0], 'id', '') == '__tablename__':

                                                  tname_override = ast.unparse(s.value).strip('\'"')

                                                  analysis['tables'][tname_override] = analysis['tables'].pop(tname, dict(cols=[], src=rel))

                                                  tname = tname_override

                              analysis['tables'][tname] = dict(cols=cols, src=rel)



def analyze_javascript(analysis, rel, src):

          imps = set(re.findall('(?:from\\s+|require\\(\\s*|import\\s+)[\'"]([^\'"]+)[\'"]', src))

          analysis['imports'][rel] = imps

          for m in re.finditer('(?:app|router|server)\\.(get|post|put|delete|patch)\\(\\s*[\'"`]([^\'"`]+)[\'"`]', src):

                    analysis['endpoints'].append(dict(method=m.group(1).upper(), path=m.group(2), handler=None, file=rel, line=src[:m.start()].count('\\n') + 1, doc=''))

          for m in re.finditer('(?:mongoose\\.model|sequelize\\.define)\\(\\s*[\'"](\\w+)', src):

                    analysis['tables'].setdefault(m.group(1), dict(cols=[], src=rel))

          for m in re.finditer('function\\s+(\\w+)|(?:const|let)\\s+(\\w+)\\s*=\\s*(?:async\\s*)?\\([^)]*\\)\\s*=>', src):

                    nm = m.group(1) or m.group(2)

                    analysis['functions'][f'{rel}:{nm}'] = dict(name=nm, file=rel, line=src[:m.start()].count('\n') + 1, cx=1 + src.count('if (') // 4, doc='')



def analyze_java(analysis, rel, src):

          """Evidence-based Java syntax scan (regex-based, not a full compiler)."""

          imports = set(re.findall('(?m)^\\s*import\\s+(?:static\\s+)?([\\w.*]+)\\s*;', src))

          analysis['imports'][rel] = imports

          # Uppercase identifiers are retained only as candidates; resolve_imports links them

          # only when they exactly match a class discovered in this same codebase.

          analysis.setdefault('java_type_refs', {})[rel] = set(re.findall(r'\b[A-Z][A-Za-z0-9_$]*\b', src))

          package = re.search('(?m)^\\s*package\\s+([\\w.]+)\\s*;', src)

          classes = re.finditer('\\b(class|interface|enum|record)\\s+([A-Za-z_$][\\w$]*)', src)

          for cm in classes:

                    cname = cm.group(2)

                    analysis.setdefault('classes', {})[f'{rel}:{cname}'] = dict(name=cname, kind=cm.group(1), file=rel, line=src[:cm.start()].count('\n') + 1, package=package.group(1) if package else '')

          method_pat = re.compile('(?m)^[ \\t]*(?:public|protected|private|static|final|abstract|synchronized|native|default|\\s)+[\\w<>\\[\\].?, ]+\\s+([A-Za-z_$][\\w$]*)\\s*\\(([^;{}]*)\\)\\s*(?:throws\\s+[\\w., ]+)?\\s*\\{')

          for mm in method_pat.finditer(src):

                    name = mm.group(1)

                    if name in {'if', 'for', 'while', 'switch', 'catch', 'return', 'new'}:

                              continue

                    key = f'{rel}:{name}'

                    analysis['functions'][key] = dict(name=name, file=rel, line=src[:mm.start()].count('\n') + 1, cx=1, doc='')

                    analysis['calls'][key] = set()

          annotations = re.compile('@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\\s*(?:\\((.*?)\\))?', re.S)

          for am in annotations.finditer(src):

                    ann, args = (am.group(1), am.group(2) or '')

                    method = {'GetMapping': 'GET', 'PostMapping': 'POST', 'PutMapping': 'PUT', 'DeleteMapping': 'DELETE', 'PatchMapping': 'PATCH', 'RequestMapping': 'GET'}[ann]

                    pathm = re.search('(?:value|path)?\\s*=\\s*["\\\']([^"\\\']+)["\\\']|^\\s*["\\\']([^"\\\']+)["\\\']', args)

                    route = pathm.group(1) or pathm.group(2) if pathm else '/'

                    tail = src[am.end():]

                    hm = re.search('\\b([A-Za-z_$][\\w$]*)\\s*\\(', tail)

                    handler = f'{rel}:{hm.group(1)}' if hm else None

                    analysis['endpoints'].append(dict(method=method, path=route, handler=handler, file=rel, line=src[:am.start()].count('\\n') + 1, doc=''))



def resolve_imports(analysis):

          """turn raw imports into file->file edges"""

          paths = [f['path'] for f in analysis['files']]

          mods = {}

          for p in paths:

                    stem = os.path.splitext(p)[0]

                    mods[stem.replace('/', '.')] = p

                    mods[os.path.basename(stem)] = p

          analysis['edges'], analysis['external'] = (set(), collections.Counter())

          java_classes_by_name = {c.get('name'): c.get('file') for c in analysis.get('classes', {}).values() if c.get('file', '').lower().endswith('.java')}

          for rel, imps in analysis['imports'].items():

                    for i in imps:

                              tgt = None

                              # Java package imports may not include the source-root prefix; resolve by exact class name.

                              if rel.lower().endswith('.java') and i.rsplit('.', 1)[-1] in java_classes_by_name:

                                        tgt = java_classes_by_name[i.rsplit('.', 1)[-1]]

                              if tgt and tgt != rel:

                                        analysis['edges'].add((rel, tgt))

                                        continue

                              if i.startswith('.'):

                                        cand = os.path.normpath(os.path.join(os.path.dirname(rel), i)).replace(os.sep, '/')

                                        tgt = next((p for p in paths if os.path.splitext(p)[0] == cand or os.path.splitext(p)[0] == cand + '/index'), None)

                              else:

                                        parts = i.split('.')

                                        for k in range(len(parts), 0, -1):

                                                  tgt = mods.get('.'.join(parts[:k])) or (mods.get(parts[-1]) if k == len(parts) and len(parts) > 1 and False else None)

                                                  if tgt:

                                                            break

                                        if not tgt and '/' not in i and (i in mods):

                                                  tgt = mods[i]

                              if tgt and tgt != rel:

                                        analysis['edges'].add((rel, tgt))

                              elif not tgt:

                                        top = i.split('.')[0] if not i.startswith('@') else '/'.join(i.split('/')[:2])

                                        top = top.split('/')[0] if not i.startswith('@') else top

                                        is_java_platform = rel.lower().endswith('.java') and top in {'java', 'javax'}

                                        if top not in PYTHON_STDLIB and not i.startswith('.') and not is_java_platform:

                                                  analysis['external'][top] += 1



          # Java files often reference classes in the same package without importing them.

          # Link only exact identifiers that match a class discovered in this project.

          java_class_files = collections.defaultdict(set)

          for class_info in analysis.get('classes', {}).values():

                    if class_info.get('file', '').lower().endswith('.java'):

                              java_class_files[class_info.get('name')].add(class_info.get('file'))

          for source_file, identifiers in analysis.get('java_type_refs', {}).items():

                    if not source_file.lower().endswith('.java'):

                              continue

                    for identifier in identifiers:

                              for target_file in java_class_files.get(identifier, set()):

                                        if target_file != source_file:

                                                  analysis['edges'].add((source_file, target_file))



def build_call_graph(analysis):

          byname = collections.defaultdict(list)

          for k, f in analysis['functions'].items():

                    byname[f['name']].append(k)

          analysis['cg'] = {k: sorted({t for c in cs for t in byname.get(c, []) if t != k}) for k, cs in analysis['calls'].items()}



def get_reachable_functions(analysis, start):

          seen, todo = (set(), [start])

          while todo:

                    x = todo.pop()

                    if x in seen:

                              continue

                    seen.add(x)

                    todo += analysis['cg'].get(x, [])

          return sorted(seen)



def detect_tech_stack(analysis):

          return sorted(set(analysis['external']) | {x for x in analysis['infra'] if x in ('Dockerfile', 'docker-compose.yml')})





# Report generation

def build_architecture_diagram(analysis):

          """Render detected files/classes and only evidence-backed dependency edges."""

          classes_by_file = collections.defaultdict(list)

          for info in analysis.get('classes', {}).values():

                    if info.get('file'):

                              classes_by_file[info['file']].append(info.get('name', 'Class'))



          used = set(classes_by_file)

          used.update(x for edge in analysis.get('edges', set()) for x in edge)

          used.update(e.get('file') for e in analysis.get('endpoints', []) if e.get('file'))

          if not used:

                    used = {f['path'] for f in analysis.get('files', [])}



          out = ['flowchart TD']

          for path in sorted(used):

                    names = sorted(set(classes_by_file.get(path, [])))

                    label = os.path.basename(path)

                    if names:

                              label += ': ' + ', '.join(names[:5])

                    out.append(f'     {mermaid_id(path)}["{mermaid_label(label)}"]')



          edges = sorted(analysis.get('edges', set()))

          for source, target in edges[:100]:

                    if source in used and target in used:

                              out.append(f'     {mermaid_id(source)} --> {mermaid_id(target)}')



          if analysis.get('external'):

                    out.append('     EXT[(External libraries)]')

                    for path in sorted(analysis.get('imports', {})):

                              if path in used and analysis['imports'].get(path):

                                        out.append(f'     {mermaid_id(path)} -.-> EXT')



          if not edges:

                    out.append('     NOTE["No internal dependency links detected<br/>Nodes show discovered source files/classes only"]')

                    if used:

                              out.append(f'     {mermaid_id(sorted(used)[0])} -.-> NOTE')

          return '\n'.join(out)



def build_database_diagram(analysis):

          if not analysis['tables']:

                    return ''

          names = {t.lower(): t for t in analysis['tables']}

          out = ['erDiagram']

          for t, d in analysis['tables'].items():

                    out.append(f'     {mermaid_id(mermaid_label(t))[1:]} {{')

                    for c, ty, pk in d['cols'][:12]:

                              out.append(f"          {re.sub(chr(92) + 'W', '', ty) or 'text'} {re.sub(chr(92) + 'W', '_', c)}{(' PK' if pk else '')}")

                    if not d['cols']:

                              out.append('          string id PK')

                    out.append('     }')

          for a, b in analysis['fks']:

                    b = names.get(b.lower(), names.get(b.lower().rstrip('s'), b))

                    out.append(f'     {mermaid_id(mermaid_label(b))[1:]} ||--o{{ {mermaid_id(mermaid_label(a))[1:]} : has')

          return '\n'.join(out)



def build_call_diagram(analysis):

          es = [(a, b) for a, bs in analysis['cg'].items() for b in bs][:60]

          if not es:

                    return ''

          lab = lambda k: f'''{mermaid_id(k)}["{analysis['functions'][k]['name']}()"]'''

          return 'graph TD\n' + '\n'.join((f'     {lab(a)} --> {lab(b)}' for a, b in es))



def build_api_documentation(analysis):

          out = ['# API Documentation (auto-generated by CODEX)\n', '| Method | Path | Handler | File | Description |', '|---|---|---|---|---|']

          for ep in sorted(analysis['endpoints'], key=lambda x: x['path']):

                    h = analysis['functions'].get(ep['handler'], {}).get('name', '-') if ep['handler'] else '-'

                    out.append(f"| {ep['method']} | `{ep['path']}` | {h} | {ep['file']} | {(ep['doc'].splitlines()[0] if ep['doc'] else '')} |")

          return '\n'.join(out)



def generate_test_suggestions(analysis):

          out = ['"""Auto-generated API smoke tests (not full unit/business-logic tests).',

                             'Start the analysed application first, set BASE_URL to its address,',

                             'then run: pytest -q test_generated.py', '"""',

                             'import os, requests',

                             'BASE = os.getenv("BASE_URL", "http://localhost:5000")', '']

          if not analysis.get('endpoints'):

                    out += ["# No HTTP endpoints were detected by CODEX, so no API smoke tests were generated.",

                                        "# Add unit tests for discovered functions/classes using the project's test framework."]

                    return '\n'.join(out)

          for i, ep in enumerate(analysis['endpoints']):

                    path = re.sub('<[^>]*>|\\{[^}]*\\}|:\\w+', '1', ep['path'])

                    m = ep['method'].lower()

                    name = re.sub('\\W+', '_', f"{m}_{ep['path']}").strip('_')

                    body = ', json={}' if m in ('post', 'put', 'patch') else ''

                    out += [f'def test_{i}_{name}():', f'          r = requests.{m}(BASE + "{path}"{body}, timeout=5)',

                                        '          assert r.status_code < 500, r.text', '']

          return '\n'.join(out)



def get_modernization_suggestions(analysis):

          recs = [v for k, v in MODERNIZATION_RULES.items() if k in analysis['external']]

          if any(('Python 2' in f[2] for f in analysis['findings'])):

                    recs.insert(0, 'Migrate Python 2 code to Python 3.12 (use 2to3/pyupgrade).')

          if 'Dockerfile' not in analysis['infra']:

                    recs.append('Containerise with Docker + docker-compose for reproducible deploys.')

          if 'tests' not in analysis['infra']:

                    recs.append('No test suite found - use the generated tests as a baseline, then add CI (GitHub Actions).')

          if any((f[0] == 'high' for f in analysis['findings'])):

                    recs.append('Fix high-severity findings: move secrets to env vars, parameterise SQL queries.')

          hot = sorted(analysis['functions'].values(), key=lambda f: -f['cx'])[:3]

          if hot and hot[0]['cx'] > 8:

                    recs.append('Refactor high-complexity functions: ' + ', '.join((f"{f['name']} (cx {f['cx']})" for f in hot)))

          return recs or ['Codebase looks modern; consider adding CI/CD and observability.']



def build_summary_data(analysis):

          classes = [

                    {'name': c.get('name'), 'kind': c.get('kind', 'class'),

                        'file': c.get('file'), 'package': c.get('package', '')}

                    for c in analysis.get('classes', {}).values()

          ]

          dependencies = [{'from': a, 'to': b} for a, b in sorted(analysis.get('edges', set()))][:60]

          return dict(

                    files=len(analysis['files']),

                    loc=sum(f['loc'] for f in analysis['files']),

                    languages=dict(collections.Counter(f['lang'] for f in analysis['files'])),

                    stack=analysis['stack'],

                    modules=sorted({os.path.dirname(f['path']) or 'root' for f in analysis['files']}),

                    classes=classes[:60],

                    functions=[{'name': f['name'], 'file': f['file']} for f in list(analysis['functions'].values())[:60]],

                    dependencies=dependencies,

                    endpoints=[{'method': e['method'], 'path': e['path'], 'handler': e.get('handler'), 'file': e['file']} for e in analysis['endpoints'][:40]],

                    tables={t: [c[0] for c in d['cols']] for t, d in analysis['tables'].items()},

                    findings=[{'severity': f[0], 'location': f[1], 'issue': f[2]} for f in analysis['findings'][:15]],

                    infrastructure=sorted(analysis.get('infra', set()))

          )





def _call_claude_summary(data, api_key):
    """Generate evidence-grounded application insights with the Claude API."""
    prompt = (
        'You are CODEX, a careful software reverse-engineering assistant. '
        'Analyse only the supplied static-analysis evidence. Do not invent files, '
        'frameworks, vulnerabilities, endpoints, or architecture details. If evidence '
        'is insufficient, say so. Return a polished report with exactly these headings: '
        'APPLICATION OVERVIEW, ARCHITECTURE, KEY OBSERVATIONS, TOP 3 IMPROVEMENTS. '
        'Keep it concise (120-160 words). Output all four sections in this exact order, '
        'using Markdown headings exactly as: ## APPLICATION OVERVIEW, ## ARCHITECTURE, '
        '## KEY OBSERVATIONS, and ## TOP 3 IMPROVEMENTS. Each section must contain '
        '2-3 complete sentences or bullets. The final section must contain exactly '
        '3 numbered improvements. Mention concrete class names, package names, '
        'dependencies, endpoints, or findings from the input. Do not stop after the '
        'first section or output a partial sentence. For a desktop Java/Swing project, '
        'describe UI classes and detected internal dependencies; do not claim a service, '
        'API, or database layer unless the evidence lists it. If no internal dependency '
        'edges or database tables were detected, state that limitation instead of '
        'inventing a flow.\n\nSTATIC ANALYSIS DATA:\n'
        + json.dumps(data, ensure_ascii=False)
    )

    payload = {
        'model': os.getenv('CODEX_MODEL', 'claude-sonnet-4-5'),
        'max_tokens': 900,
        'messages': [{'role': 'user', 'content': prompt}],
    }
    req = urllib.request.Request(
        'https://api.anthropic.com/v1/messages',
        method='POST',
        headers={
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json',
        },
        data=json.dumps(payload).encode('utf-8'),
    )
    with urllib.request.urlopen(req, timeout=int(os.getenv('CODEX_CLAUDE_TIMEOUT', '60'))) as response:
        result = json.loads(response.read().decode('utf-8'))

    content = result.get('content') or []
    answer = '\n'.join(
        block.get('text', '') for block in content
        if isinstance(block, dict) and block.get('type') == 'text' and block.get('text')
    ).strip()
    if not answer:
        raise ValueError('Claude returned an empty response.')
    return answer


def build_application_summary(analysis, allow_ai=True):
    data = build_summary_data(analysis)
    notes = []

    claude_key = os.getenv('ANTHROPIC_API_KEY')
    if allow_ai and claude_key:
        try:
            return (_call_claude_summary(data, claude_key), 'Claude AI')
        except Exception as ex:
            detail = str(ex)
            if isinstance(ex, urllib.error.HTTPError):
                try:
                    detail = ex.read().decode('utf-8', errors='replace')[:1200]
                except Exception:
                    pass
            message = f'Claude request failed ({type(ex).__name__}): {detail}'
            print('[CODEX AI] ' + message, file=sys.stderr, flush=True)
            notes.append(message)

    eps = ', '.join(
        f"{ep.get('method', 'GET')} {ep.get('path', '/')}"
        for ep in data['endpoints'][:5]
    ) or 'no HTTP endpoints'
    fallback = (
        f"Detected a {', '.join(data['stack'][:4]) or 'plain'} application with "
        f"{data['files']} source files ({data['loc']} LOC) across modules {data['modules']}. "
        f"It exposes {len(data['endpoints'])} endpoints ({eps}) and "
        f"{len(data['tables'])} data entities ({', '.join(data['tables']) or 'none'}). "
        f"Architecture looks like a layered {('REST API' if data['endpoints'] else 'application')}: "
        'routes -> logic -> data models.'
    )
    if notes:
        fallback += ' AI provider unavailable; deterministic static-analysis summary shown.'
    return (fallback, 'Static analysis fallback')

CSS = r"""@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root{--bg:#171816;--panel:#20211e;--panel-2:#252622;--line:#383a33;--text:#f2f0e9;--muted:#a5a398;--soft:#c9c5b9;--accent:#e58b4c;--accent-2:#f0a66e;--mono:'IBM Plex Mono',monospace;--sans:'Inter',system-ui,sans-serif}

*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:28px}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.65 var(--sans)}a{color:var(--accent-2);text-decoration:none}a:hover{color:#ffc08f}button,input{font:inherit}header{background:#1d1e1a;border-bottom:1px solid var(--line);padding:25px clamp(20px,4vw,58px)}header h1{margin:0;font-size:22px;font-weight:700;letter-spacing:-.7px}header h1 span{color:var(--accent)!important}header div{margin-top:5px;color:var(--muted);font-size:12px}main{max-width:1500px;margin:auto;padding:28px clamp(16px,3vw,44px) 64px}.nav{display:flex;gap:7px;flex-wrap:wrap;padding:0 0 22px;margin:0 0 22px;border-bottom:1px solid var(--line)}.nav a{padding:7px 11px;border:1px solid var(--line);border-radius:7px;color:var(--soft);font-size:11px;font-weight:600}.nav a:hover{border-color:var(--accent);color:var(--accent-2);background:#30251e}section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:22px 24px;margin:17px 0;box-shadow:0 10px 30px #00000012;min-width:0}h2{margin:0 0 18px;color:var(--text);font-size:15px;font-weight:650;display:flex;align-items:center;gap:10px}h2:before{content:'';display:block;width:3px;height:17px;border-radius:3px;background:var(--accent)}h3{color:var(--soft);font-size:13px;margin:22px 0 12px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:11px}.card{background:var(--panel-2);border:1px solid #393a33;border-radius:9px;padding:16px 17px;color:var(--muted);font-size:11px;font-weight:600;letter-spacing:.035em;text-transform:uppercase}.card b{display:block;color:var(--text);font-size:29px;line-height:1.25;letter-spacing:-1px;font-weight:600;margin:0 0 5px;font-variant-numeric:tabular-nums}.card b:after{content:'';display:block;width:20px;height:2px;background:var(--accent);margin-top:10px}section p{color:var(--soft)}section p b{color:var(--text)}table{width:100%;border-collapse:collapse;overflow-wrap:anywhere}td,th{padding:11px 12px;text-align:left;border-bottom:1px solid #383a33;font-size:12px;vertical-align:top}th{color:var(--muted);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;background:#252621}td{color:#d5d1c6}tr:last-child td{border-bottom:0}tr:hover{background:#ffffff05}pre{background:#171815;color:#e7c6a9;padding:17px;border:1px solid var(--line);border-radius:9px;overflow:auto;font:12px/1.7 var(--mono)}.high{color:#e18b80;font-weight:700}.medium{color:#dfbd78;font-weight:700}code{font:11px var(--mono);background:#30271f;color:#f0b080;padding:3px 6px;border-radius:4px}.mermaid{text-align:center;min-height:90px}.mermaid svg{max-width:100%;height:auto}ul{padding-left:20px;color:var(--soft)}li{margin:7px 0}small{color:var(--muted);font-size:11px}.report-intro{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;margin:0 0 18px}.report-intro h2{font-size:23px;margin:0}.report-intro h2:before{display:none}.eyebrow{color:var(--accent);font-size:10px;font-weight:700;letter-spacing:.13em;text-transform:uppercase;margin-bottom:7px}.status-pill{display:inline-flex;align-items:center;gap:7px;border:1px solid #46513f;background:#252d23;color:#b9d2ad;padding:6px 10px;border-radius:20px;font-size:10px;font-weight:700}.status-pill:before{content:'';width:6px;height:6px;background:#9fbd8d;border-radius:50%}.intelligence{border-color:#63452f;background:linear-gradient(135deg,#29251f,#20211e 65%)}.intelligence p{font-size:13px;line-height:1.8}.ai-content h3{margin:18px 0 7px;color:var(--accent-2);font-size:12px;letter-spacing:.04em}.ai-content p{margin:7px 0 11px}.ai-content ul{margin:7px 0 13px}.download-link{display:inline-flex;margin:0 0 18px;padding:9px 13px;border:1px solid #805537;border-radius:7px;background:#30251e;color:#f0b080;font-size:11px;font-weight:700}.footer-note{color:#77766d;font-size:10px;margin-top:30px;border-top:1px solid var(--line);padding-top:14px}

.app-shell{max-width:1280px;margin:0 auto;padding:34px clamp(18px,4vw,54px) 60px}.topline{display:flex;align-items:center;justify-content:space-between;padding-bottom:22px;border-bottom:1px solid var(--line)}.brand{font-size:22px;font-weight:750;letter-spacing:-.8px}.brand span{color:var(--accent)}.top-meta{font:10px var(--mono);color:var(--muted);letter-spacing:.08em}.hero{padding:58px 0 34px;max-width:760px}.hero-kicker{color:var(--accent);font-size:10px;font-weight:700;letter-spacing:.16em;text-transform:uppercase}.hero h2{display:block;font-size:clamp(34px,5vw,54px);line-height:1.12;letter-spacing:-2px;margin:14px 0 16px;max-width:700px}.hero h2:before{display:none}.hero p{max-width:620px;color:var(--muted);font-size:14px;line-height:1.8}.workspace-grid{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(280px,.8fr);gap:16px;align-items:stretch}.upload-panel,.path-panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:23px}.panel-label{font-size:12px;font-weight:700;color:var(--text);margin-bottom:5px}.panel-hint{font-size:11px;color:var(--muted);margin-bottom:18px}.drop-zone{min-height:230px;border:1px dashed #6e5947;border-radius:9px;background:#211f1b;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:25px;cursor:pointer;transition:border-color .18s,background .18s}.drop-zone:hover,.drop-zone.over{border-color:var(--accent);background:#2a241e}.upload-icon{width:44px;height:44px;border:1px solid #60452f;border-radius:11px;display:grid;place-items:center;color:var(--accent);font-size:20px;margin-bottom:15px}.drop-zone strong{font-size:13px;color:var(--text)}.drop-zone span{font-size:11px;color:var(--muted);margin-top:7px}.choose-btn,.primary-btn{display:inline-flex;align-items:center;justify-content:center;border:0;border-radius:7px;background:var(--accent);color:#211912;padding:10px 15px;font-size:11px;font-weight:750;cursor:pointer;margin-top:17px}.choose-btn:hover,.primary-btn:hover{background:var(--accent-2)}#msg{min-height:20px;margin-top:12px;color:var(--accent-2);font-size:11px}.path-form{display:flex;flex-direction:column;gap:12px}.path-form input{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:7px;background:#171815;color:var(--text);outline:none}.path-form input:focus{border-color:var(--accent)}.path-form .primary-btn{margin-top:0;width:100%}.capability-list{margin-top:24px;padding-top:18px;border-top:1px solid var(--line)}.capability-list div{display:flex;align-items:center;gap:9px;color:var(--muted);font-size:11px;margin:10px 0}.capability-list i{width:6px;height:6px;border-radius:50%;background:var(--accent)}.footline{margin-top:24px;color:#77766d;font-size:10px;display:flex;justify-content:space-between;gap:15px;flex-wrap:wrap}

@media(max-width:760px){.workspace-grid{grid-template-columns:1fr}.hero{padding:40px 0 25px}.report-intro{align-items:flex-start;flex-direction:column}section{padding:17px}main{padding-top:18px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:480px){.cards{grid-template-columns:1fr 1fr}.card{padding:13px}.card b{font-size:24px}.nav{gap:5px}.nav a{font-size:10px;padding:6px 8px}}

"""

def render_ai_markdown(value):

          """Render a safe Markdown subset used by the AI report."""

          lines = str(value or '').replace('\r\n', '\n').replace('\r', '\n').split('\n')

          output = []

          list_type = None



          def inline(text):

                    text = escape_html(text)

                    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)

                    text = re.sub(r'(?<!\*)\*([^*]+)\*(?!\*)', r'<em>\1</em>', text)

                    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)

                    return text



          def close_list():

                    nonlocal list_type

                    if list_type:

                              output.append(f'</{list_type}>')

                              list_type = None



          for raw in lines:

                    line = raw.strip()

                    if not line:

                              close_list()

                              continue

                    heading = re.match(r'^#{1,3}\s+(.+)$', line)

                    unordered = re.match(r'^[-*•]\s+(.+)$', line)

                    ordered = re.match(r'^\d+[.)]\s+(.+)$', line)

                    if heading:

                              close_list()

                              output.append(f'<h3>{inline(heading.group(1).strip("# "))}</h3>')

                    elif unordered or ordered:

                              wanted = 'ul' if unordered else 'ol'

                              if list_type != wanted:

                                        close_list()

                                        output.append(f'<{wanted}>')

                                        list_type = wanted

                              item = (unordered or ordered).group(1)

                              output.append(f'<li>{inline(item)}</li>')

                    else:

                              close_list()

                              output.append(f'<p>{inline(line)}</p>')

          close_list()

          return ''.join(output)



def build_html_report(analysis, ai_summary=None):

          insight, how = ai_summary if ai_summary is not None else build_application_summary(analysis)

          h = [f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>CODEX · Application Intelligence</title><style>{CSS}</style></head><body><header><h1>CODEX <span>/</span> <small>APPLICATION INTELLIGENCE</small></h1><div>Static reverse-engineering report · Target: ' + escape_html(analysis['root']) + '</div></header><main><div class="report-intro"><div><div class="eyebrow">Analysis workspace / Report</div><h2>Application overview</h2></div><span class="status-pill">Analysis complete</span></div><nav class="nav">' + ''.join((f'<a href="#{x}">{x}</a>' for x in ['Overview', 'Architecture', 'Dependencies', 'APIs', 'Database', 'Findings', 'Recommendations', 'Tests'])) + '</nav>']

          loc = sum((f['loc'] for f in analysis['files']))

          cards = [('Files', len(analysis['files'])), ('LOC', loc), ('Endpoints', len(analysis['endpoints'])), ('Tables', len(analysis['tables'])), ('Functions', len(analysis['functions'])), ('Classes', len(analysis.get('classes', {}))), ('Findings', len(analysis['findings']))]

          h.append('<section><h2 id="Overview">Overview</h2><div class=cards>' + ''.join((f'<div class=card><b>{v}</b>{k}</div>' for k, v in cards)) + '</div>')

          h.append(f"<p><b>Languages:</b> {escape_html(dict(collections.Counter((f['lang'] for f in analysis['files']))))} &nbsp; <b>Tech stack:</b> {escape_html(', '.join(analysis['stack']) or 'n/a')}</p></section>")

          if analysis.get('classes'):

                    h.append('<section><h2>Discovered Classes</h2><table><tr><th>Class</th><th>Kind</th><th>Source</th><th>Line</th></tr>')

                    for c in analysis['classes'].values():

                              h.append(f"<tr><td>{escape_html(c['name'])}</td><td>{escape_html(c.get('kind', 'class'))}</td><td>{escape_html(c['file'])}</td><td>{c['line']}</td></tr>")

                    h.append('</table></section>')

          h.append(f"<section class=\"intelligence\"><h2>AI Application Intelligence <small id=\"ai-provider\">({escape_html(how)})</small></h2><div class=\"ai-content\" id=\"ai-content\">{render_ai_markdown(insight)}</div></section>")

          h.append(f'<section><h2 id="Architecture">Architecture Reconstruction</h2><pre class=mermaid>{escape_html(build_architecture_diagram(analysis))}</pre></section>')

          h.append('<section><h2 id="Dependencies">Dependency Map</h2><table><tr><th>File</th><th>Depends on</th></tr>')

          deps = collections.defaultdict(list)

          for a, b in sorted(analysis['edges']):

                    deps[a].append(b)

          h += [f"<tr><td>{escape_html(a)}</td><td>{escape_html(', '.join(bs))}</td></tr>" for a, bs in deps.items()]

          h.append(f"</table><p><b>External packages:</b> {escape_html(', '.join((f'{k}' for k in analysis['external'])) or 'none')}</p></section>")

          h.append('<section><h2 id="APIs">API Discovery</h2><table><tr><th>Method</th><th>Path</th><th>Handler</th><th>File</th></tr>')

          for ep in sorted(analysis['endpoints'], key=lambda x: x['path']):

                    hn = analysis['functions'].get(ep['handler'], {}).get('name', '-') if ep['handler'] else '-'

                    h.append(f"<tr><td><b>{escape_html(ep['method'])}</b></td><td><code>{escape_html(ep['path'])}</code></td><td>{escape_html(hn)}</td><td>{escape_html(ep['file'])}</td></tr>")

          h.append('</table></section>')

          er = build_database_diagram(analysis)

          h.append('<section><h2 id="Database">Database Reverse Engineering</h2>' + (f'<pre class=mermaid>{escape_html(er)}</pre>' if er else '<p>No schema evidence found.</p>') + '</section>')

          h.append('<section><h2>Program Slicing (code reachable from each endpoint)</h2><table><tr><th>Endpoint</th><th>Slice</th></tr>')

          for ep in analysis['endpoints']:

                    if ep['handler']:

                              sl = [analysis['functions'][k]['name'] for k in get_reachable_functions(analysis, ep['handler'])]

                              h.append(f"<tr><td>{escape_html(ep['method'])} <code>{escape_html(ep['path'])}</code></td><td>{escape_html(' -> '.join(sl))}</td></tr>")

          h.append('</table>')

          cg = build_call_diagram(analysis)

          h.append((f'<h3>Call graph</h3><pre class=mermaid>{escape_html(cg)}</pre>' if cg else '') + '</section>')

          h.append('<section><h2 id="Findings">Risks &amp; Findings</h2><table><tr><th>Severity</th><th>Location</th><th>Issue</th></tr>')

          h += [f'<tr><td class={s}>{s}</td><td>{escape_html(w)}</td><td>{escape_html(m)}</td></tr>' for s, w, m in analysis['findings']] or ['<tr><td colspan=3>None</td></tr>']

          h.append('</table></section><section><h2 id="Recommendations">Modernization Recommendations</h2><ul>' + ''.join((f'<li>{escape_html(r)}</li>' for r in get_modernization_suggestions(analysis))) + '</ul></section>')

          h.append(f'<section><h2 id="Tests">Generated Test Cases</h2><pre>{escape_html(generate_test_suggestions(analysis))}</pre></section></main>')

          h.append('<script type=module>import m from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs";m.initialize({startOnLoad:true});</script>')

          h.append('<div class="footer-note">CODEX · Static analysis report. Findings and relationships are based on detectable source-code evidence.</div></main></body></html>')

          return '\n'.join(h)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024

MAX_EXTRACTED_BYTES = 200 * 1024 * 1024

MAX_FILES = 5000





# Upload handling

def extract_zip_safely(zip_path, destination):

          """Extract an untrusted ZIP after validating every member; never execute contents."""

          total = 0

          with zipfile.ZipFile(zip_path) as archive:

                    members = archive.infolist()

                    if len(members) > MAX_FILES:

                              raise ValueError(f'Archive contains too many entries (limit {MAX_FILES}).')

                    for info in members:

                              name = info.filename.replace('\\', '/')

                              parts = pathlib.PurePosixPath(name).parts

                              if name.startswith('/') or (parts and ':' in parts[0]) or any((part in ('..', '') for part in parts)):

                                        raise ValueError(f'Unsafe archive path: {info.filename}')

                              mode = info.external_attr >> 16 & 61440

                              if mode == 40960:

                                        raise ValueError(f'Symbolic links are not accepted: {info.filename}')

                              total += info.file_size

                              if total > MAX_EXTRACTED_BYTES:

                                        raise ValueError('Archive expands beyond the 200 MB extraction limit.')

                              if info.file_size > 20 * 1024 * 1024:

                                        raise ValueError(f'Archive member is too large: {info.filename}')

                    archive.extractall(destination)



def build_documentation(analysis):

          langs = collections.Counter((f['lang'] for f in analysis['files']))

          lines = ['# CODEX Application Intelligence Report', '', f"**Target:** `{analysis['root']}`", '', '## Project overview', f"- Files analysed: {len(analysis['files'])}", f"- Lines of code: {sum((f['loc'] for f in analysis['files']))}", f"- Languages: {', '.join((f'{k}: {v}' for k, v in sorted(langs.items()))) or 'None'}", f"- Classes: {len(analysis.get('classes', {}))}", f"- Functions/methods: {len(analysis['functions'])}", f"- API endpoints: {len(analysis['endpoints'])}", f"- Database entities: {len(analysis['tables'])}", '', '## Folder structure']

          for f in analysis['files']:

                    lines.append(f"- `{f['path']}` ({f['lang']}, {f['loc']} LOC)")

          lines += ['', '## Important classes']

          lines += [f"- `{v['name']}` — `{v['file']}:{v['line']}` ({v.get('kind', 'class')})" for v in analysis.get('classes', {}).values()]

          lines += ['', '## Functions and methods']

          lines += [f"- `{v['name']}()` — `{v['file']}:{v['line']}`" for v in analysis['functions'].values()]

          lines += ['', '## API endpoints', '| Method | Route | Source |', '|---|---|---|']

          lines += [f"| {x['method']} | `{x['path']}` | `{x['file']}` |" for x in analysis['endpoints']]

          lines += ['', '## Database structure']

          for t, d in analysis['tables'].items():

                    lines += [f'### {t}', f"Source: `{d['src']}`"]

                    lines += [f"- `{c}`: {ty}{(' (primary key)' if pk else '')}" for c, ty, pk in d['cols']]

          lines += ['', '## Dependencies', *[f'- `{a}` → `{b}`' for a, b in sorted(analysis['edges'])], '', '## Security findings']

          lines += [f'- **{s.upper()}** `{where}`: {msg}' for s, where, msg in analysis['findings']] or ['- No findings detected by the configured pattern checks.']

          lines += ['', '## Analysis limitations', '- Static analysis only; uploaded source code is never executed.', '- JavaScript/TypeScript and Java parsing uses pattern-based extraction; results may be incomplete.', '- Import and call relationships are best-effort and do not represent full compiler/runtime semantics.', '- ORM support is limited to recognised model patterns.', '- Generated test cases are suggestions and have not been executed.']

          return '\\n'.join(lines) + '\\n'



def analyze_and_export(target, out='out'):

          if target.lower().endswith('.zip'):

                    tmp = tempfile.mkdtemp(prefix='codex-')

                    zp = os.path.abspath(target)

                    dest = os.path.join(tmp, 'src')

                    os.makedirs(dest)

                    extract_zip_safely(zp, dest)

                    target = dest

          analysis = analyze(target)

          os.makedirs(out, exist_ok=True)

          outputs = [('report.html', build_html_report(analysis)), ('API.md', build_api_documentation(analysis)), ('test_generated.py', generate_test_suggestions(analysis)), ('architecture.mmd', build_architecture_diagram(analysis)), ('DOCUMENTATION.md', build_documentation(analysis))]

          for name, txt in outputs:

                    with open(os.path.join(out, name), 'w', encoding='utf-8') as f:

                              f.write(txt)

          return analysis



# Local web interface

FORM = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>CODEX · Software Intelligence</title><style>{CSS}</style></head><body><main class="app-shell"><div class="topline"><div class="brand">CODEX<span>.</span></div><div class="top-meta">SOFTWARE REVERSE ENGINEERING / LOCAL WORKSPACE</div></div><div class="hero"><div class="hero-kicker">Application intelligence platform</div><h2>Understand the software<br>behind the surface.</h2><p>Reconstruct architecture, discover APIs and database structures, and explore an unfamiliar codebase through evidence-based static analysis.</p></div><div class="workspace-grid"><section class="upload-panel"><div class="panel-label">Import a codebase</div><div class="panel-hint">Upload an authorized project archive to begin analysis.</div><div id="drop" class="drop-zone"><div class="upload-icon">↑</div><strong>Drop your project ZIP here</strong><span>or choose a file from your computer · ZIP up to 50 MB</span><button type="button" class="choose-btn">Choose ZIP file</button><input id="file" type="file" accept=".zip" hidden></div><div id="msg" aria-live="polite"></div></section><section class="path-panel"><div class="panel-label">Analyze a local project</div><div class="panel-hint">Use a folder or ZIP path available on this machine.</div><form class="path-form" method="post" action="/analyze"><input name="path" placeholder="Enter a local project folder or ZIP path" aria-label="Project folder or ZIP path"><button class="primary-btn" type="submit">Analyze local path →</button></form><div class="capability-list"><div><i></i>Multi-language source discovery</div><div><i></i>Architecture and dependency mapping</div><div><i></i>API and database exploration</div><div><i></i>Downloadable technical documentation</div></div></section></div><div class="footline"><span>CODEX / LOCAL ANALYSIS ENVIRONMENT</span><span>Uploaded source code is analysed, never executed.</span></div></main><script>const d=document.getElementById("drop"),f=document.getElementById("file"),m=document.getElementById("msg");d.onclick=()=>f.click();f.onchange=()=>up(f.files[0]);d.ondragover=e=>{e.preventDefault();d.classList.add("over")};d.ondragleave=()=>d.classList.remove("over");d.ondrop=e=>{e.preventDefault();d.classList.remove("over");up(e.dataTransfer.files[0])};async function up(x){if(!x)return;if(!x.name.toLowerCase().endsWith(".zip")){m.textContent="Please choose a .zip file";return}m.textContent="Analysing "+x.name+" …";try{const r=await fetch("/upload",{method:"POST",headers:{"X-Filename":x.name},body:x});if(!r.ok){m.textContent="Error: "+await r.text();return}location.href="/report/"+(await r.text())}catch(err){m.textContent="Upload failed: "+err}}</script></body></html>

""".replace("{CSS}", CSS)

REPORTS = {}

REPORT_DOCS = {}

AI_RESULTS = {}





def _run_ai_job(report_id, analysis):

          """Generate AI insights off the request thread so static reports load immediately."""

          try:

                    insight, provider = build_application_summary(analysis, allow_ai=True)

                    AI_RESULTS[report_id] = {

                              'status': 'done',

                              'provider': provider,

                              'html': render_ai_markdown(insight),

                    }

          except Exception as ex:

                    print(f'[CODEX AI] Background AI job failed: {type(ex).__name__}: {ex}', file=sys.stderr, flush=True)

                    fallback, provider = build_application_summary(analysis, allow_ai=False)

                    AI_RESULTS[report_id] = {

                              'status': 'done',

                              'provider': provider,

                              'html': render_ai_markdown(fallback),

                    }





def _attach_ai_polling(report_html, report_id):

          """Poll the background AI job and replace only the AI section when ready."""

          script = f"""

<script>

(async function() {{

     const provider = document.getElementById('ai-provider');

     const content = document.getElementById('ai-content');

     if (!provider || !content) return;

     provider.textContent = '(AI insights generating…)';

     const endpoint = '/ai-status/{report_id}';

     const started = Date.now();

     while (Date.now() - started < 180000) {{

          try {{

               const response = await fetch(endpoint, {{cache: 'no-store'}});

               if (response.ok) {{

                    const result = await response.json();

                    if (result.status === 'done') {{

                         provider.textContent = '(' + result.provider + ')';

                         content.innerHTML = result.html;

                         return;

                    }}

               }}

          }} catch (e) {{}}

          await new Promise(resolve => setTimeout(resolve, 2000));

     }}

     provider.textContent = '(AI still processing — static analysis available)';

}})();

</script>

"""

          return report_html.replace('</body>', script + '</body>')





class H(BaseHTTPRequestHandler):



          def _send(self, body, code=200, ctype='text/html; charset=utf-8'):

                    self.send_response(code)

                    self.send_header('Content-Type', ctype)

                    self.end_headers()

                    self.wfile.write(body.encode())



          def do_GET(self):

                    if self.path.startswith('/download/'):

                              rid = self.path.rsplit('/', 1)[-1]

                              if rid in REPORT_DOCS:

                                        body = REPORT_DOCS[rid]

                                        self.send_response(200)

                                        self.send_header('Content-Type', 'text/markdown; charset=utf-8')

                                        self.send_header('Content-Disposition', 'attachment; filename="CODEX-DOCUMENTATION.md"')

                                        self.end_headers()

                                        self.wfile.write(body.encode('utf-8'))

                              else:

                                        self._send('Report not found', 404, 'text/plain')

                    elif self.path.startswith('/report/') and self.path[8:] in REPORTS:

                              self._send(REPORTS[self.path[8:]])

                    else:

                              self._send(FORM)



          def do_POST(self):

                    n = int(self.headers.get('Content-Length', 0))

                    if n <= 0 or n > MAX_UPLOAD_BYTES:

                              self._send('Upload must be between 1 byte and 50 MB.', 413, 'text/plain')

                              return

                    raw = self.rfile.read(n)

                    try:

                              if self.path == '/upload':

                                        tmp = tempfile.mkdtemp(prefix='codex-upload-')

                                        zp = os.path.join(tmp, 'up.zip')

                                        dest = os.path.join(tmp, 'src')

                                        os.makedirs(dest)

                                        with open(zp, 'wb') as upload:

                                                  upload.write(raw)

                                        extract_zip_safely(zp, dest)

                                        rid = str(len(REPORTS) + 1)

                                        result = analyze(dest)

                                        static_summary = build_application_summary(result, allow_ai=False)

                                        report_html = build_html_report(result, ai_summary=static_summary)

                                        report_html = report_html.replace('</nav>', f'<a href="/download/{rid}">Download documentation ↓</a></nav>')

                                        REPORTS[rid] = _attach_ai_polling(report_html, rid)

                                        REPORT_DOCS[rid] = build_documentation(result)

                                        AI_RESULTS[rid] = {'status': 'pending'}

                                        threading.Thread(target=_run_ai_job, args=(rid, result), daemon=True).start()

                                        self._send(rid, ctype='text/plain')

                              else:

                                        path = parse_qs(raw.decode())['path'][0].strip()

                                        if path.endswith('.zip'):

                                                  tmp = tempfile.mkdtemp(prefix='codex-path-')

                                                  extract_zip_safely(path, tmp)

                                                  path = tmp

                                        rid = str(len(REPORTS) + 1)

                                        result = analyze(path)

                                        static_summary = build_application_summary(result, allow_ai=False)

                                        report_html = build_html_report(result, ai_summary=static_summary)

                                        REPORTS[rid] = _attach_ai_polling(report_html, rid)

                                        REPORT_DOCS[rid] = build_documentation(result)

                                        AI_RESULTS[rid] = {'status': 'pending'}

                                        threading.Thread(target=_run_ai_job, args=(rid, result), daemon=True).start()

                                        self._send(REPORTS[rid])

                    except Exception as ex:

                              self._send(f'Error: {ex}', 400, 'text/plain')



          def log_message(self, *a):

                    pass

if __name__ == '__main__':

          ap = argparse.ArgumentParser()

          sub = ap.add_subparsers(dest='cmd', required=True)

          a = sub.add_parser('analyze')

          a.add_argument('target')

          a.add_argument('-o', '--out', default='out')

          s = sub.add_parser('serve')

          s.add_argument('-p', '--port', type=int, default=8000)

          args = ap.parse_args()

          if args.cmd == 'analyze':

                    analysis = analyze_and_export(args.target, args.out)

                    print(f"Done: {len(analysis['files'])} files, {len(analysis['endpoints'])} endpoints, {len(analysis['tables'])} tables -> {args.out}/report.html")

          else:

                    print(f'CODEX UI on http://localhost:{args.port}')

                    HTTPServer(('127.0.0.1', args.port), H).serve_forever()
