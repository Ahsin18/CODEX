# CODEX — Autonomous Software Reverse Engineering & Application Intelligence

PS06 hackathon prototype for evidence-based static analysis of an authorised codebase.

## Requirements
- Python 3.9 or newer
- No mandatory third-party packages
- Optional: set `ANTHROPIC_API_KEY` to enable Claude-generated explanations. CODEX remains usable without it.

## Run locally
```bash
cd codex
python codex.py serve
```
Open http://127.0.0.1:8000 and upload an authorised `.zip` codebase.

## Analyse from the command line
```bash
python codex.py analyze demo_app -o out
# or
python codex.py analyze path/to/project.zip -o out
```
Outputs: `report.html`, `DOCUMENTATION.md`, `API.md`, `architecture.mmd`, and `test_generated.py`.

## Run tests
```bash
python -m unittest discover -s tests -v
```

## Supported evidence extraction
- Python: imports, classes, functions, Flask-style route decorators, basic SQLAlchemy model fields.
- JavaScript/TypeScript: imports, common Express route declarations, function declarations and arrow functions.
- Java: package/imports, classes/interfaces/enums/records, basic method declarations and Spring mapping annotations.
- SQL: basic `CREATE TABLE` column declarations and inline foreign-key references.
- Cross-file import dependency resolution, basic call-name matching, and pattern-based security findings.

## Security notes
- Uploaded ZIP files are size-limited and validated before extraction.
- ZIP traversal paths and symbolic links are rejected; archive entry and expanded-size limits apply.
- Uploaded source code is read as text and is never executed.
- The local development server is intended for localhost demonstrations, not direct public internet exposure.

## Analysis limitations
- This is static, best-effort analysis, not a compiler, runtime tracer, or complete semantic model.
- Java and JavaScript extraction is pattern-based; unsupported syntax and framework conventions may be missed.
- Import/call relationships are heuristic and can be ambiguous.
- ORM detection is limited to recognised model patterns.
- Generated test cases are suggestions; they are not run automatically and do not imply passing tests.
- Security findings are pattern matches, not a full security audit.
- Mermaid diagrams in the HTML report use the Mermaid CDN and therefore need internet access to render. The `.mmd` file can also be opened in a Mermaid-compatible viewer.

## Demo project
`demo_app/` contains a small Flask/SQLAlchemy application plus Express route examples. It intentionally includes example insecure patterns so the security scanner can demonstrate findings. Do not deploy it.
