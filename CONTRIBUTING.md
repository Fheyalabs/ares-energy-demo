# Contributing to ARES Core

Thanks for considering a contribution. ARES Core is pre-1.0 and the API
is still evolving — contributions that exercise the framework with new
applications are especially welcome.

## Before you start

- For non-trivial changes, **open an issue first** to discuss the
  approach. This avoids wasted work.
- Security issues: see [SECURITY.md](SECURITY.md). Do not file public
  issues for vulnerabilities.
- All contributors must follow the
  [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Requirements:

- **Go 1.23+**
- **OpenFHE 1.5.1** (the framework is tested against this exact version;
  `v1.5.x` major.minor is supported)
- Python 3.12+ if you'll touch `clients/python/`
- `pkg-config` (optional — see `pkg-config/openfhe.pc.in`)

```bash
git clone https://github.com/Fheyalabs/ARES-core.git
cd ARES-core
go test ./...                               # Go-only tests (no OpenFHE)
go test -tags openfhe ./...                 # full tests (needs OpenFHE)
```

If you need to override OpenFHE paths:

```bash
export CGO_CXXFLAGS="-I/your/openfhe/include/openfhe -I/your/openfhe/include/openfhe/pke -I/your/openfhe/include/openfhe/core -I/your/openfhe/include/openfhe/cereal -I/your/openfhe/include/openfhe/binfhe"
export CGO_LDFLAGS="-L/your/openfhe/lib -Wl,-rpath,/your/openfhe/lib"
go build -tags openfhe ./...
```

## Pull requests

1. Fork and create a feature branch off `main`.
2. Keep PRs small and focused — one logical change per PR.
3. Include tests. For framework changes, exercise the change via at
   least one of the reference apps in `examples/`.
4. Run `go vet ./...` and `go test ./...` before pushing.
5. Update `CHANGELOG.md` under `[Unreleased]` for any user-visible
   change.
6. Use a clear commit message:
   - First line: short imperative summary (under 70 chars).
   - Blank line, then a paragraph explaining the *why*.
   - Reference issues with `Closes #N` / `Refs #N` when relevant.

## Code style

- Go: `gofmt`-clean, idiomatic, no `interface{}` where `any` works.
- Comments explain *why* a non-obvious decision exists, not *what* the
  code does.
- C++ wrapper (`pkg/ares/crypto/cgo/`): C-callable, `try { ... } catch`
  the world, return error codes rather than throwing across the FFI
  boundary.

## What we welcome

- New reference apps in `examples/` that exercise framework primitives
  in domains we haven't covered (governance / voting, biodiversity
  allocation, peer review, etc.).
- Documentation improvements (the framework is dense; clear teaching
  helps).
- CI / build portability fixes (Apple Silicon, Linux distros with
  non-default OpenFHE prefixes, etc.).
- New keygen variants, scoring primitives, post-result patterns.

## What we'll push back on

- Framework code that bakes in app-specific assumptions (e.g.,
  hardcoded vector dimensions, scoring shapes, payload formats).
- Backwards-compatibility shims for pre-1.0 API. Break things cleanly
  and document in `CHANGELOG.md` instead.
- Cosmetic-only diffs that touch many files without a clear goal.

## License

By contributing, you agree your contribution is licensed under the
[Apache License 2.0](LICENSE).
