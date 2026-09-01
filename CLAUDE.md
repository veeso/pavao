# CLAUDE.md

This file provides guidance to Claude Code when working with code in this
repository.

`AGENTS.md` is a symbolic link to this file so every coding agent uses the same
repository contract.

## Commands

Every recurring task runs through a [`just`](https://just.systems) recipe. Do
not bypass a recipe with an ad hoc Cargo or tool command. If a recurring task
has no recipe, add one under `just/` before using it. Run `just` to list all
recipes.

```sh
just build                         # Build all workspace targets.
just release                       # Build all targets in release mode.
just vendored                      # Build the vendored transfer example.
just test                          # Run target and documentation tests.
just doctest                       # Run documentation tests.
just coverage                      # Write LCOV coverage to lcov.info.
just fmt                           # Format Markdown, Rust, TOML, and YAML.
just fmt_check                     # Check formatting without changes.
just lint "-- -D warnings"         # Run Clippy and deny warnings.
just doc                           # Build documentation and deny warnings.
just deny                          # Audit dependencies with cargo-deny.
just scan_secrets                  # Scan the repository with TruffleHog.
just check                         # Run the complete local quality gate.
just changelog_preview 0.2.17      # Preview an unreleased changelog.
just changelog 0.2.17              # Generate CHANGELOG.md.
just publish pavao "--dry-run --allow-dirty"
```

The regular build requires `libsmbclient` and its development files. On macOS,
install Samba and `pkg-config` with Homebrew. On Debian-based systems, install
`libsmbclient` and `libsmbclient-dev`.

Tests start a Samba container through `testcontainers`, so Docker must be
available locally.

To run one test, pass its filter through the recipe:

```sh
just test "should_list_dir"
just test "-- --nocapture"
```

Never request build or test parallelism above eight from the command line. This
is an invocation constraint only; do not encode the cap in tracked files.

If a required tool or native library is missing, report it. Never claim a check
passed or silently replace it with a weaker command.

## Architecture

Pavão is a Cargo workspace providing a Rust SMB 2/3 client on top of Samba's
`libsmbclient`.

- `pavao/` is the public safe wrapper. `SmbClient` owns the native context,
  `smb/` contains the client and public SMB types, and `test/` manages the Samba
  test container.
- `pavao-sys/` exposes the raw `libsmbclient` FFI and chooses between the system
  library and the vendored build in `build.rs`.
- `pavao-src/` downloads and compiles the pinned Samba source used by the
  `vendored` feature. Its large source list mirrors the native build and should
  be changed only when the bundled Samba release changes.
- `pavao/build.rs` defines platform aliases used by the safe wrapper.

The workspace features have distinct purposes: `debug` enables native Samba
debug output, `no-log` disables `log` output at compile time, and `vendored`
builds Samba through `pavao-src` instead of linking the system library.

## Tooling

- `Justfile` imports grouped recipes from `just/`.
- `dprint.json` formats Markdown, TOML, and YAML directly and delegates Rust
  files to nightly rustfmt.
- `cliff.toml` generates `CHANGELOG.md` from Conventional Commits.
- `deny.toml` enforces advisory, license, duplicate, wildcard, and source
  policy for every feature.
- `.github/workflows/ci.yml` drives build and quality jobs through `just`.
- `.github/workflows/vendored.yml` validates the bundled Samba path on Linux
  and macOS.
- Dedicated workflows audit GitHub Actions with zizmor and scan secrets with
  TruffleHog.

## Conventions

- The development toolchain is Rust 1.98.0 with edition 2024. The published
  workspace MSRV is 1.88.0; do not synchronize it with the newer development
  toolchain without a compatibility reason.
- Use `module_name.rs`; never add `mod.rs`.
- Public library items require canonical rustdoc and runnable examples.
- Use named format placeholders instead of positional `{}` placeholders.
- Prefer `#[expect]` with a reason over `#[allow]`.
- Keep Cargo dependencies and features alphabetically sorted, use workspace
  dependencies, and use minimal bare versions.
- Follow Conventional Commits with imperative, lower-case subjects. Do not add
  agent attribution, session links, or agent `Co-Authored-By` lines.
- After changing a Markdown file containing a table, run
  `fmt-md-tables -i <file>`.
- After changing `.github/workflows/`, run `zizmor .github/workflows` until it
  exits cleanly. Pin actions to full commit SHAs with matching version comments,
  declare least-privilege permissions, and disable persisted checkout
  credentials.
