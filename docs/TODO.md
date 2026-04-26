# wsdf TODO

## Priority 1 — Build system stabilization (build-improvements branch)

### Done
- [x] Multi-tier Wireshark detection: Cargo metadata → env vars → pkg-config → platform auto-detect → smoke test → source build
- [x] `post_build.rs`: rpath + codesign fix for Apple Silicon (silent dlopen failure)
- [x] `post_build.rs`: correct per-platform plugin install path (macOS `4-4` hyphens vs Linux `4.4` dots, Windows `%APPDATA%`)
- [x] `post_build.rs`: `detect_wireshark_version()` from tshark, `--wireshark-version` override
- [x] Smoke test: replaced hand-rolled `Command::new("cc")` + binary exec with `cc::Build::try_compile` against `src/smoke.c` (cross-compile safe)
- [x] `source-build` feature gate: `fallback_source_build()` no longer silently clones 200 MB
- [x] `is_cdylib_target()` bug fixed: was checking `CARGO_PKG_NAME == "builder"`, broken for any other plugin name
- [x] `plugin_version` symbol: was hardcoded `"0.0.1"`, now reads `env!("CARGO_PKG_VERSION")` from macro call site
- [x] Wireshark submodule: bumped 4.4.1 → 4.4.14

### Remaining
- [x] Remove `mach_object` + `build-target` build-deps — replace Mach-O dynamic dep discovery with directory scan; hardcode dep link strategy
- [x] Gate `cmake` build-dep behind `source-build` feature (currently always compiled)
- [x] Integration tests: `dissect_bytes(&[u8]) → serde_json::Value` helper using `text2pcap -i 17` + `tshark -T json -J wsdf_example`; `test_dissection_uncompressed_packet` asserts all builder fields

---

## Priority 2 — Lua API parity

The overarching goal is to provide a Lua-like API with Rust ergonomics and native C performance. Missing for decent parity:

### Core missing
- **PacketInfo getters** — timestamp, addresses, ports, frame number, protocol context. Currently only column setting and memory allocation.
- **Preferences system** — `Pref.bool()`, `Pref.uint()`, `Pref.enum()`, `Pref.range()`, `Pref.string()` builders and runtime access.
- **FieldBuilder convenience constructors** — `::ipv4()`, `::timestamp()`, `::string()`, `::guid()` matching Lua's `ProtoField` class.
- **DissectorTable runtime access** — `add()`, `remove()`, `try()`, `get_dissector()` equivalents.

### Advanced protocol features
- **Heuristic dissectors** — `proto:register_heuristic()` equivalent.
- **Field access system** — `Field`/`FieldInfo` classes for cross-protocol field references.
- **Address class** — `ip()`, `ipv6()`, `ether()` constructors and comparison.
- **Int64/UInt64** — large integer manipulation with arithmetic and bitwise ops.
- **Listener/Tap** — packet statistics framework.
- **Tree RAII** — eliminate `end_subtree()` calls with a `SubtreeGuard<'parent>` pattern.

### Error type
- Unify error handling before implementing any of the above — currently inconsistent across the codebase.

---

## Priority 3 — Multi-version Wireshark support

Follow openssl-sys pattern: one crate, multiple committed `bindings_44.rs` / `bindings_46.rs`, additive `cargo:rustc-cfg=wireshark44` flags, cfg-gated overlays.

- Current submodule: 4.4.14. Homebrew ships 4.6.4 — macOS users get `plugin_want_minor` mismatch today.
- **Next step**: bump submodule to 4.6.4, regen `bindings_46.rs`, emit `wireshark44`/`wireshark46` cfg flags, cfg-gate in `lib.rs`.
- Verify 4.6.1 ABI break (Issue 20881) does not affect `proto_plugin`, `proto_tree_add_item`, or `field_info` in a way that breaks wsdf source.
- Windows: hardcoded `C:\Program Files\Wireshark` covers ~90%; registry detection deferred.

---

## Ongoing — Monitor

**Plugin API changes (MR !13747)**: still open as of 2026-04-18, not merged. Represents a revert of a prior redesign. No action until it merges. Subscribe to GitLab thread or check before 5.0 branch cut.

**Wireshark 5.0**: milestone expired 2026-04-01 at 45% complete. Undated. 4.4 and 4.6 both supported.

---

## Developer experience (lower priority)

- **Logging in generated code** — use `log` crate, re-export `log` + `env_logger` from `wsdf` so generated code can call `wsdf::log::info!`.
- **Soname/install_name pattern** — document that plugin crates should emit `cargo:rustc-cdylib-link-arg` from their own `build.rs`; provide helper in `wsdf` crate.
- **CI**: Docker multi-distro envs added (ubuntu/fedora/alpine). Integration test job pending item 1 above.
- **Code generation research** — Wireshark uses `WSLUA_*` macros + `make-reg.py`. Proc-macro automation for wsdf is speculative; research before committing.
