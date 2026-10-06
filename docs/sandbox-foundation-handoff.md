# Draft: handoff to digigrant/sandbox-foundation

**Status:** draft. SPEC 23 asks for a documentation-only handoff to `digigrant/sandbox-foundation` once Study Room has been implemented *and* tested. Hermetic testing is done; this draft is to be copied there after the live acceptance in [ACCEPTANCE.md](ACCEPTANCE.md) passes. Nothing is extracted from either repository now.

## Possible shared seams, with the evidence behind them

| Seam | Study Room implementation | Evidence it generalizes | Open questions |
| --- | --- | --- | --- |
| Keyring access | `studyroom/keyring.py`: per-tool Secret Service namespace; `SearchItems` for the locked state without prompting; values only on stdin | devenv implements the same pattern independently | Whether one shared namespace or per-tool namespaces is better |
| Infisical access | `studyroom/infisical.py`: Universal Auth per call, token revoked after use, writes limited to an allowlist of secrets; per-installation entries in a shared secret | devenv reads secrets the same way; Study Room adds writes | Path-scoped permissions need a paid Infisical plan |
| Docker Sandbox secret registration | `studyroom/entry.py` `register_secrets`: command-backed placeholders (path and name only), placeholder reuse | devenv also uses command-backed secrets | Behaviour of custom secrets across sbx versions |
| Host prerequisite checks | `studyroom/hostdetect.py` plus JSON fixtures, capability-based (WSLg versus native) | Both projects target WSL2 and native Ubuntu | Which prerequisites are common |
| Deterministic update checks | `studyroom/updates.py` (cached, non-blocking), `studyroom/bump.py` (branch-only, rebuild, test) | devenv pins with `versions.env` and `devenv bump` | One lock format or two |
| Test fixtures | fake runner, fake HTTP transport, fake Infisical, fake sbx | Similar fakes exist in devenv's tests | A shared fixture package |
| Security invariants | placeholders only in the sandbox; nothing secret in arguments or files; redaction of every message | Shared by both projects | |

Remain project-specific (SPEC 23): provider bindings, network policy, workspace layout, persistence, Obsidian, and entry UX.
