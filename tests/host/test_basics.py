"""Redaction, classified errors, XDG layout and trusted configuration."""

from __future__ import annotations

import json
import os
import stat

from studyroom import config as configmod
from studyroom import fsutil, redact
from studyroom.errors import EXIT_CODES, Failure, StudyRoomError, fail
from studyroom.paths import host_paths

from tests.host.helpers import FAKE_ACCESS, FAKE_PAT, FAKE_REFRESH, TempHome


class RedactionTests(TempHome):
    def test_registered_values_never_render(self) -> None:
        redact.register(FAKE_REFRESH)
        text = f"refresh failed for {FAKE_REFRESH} at step 2"
        self.assertNotIn(FAKE_REFRESH, redact.redact_text(text))
        self.assertIn(redact.REDACTED, redact.redact_text(text))

    def test_token_shapes_redact_without_registration(self) -> None:
        cases = [
            f"Authorization: Bearer {FAKE_ACCESS}",
            f'{{"access_token": "{FAKE_ACCESS}", "refresh_token": "x-{FAKE_REFRESH}"}}',
            f"refresh_token={FAKE_REFRESH}&client_id=abc",
            f"token {FAKE_PAT} leaked",
            "sk-proj-FAKEFAKEFAKEFAKEFAKE1234",
            "github_pat_FAKE_11AAAAAAAAAAAAAAAAAAAAAA",
        ]
        for text in cases:
            out = redact.redact_text(text)
            for secret in (FAKE_ACCESS, FAKE_REFRESH, FAKE_PAT, "sk-proj-FAKEFAKEFAKEFAKEFAKE1234", "github_pat_FAKE_11AAAAAAAAAAAAAAAAAAAAAA"):
                self.assertNotIn(secret, out, text)

    def test_structured_state_registers_secret_leaves_only(self) -> None:
        redact.register_mapping({"access": FAKE_ACCESS, "refresh": FAKE_REFRESH, "expires_ms": 123, "client_id": "issued-client-xyz"})
        out = redact.redact_text(f"{FAKE_ACCESS} {FAKE_REFRESH} expires 123")
        self.assertNotIn(FAKE_ACCESS, out)
        self.assertNotIn(FAKE_REFRESH, out)
        self.assertIn("123", out)

    def test_errors_are_classified_and_redacted(self) -> None:
        redact.register(FAKE_REFRESH)
        err = fail(Failure.AUTHORIZATION_EXPIRED, f"provider said invalid_grant for {FAKE_REFRESH}", hint=f"token {FAKE_PAT}")
        self.assertIsInstance(err, StudyRoomError)
        rendered = err.render()
        self.assertIn("authorization expired or revoked", rendered)
        self.assertNotIn(FAKE_REFRESH, rendered)
        self.assertNotIn(FAKE_PAT, rendered)
        self.assertEqual(err.exit_code, EXIT_CODES[Failure.AUTHORIZATION_EXPIRED])

    def test_every_spec_failure_class_exists(self) -> None:
        wanted = {
            "missing host prerequisite", "permission declined", "unsupported platform", "pin/checksum mismatch",
            "provider unavailable", "credentials not configured", "authorization expired or revoked", "refresh conflict",
            "external service unavailable", "model absent from authenticated catalog", "search unsupported",
            "network policy blocked destination", "Obsidian not configured", "vault path missing", "subagent crash or timeout",
        }
        self.assertTrue(wanted <= {f.value for f in Failure})
        self.assertEqual(len(set(EXIT_CODES.values())), len(EXIT_CODES))


class PathTests(TempHome):
    def test_xdg_defaults_and_overrides(self) -> None:
        p = host_paths({"HOME": "/home/u"})
        self.assertEqual(str(p.config_dir), "/home/u/.config/study-room")
        self.assertEqual(str(p.state_dir), "/home/u/.local/state/study-room")
        self.assertEqual(str(p.cache_dir), "/home/u/.cache/study-room")
        self.assertEqual(str(p.default_vault_dir), "/home/u/.local/share/study-room/obsidian-vault")
        p2 = host_paths({"HOME": "/home/u", "XDG_CONFIG_HOME": "/cfg", "XDG_DATA_HOME": "relative/ignored"})
        self.assertEqual(str(p2.config_dir), "/cfg/study-room")
        self.assertEqual(str(p2.data_dir), "/home/u/.local/share/study-room")

    def test_atomic_private_writes(self) -> None:
        target = self.paths.config_dir / "x.json"
        fsutil.atomic_write_json(target, {"a": 1})
        self.assertEqual(json.loads(target.read_text()), {"a": 1})
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(target.parent).st_mode), 0o700)
        self.assertEqual([p.name for p in target.parent.iterdir()], ["x.json"], "no temporary files left behind")


class ConfigTests(TempHome):
    def test_defaults(self) -> None:
        cfg = configmod.load(self.paths, create=True)
        cfg.save()
        d = cfg.data
        self.assertEqual(d["network"]["mode"], "balanced")
        self.assertEqual(d["profiles"]["main"]["thinking"], "max")
        self.assertEqual(d["profiles"]["researcher"]["thinking"], "medium")
        self.assertFalse(d["providers"]["kimi"]["enabled"])
        self.assertTrue(d["providers"]["kimi"]["experimental"])
        self.assertTrue(d["vault"]["path"].startswith(str(self.home)))
        self.assertNotIn("C:", d["vault"]["path"])
        self.assertEqual(stat.S_IMODE(os.stat(self.paths.config_file).st_mode), 0o600)
        text = self.paths.config_file.read_text()
        self.assertFalse(redact.contains_secret(text), "configuration holds no credential-shaped value")

    def test_installation_id_is_random_and_stable(self) -> None:
        a = configmod.load(self.paths, create=True)
        a.save()
        b = configmod.load(self.paths)
        self.assertEqual(a.installation_id, b.installation_id)
        other = host_paths({"HOME": str(self.tmp / "other")})
        self.assertNotEqual(configmod.load(other, create=True).installation_id, a.installation_id)

    def test_researcher_follows_main_until_set(self) -> None:
        cfg = self.make_config()
        r = cfg.researcher_effective_profile()
        self.assertEqual((r["provider"], r["model"], r["thinking"]), ("openai", "gpt-teach", "medium"))
        cfg.set("profiles.researcher.provider", "openai")
        cfg.set("profiles.researcher.model", "gpt-research")
        self.assertEqual(cfg.researcher_effective_profile()["model"], "gpt-research")
        cfg.set("profiles.main.model", "gpt-other")
        self.assertEqual(cfg.researcher_effective_profile()["model"], "gpt-research", "independent after initialization")

    def test_set_validates(self) -> None:
        cfg = self.make_config()
        for key, value in [
            ("profiles.main.thinking", "huge"),
            ("profiles.main.model", "openai/gpt-x"),
            ("profiles.main.model", "gpt-x:max"),
            ("vault.study_dir", "a/b"),
            ("profiles.researcher.allowed_model_overrides", "gpt-x"),
            ("nope.key", "1"),
        ]:
            with self.assertRaises(StudyRoomError, msg=key):
                cfg.set(key, value)
                configmod.validate(cfg.data)
            cfg = self.make_config()
        cfg.set("profiles.researcher.allowed_model_overrides", "openai/gpt-a, openai/gpt-b")
        self.assertEqual(cfg.get("profiles.researcher.allowed_model_overrides"), ["openai/gpt-a", "openai/gpt-b"])
        cfg.set("updates.interval_hours", "6")
        self.assertEqual(cfg.get("updates.interval_hours"), 6)
