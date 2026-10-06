"""OAuth parsing, refresh rotation, locking, atomic write-back, keyring and Infisical (SPEC 15, 20.1)."""

from __future__ import annotations

import io
import json
import threading
import time
import urllib.parse
from contextlib import redirect_stderr, redirect_stdout

from studyroom import cli, redact
from studyroom.errors import Failure, StudyRoomError
from studyroom.http import Client, FakeTransport, Response, json_response
from studyroom.infisical import FakeInfisical, Handles, Infisical
from studyroom.keyring import Keyring, _parse_search_items
from studyroom.oauth import kimi, openai
from studyroom.oauth.state import OAuthState, dump_document, empty_document, entry, parse, parse_document, with_entry
from studyroom.resolver import OAuthLocation, Resolver
from studyroom.runner import FakeRunner, Result

from tests.host.helpers import FAKE_ACCESS, FAKE_CLIENT_SECRET, FAKE_PAT, FAKE_REFRESH, TempHome

INSTALL = "3f1c2b9e-7a64-4d2e-9b1f-0c5d8e2a4f61"
NOW = 1_800_000_000.0


def state(**kw) -> OAuthState:
    base = dict(provider="openai", installation_id=INSTALL, access=FAKE_ACCESS, refresh=FAKE_REFRESH, expires_ms=int((NOW + 3600) * 1000), client_id="issued-client-1", scopes=["chatgpt.tokens.use.direct"])
    base.update(kw)
    return OAuthState(**base)


class OpenAIFlowTests(TempHome):
    def test_authorization_url_carries_pkce_resource_and_installation(self) -> None:
        pkce = openai.Pkce.new()
        url = openai.authorization_url(INSTALL, pkce, "st", "nonce")
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.assertTrue(url.startswith("https://auth.openai.com/api/accounts/authorize?"))
        self.assertEqual(q["code_challenge_method"], ["S256"])
        self.assertEqual(q["code_challenge"], [pkce.challenge])
        self.assertEqual(q["resource"], ["https://api.openai.com/v1"])
        self.assertEqual(q["ext_agent_host_id"], [f"urn:uuid:{INSTALL}"])
        self.assertIn("chatgpt.tokens.use.direct", q["scope"][0])
        self.assertNotIn(pkce.verifier, url, "the PKCE verifier never leaves this process")

    def test_callback_parsing_checks_state_and_issued_client(self) -> None:
        ok = f"{openai.REDIRECT_URI}?code=abc123&state=s1&client_id=issued-xyz"
        self.assertEqual(openai.parse_callback(ok, "s1"), ("abc123", "issued-xyz"))
        for bad, failure in [
            (f"{openai.REDIRECT_URI}?code=abc&state=other&client_id=x", Failure.PERMISSION_DECLINED),
            (f"{openai.REDIRECT_URI}?error=access_denied&state=s1", Failure.PERMISSION_DECLINED),
            (f"{openai.REDIRECT_URI}?code=abc&state=s1", Failure.PROVIDER_UNAVAILABLE),
            ("http://evil.example/auth/callback?code=abc&state=s1&client_id=x", Failure.PERMISSION_DECLINED),
        ]:
            with self.assertRaises(StudyRoomError) as ctx:
                openai.parse_callback(bad, "s1")
            self.assertEqual(ctx.exception.failure, failure, bad)

    def test_exchange_builds_complete_state(self) -> None:
        t = FakeTransport()
        t.on("POST", openai.TOKEN_URL, json_response({"access_token": FAKE_ACCESS, "refresh_token": FAKE_REFRESH, "id_token": "idtok", "expires_in": 3600, "scope": "openid chatgpt.tokens.use.direct"}))
        st = openai.exchange(Client(t), "code-1", openai.Pkce("verifier-1", "challenge-1"), "issued-1", INSTALL, now_ms=1000)
        self.assertEqual((st.provider, st.client_id, st.access, st.refresh), ("openai", "issued-1", FAKE_ACCESS, FAKE_REFRESH))
        self.assertEqual(st.expires_ms, 1000 + 3600_000 - openai.EXPIRY_MARGIN_MS)
        form = urllib.parse.parse_qs(t.requests[0].body.decode())
        self.assertEqual(form["grant_type"], ["authorization_code"])
        self.assertEqual(form["code_verifier"], ["verifier-1"])
        self.assertEqual(form["resource"], ["https://api.openai.com/v1"])
        self.assertNotIn("code-1", t.requests[0].url, "codes travel in the body, not the URL")

    def test_exchange_rejects_grants_without_direct_scope_or_id_token(self) -> None:
        for body in (
            {"access_token": "a" * 20, "refresh_token": "r" * 20, "id_token": "i", "expires_in": 60, "scope": "openid"},
            {"access_token": "a" * 20, "refresh_token": "r" * 20, "expires_in": 60, "scope": "chatgpt.tokens.use.direct"},
        ):
            t = FakeTransport().on("POST", openai.TOKEN_URL, json_response(body))
            with self.assertRaises(StudyRoomError):
                openai.exchange(Client(t), "c", openai.Pkce("v", "c"), "client", INSTALL)

    def test_refresh_rotates_and_reports_revocation(self) -> None:
        t = FakeTransport().on("POST", openai.TOKEN_URL, json_response({"access_token": "new-access-FAKE-0001", "refresh_token": "new-refresh-FAKE-0001", "expires_in": 600, "scope": "chatgpt.tokens.use.direct"}))
        new = openai.refresh(Client(t), state(), now_ms=5000)
        self.assertEqual((new.access, new.refresh, new.generation), ("new-access-FAKE-0001", "new-refresh-FAKE-0001", 2))
        form = urllib.parse.parse_qs(t.requests[0].body.decode())
        self.assertEqual(form["client_id"], ["issued-client-1"])
        self.assertEqual(form["refresh_token"], [FAKE_REFRESH])
        revoked = FakeTransport().on("POST", openai.TOKEN_URL, Response(400, json.dumps({"error": "invalid_grant", "refresh_token": FAKE_REFRESH}).encode()))
        with self.assertRaises(StudyRoomError) as ctx:
            openai.refresh(Client(revoked), state())
        self.assertEqual(ctx.exception.failure, Failure.AUTHORIZATION_EXPIRED)
        self.assertNotIn(FAKE_REFRESH, ctx.exception.render())


class KimiFlowTests(TempHome):
    def test_device_flow_pending_slow_down_then_success(self) -> None:
        answers = [
            Response(400, b'{"error":"authorization_pending"}'),
            Response(400, b'{"error":"slow_down","interval":7}'),
            json_response({"access_token": "kimi-access-FAKE-01", "refresh_token": "kimi-refresh-FAKE-01", "expires_in": 900}),
        ]
        t = FakeTransport().on("POST", kimi.TOKEN_URL, lambda _r: answers.pop(0))
        sleeps: list[float] = []
        clock = [NOW]
        st = kimi.poll(Client(t), {"device_code": "dev-FAKE-123456", "interval": 5, "expires_in": 900}, INSTALL, sleep=lambda s: (sleeps.append(s), clock.__setitem__(0, clock[0] + s)), now=lambda: clock[0])
        self.assertEqual(sleeps, [5, 5, 7])
        self.assertEqual((st.provider, st.access), ("kimi", "kimi-access-FAKE-01"))

    def test_device_flow_denied_and_expired(self) -> None:
        t = FakeTransport().on("POST", kimi.TOKEN_URL, Response(400, b'{"error":"access_denied"}'))
        with self.assertRaises(StudyRoomError) as ctx:
            kimi.poll(Client(t), {"device_code": "dev-FAKE-123456"}, INSTALL, sleep=lambda s: None)
        self.assertEqual(ctx.exception.failure, Failure.PERMISSION_DECLINED)
        t2 = FakeTransport().on("POST", kimi.TOKEN_URL, Response(400, b'{"error":"expired_token"}'))
        with self.assertRaises(StudyRoomError) as ctx2:
            kimi.poll(Client(t2), {"device_code": "dev-FAKE-123456"}, INSTALL, sleep=lambda s: None)
        self.assertEqual(ctx2.exception.failure, Failure.AUTHORIZATION_EXPIRED)

    def test_device_authorization_requires_https_verification(self) -> None:
        t = FakeTransport().on("POST", kimi.DEVICE_URL, json_response({"device_code": "d" * 10, "user_code": "ABCD", "verification_uri": "http://x", "verification_uri_complete": "http://x?c=1"}))
        with self.assertRaises(StudyRoomError):
            kimi.start_device(Client(t))


class StateTests(TempHome):
    def test_round_trip_and_ownership_checks(self) -> None:
        st = state()
        again = parse(st.to_json(), provider="openai", installation_id=INSTALL)
        self.assertEqual(again, st)
        for kwargs in ({"provider": "kimi", "installation_id": INSTALL}, {"provider": "openai", "installation_id": "other"}):
            with self.assertRaises(StudyRoomError):
                parse(st.to_json(), **kwargs)
        self.assertNotIn(FAKE_ACCESS, st.describe())


class KeyringTests(TempHome):
    def test_search_items_parsing(self) -> None:
        self.assertEqual(_parse_search_items('aoao 1 "/org/freedesktop/secrets/collection/login/7" 0'), (["/org/freedesktop/secrets/collection/login/7"], []))
        self.assertEqual(_parse_search_items('aoao 0 1 "/x/1"'), ([], ["/x/1"]))
        self.assertEqual(_parse_search_items("aoao 0 0"), ([], []))

    def runner(self, search: str) -> FakeRunner:
        r = FakeRunner(available={"secret-tool", "busctl"})
        r.on(["busctl"], search)
        r.on(["secret-tool", "lookup"], FAKE_CLIENT_SECRET + "\n")
        r.on(["secret-tool", "store"], 0)
        return r

    def test_locked_keyring_fails_fast_without_prompting(self) -> None:
        r = self.runner('aoao 0 1 "/x/1"')
        with self.assertRaises(StudyRoomError) as ctx:
            Keyring(r).lookup("infisical-client-secret")
        self.assertIn("locked", ctx.exception.message)
        self.assertFalse(any(a[:2] == ["secret-tool", "lookup"] for a in r.argvs()), "no unlock prompt from a non-interactive caller")

    def test_lookup_and_store_keep_values_off_the_command_line(self) -> None:
        r = self.runner('aoao 1 "/x/1" 0')
        kr = Keyring(r, service="study-room-test")
        self.assertEqual(kr.lookup("infisical-client-secret"), FAKE_CLIENT_SECRET)
        kr.store("infisical-client-secret", FAKE_CLIENT_SECRET)
        store_argv, store_input = next((a, i) for a, i in r.calls if a[:2] == ["secret-tool", "store"])
        self.assertNotIn(FAKE_CLIENT_SECRET, " ".join(store_argv))
        self.assertEqual(store_input, FAKE_CLIENT_SECRET)
        self.assertIn("study-room-test", store_argv, "own namespace")
        self.assertNotIn("devenv", " ".join(store_argv))

    def test_missing_entry(self) -> None:
        with self.assertRaises(StudyRoomError) as ctx:
            Keyring(self.runner("aoao 0 0")).lookup("infisical-project-id")
        self.assertEqual(ctx.exception.failure, Failure.CREDENTIALS_NOT_CONFIGURED)


OPENAI_SECRET = ("/", "OPENAI_REFRESH_TOKEN")


class InfisicalTests(TempHome):
    def client(self, t: FakeTransport) -> Infisical:
        t.on("POST", "https://app.infisical.com/api/v1/auth/universal-auth/login", json_response({"accessToken": "inf-session-FAKE-1", "expiresIn": 300, "tokenType": "Bearer"}))
        return Infisical("https://app.infisical.com", "dev", Handles("proj-FAKE-1", "client-FAKE-1", FAKE_CLIENT_SECRET), Client(t), writable={OPENAI_SECRET})

    def test_read_never_expands_references_and_keeps_secrets_out_of_urls(self) -> None:
        t = FakeTransport()
        inf = self.client(t)
        t.on("GET", "https://app.infisical.com/api/v4/secrets/OPENAI_REFRESH_TOKEN", json_response({"secret": {"secretValue": '{"x":1}', "version": 3}}))
        self.assertEqual(inf.get(*OPENAI_SECRET), '{"x":1}')
        login, read = t.requests
        self.assertEqual(json.loads(login.body), {"clientId": "client-FAKE-1", "clientSecret": FAKE_CLIENT_SECRET})
        self.assertIn("expandSecretReferences=false", read.url)
        self.assertIn("projectId=proj-FAKE-1", read.url)
        self.assertNotIn(FAKE_CLIENT_SECRET, read.url)
        self.assertEqual(read.headers["Authorization"], "Bearer inf-session-FAKE-1")

    def test_missing_secret_is_none_and_forbidden_is_classified(self) -> None:
        t = FakeTransport()
        inf = self.client(t)
        t.on("GET", "https://app.infisical.com/api/v4/secrets/", Response(404, b'{"message":"Secret not found"}'))
        self.assertIsNone(inf.get(*OPENAI_SECRET))
        t.on("GET", "https://app.infisical.com/api/v4/secrets/", Response(403, b"{}"))
        with self.assertRaises(StudyRoomError) as ctx:
            inf.get(*OPENAI_SECRET)
        self.assertEqual(ctx.exception.failure, Failure.CREDENTIALS_NOT_CONFIGURED)

    def test_update_patches_the_existing_secret_in_one_request(self) -> None:
        t = FakeTransport()
        inf = self.client(t)
        t.on("PATCH", "https://app.infisical.com/api/v4/secrets/OPENAI_REFRESH_TOKEN", json_response({"secret": {"version": 4}}))
        inf.put(*OPENAI_SECRET, '{"v":2}', exists=True)
        patch = next(r for r in t.requests if r.method == "PATCH")
        body = json.loads(patch.body)
        self.assertEqual((body["secretPath"], body["secretValue"], body["projectId"], body["environment"]), ("/", '{"v":2}', "proj-FAKE-1", "dev"))

    def test_create_when_missing(self) -> None:
        t = FakeTransport()
        inf = self.client(t)
        t.on("POST", "https://app.infisical.com/api/v4/secrets/OPENAI_REFRESH_TOKEN", json_response({"secret": {"version": 1}}))
        inf.put(*OPENAI_SECRET, '{"v":1}', exists=False)
        self.assertEqual([r.method for r in t.requests], ["POST", "POST"])

    def test_refuses_writes_to_anything_but_the_configured_oauth_secrets(self) -> None:
        inf = self.client(FakeTransport())
        for path, name in (("/", "GITHUB_GEJ_MACHINE_PAT"), ("/", "CLAUDE_CODE_OAUTH_TOKEN"), ("/other", "OPENAI_REFRESH_TOKEN"), ("/", "KIMI_REFRESH_TOKEN")):
            with self.assertRaises(StudyRoomError):
                inf.put(path, name, "v", exists=True)

    def test_change_approval_is_not_a_write(self) -> None:
        t = FakeTransport()
        inf = self.client(t)
        t.on("PATCH", "https://app.infisical.com/api/v4/secrets/OPENAI_REFRESH_TOKEN", json_response({"approval": {"id": "a"}}))
        with self.assertRaises(StudyRoomError):
            inf.put(*OPENAI_SECRET, "v", exists=True)


class DocumentTests(TempHome):
    def test_entries_are_per_installation(self) -> None:
        doc = with_entry(empty_document("openai"), state())
        other = state(installation_id="0b7d4c2a-1111-4c2e-9b1f-0c5d8e2a4f62", access="other-access-FAKE-01", refresh="other-refresh-FAKE-01")
        doc = with_entry(doc, other)
        parsed, foreign = parse_document(dump_document(doc), "openai")
        self.assertFalse(foreign)
        self.assertEqual(entry(parsed, "openai", INSTALL).refresh, FAKE_REFRESH)
        self.assertEqual(entry(parsed, "openai", other.installation_id).refresh, "other-refresh-FAKE-01")
        self.assertIsNone(entry(parsed, "openai", "a1b2c3d4-0000-4000-8000-000000000000"))

    def test_blank_values_are_fresh_and_foreign_values_are_flagged(self) -> None:
        self.assertEqual(parse_document(None, "openai"), (empty_document("openai"), False))
        self.assertEqual(parse_document("  ", "openai"), (empty_document("openai"), False))
        for foreign in ("rt_FAKE_bare_refresh_token_pasted_by_hand", '{"some":"json"}', dump_document(empty_document("kimi"))):
            self.assertTrue(parse_document(foreign, "openai")[1], foreign)
        self.assertNotIn("rt_FAKE_bare_refresh_token_pasted_by_hand", redact.redact_text("value rt_FAKE_bare_refresh_token_pasted_by_hand"))


OTHER_INSTALL = "0b7d4c2a-1111-4c2e-9b1f-0c5d8e2a4f62"


class ResolverTests(TempHome):
    def setUp(self) -> None:
        super().setUp()
        self.store = FakeInfisical({})
        self.refresh_calls = 0

    def resolver(self, installation: str = INSTALL, **kw) -> Resolver:
        def refresher(_client, st: OAuthState) -> OAuthState:
            self.refresh_calls += 1
            tag = "A" if st.installation_id == INSTALL else "B"
            return st.rotated(f"rotated-access-FAKE-{tag}{st.generation + 1:04d}", f"rotated-refresh-FAKE-{tag}{st.generation + 1:04d}", int((NOW + 7200) * 1000), int(NOW * 1000))

        return Resolver(
            self.store,
            self.paths,
            installation,
            {"openai": OAuthLocation(*OPENAI_SECRET)},
            refreshers={"openai": kw.get("refresher", refresher)},
            clock=lambda: NOW,
            sleep=kw.get("sleep", lambda s: None),
        )

    def put(self, *states: OAuthState) -> None:
        doc = empty_document("openai")
        for st in states:
            doc = with_entry(doc, st)
        self.store.values[OPENAI_SECRET] = dump_document(doc)

    def stored(self, installation: str = INSTALL) -> OAuthState:
        return entry(parse_document(self.store.values[OPENAI_SECRET], "openai")[0], "openai", installation)

    def test_valid_token_needs_no_refresh(self) -> None:
        self.put(state())
        self.assertEqual(self.resolver().access_token("openai"), FAKE_ACCESS)
        self.assertEqual(self.refresh_calls, 0)
        self.assertEqual(self.store.writes, 0)
        self.assertEqual(self.store.revoked, 1, "the Infisical session is ended after use")

    def test_near_expiry_rotates_and_writes_back_before_returning(self) -> None:
        self.put(state(expires_ms=int((NOW + 60) * 1000)))
        token = self.resolver().access_token("openai")
        self.assertEqual(token, "rotated-access-FAKE-A0002")
        st = self.stored()
        self.assertEqual((st.refresh, st.generation), ("rotated-refresh-FAKE-A0002", 2))
        self.assertEqual(self.store.writes, 1)

    def test_hosts_sharing_the_secret_rotate_only_their_own_entry(self) -> None:
        other = state(installation_id=OTHER_INSTALL, access="b-access-FAKE-0001", refresh="b-refresh-FAKE-0001", expires_ms=int((NOW + 60) * 1000))
        self.put(state(expires_ms=int((NOW + 60) * 1000)), other)
        self.assertEqual(self.resolver().access_token("openai"), "rotated-access-FAKE-A0002")
        self.assertEqual(self.stored(OTHER_INSTALL).refresh, "b-refresh-FAKE-0001", "host A left host B's entry alone")
        self.assertEqual(self.resolver(OTHER_INSTALL).access_token("openai"), "rotated-access-FAKE-B0002")
        self.assertEqual(self.stored().refresh, "rotated-refresh-FAKE-A0002", "host B left host A's rotated entry alone")
        self.assertEqual(self.stored(OTHER_INSTALL).refresh, "rotated-refresh-FAKE-B0002")

    def test_a_concurrent_write_from_another_host_is_merged_again(self) -> None:
        other = state(installation_id=OTHER_INSTALL, access="b-access-FAKE-0001", refresh="b-refresh-FAKE-0001")
        self.put(state(expires_ms=int((NOW + 60) * 1000)), other)
        stale = self.store.values[OPENAI_SECRET]  # host B read this before our write
        original_put = self.store.put
        raced = []

        def racing_put(path, name, value, *, exists, token=None):
            original_put(path, name, value, exists=exists, token=token)
            if not raced:
                raced.append(1)
                doc = parse_document(stale, "openai")[0]
                b = entry(doc, "openai", OTHER_INSTALL)
                doc = with_entry(doc, b.rotated("b-access-FAKE-0002", "b-refresh-FAKE-0002", 1, 1))
                original_put(path, name, dump_document(doc), exists=True)  # B's write drops our new entry

        self.store.put = racing_put  # type: ignore[assignment]
        self.assertEqual(self.resolver().access_token("openai"), "rotated-access-FAKE-A0002")
        self.assertEqual(self.stored().refresh, "rotated-refresh-FAKE-A0002", "our rotated entry was merged back")
        self.assertEqual(self.stored(OTHER_INSTALL).refresh, "b-refresh-FAKE-0002", "and host B's rotation was kept")

    def test_late_clobbering_is_caught_by_the_settled_read_back(self) -> None:
        self.put(state(expires_ms=int((NOW + 60) * 1000)))
        stale = self.store.values[OPENAI_SECRET]
        clobbered = []

        def sleep(_s: float) -> None:
            if not clobbered:
                clobbered.append(1)
                self.store.values[OPENAI_SECRET] = stale  # another host's write lands after our first check

        self.assertEqual(self.resolver(sleep=sleep).access_token("openai"), "rotated-access-FAKE-A0002")
        self.assertEqual(self.stored().generation, 2)

    def test_concurrent_resolvers_on_one_host_spend_the_refresh_token_once(self) -> None:
        self.put(state(expires_ms=int((NOW + 60) * 1000)))
        barrier = threading.Barrier(4)
        results: list[str] = []

        def slow_refresher(_c, st: OAuthState) -> OAuthState:
            self.refresh_calls += 1
            time.sleep(0.2)
            return st.rotated("rotated-access-FAKE-0002", "rotated-refresh-FAKE-0002", int((NOW + 7200) * 1000), int(NOW * 1000))

        def worker() -> None:
            barrier.wait()
            results.append(self.resolver(refresher=slow_refresher).access_token("openai"))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(self.refresh_calls, 1)
        self.assertEqual(results, ["rotated-access-FAKE-0002"] * 4)

    def test_transient_write_failures_are_retried(self) -> None:
        self.put(state(expires_ms=int((NOW + 60) * 1000)))
        self.store.fail_writes = 2
        self.assertEqual(self.resolver().access_token("openai"), "rotated-access-FAKE-A0002")
        self.assertEqual(self.stored().generation, 2)

    def test_persistent_write_failure_is_explicit(self) -> None:
        self.put(state(expires_ms=int((NOW + 60) * 1000)))
        self.store.fail_writes = 10
        with self.assertRaises(StudyRoomError) as ctx:
            self.resolver().access_token("openai")
        self.assertEqual(ctx.exception.failure, Failure.EXTERNAL_SERVICE_UNAVAILABLE)
        self.assertIn("study-room auth openai", ctx.exception.hint or "")
        self.assertNotIn("rotated-refresh-FAKE-A0002", ctx.exception.render())

    def test_persistent_conflict_is_reported(self) -> None:
        self.put(state(expires_ms=int((NOW + 60) * 1000)))
        stale = self.store.values[OPENAI_SECRET]
        original_put = self.store.put

        def always_clobbered(path, name, value, *, exists, token=None):
            original_put(path, name, value, exists=exists, token=token)
            original_put(path, name, stale, exists=True)

        self.store.put = always_clobbered  # type: ignore[assignment]
        with self.assertRaises(StudyRoomError) as ctx:
            self.resolver().access_token("openai")
        self.assertEqual(ctx.exception.failure, Failure.REFRESH_CONFLICT)

    def test_missing_entry_asks_for_authorization(self) -> None:
        with self.assertRaises(StudyRoomError) as ctx:
            self.resolver().access_token("openai")
        self.assertEqual(ctx.exception.failure, Failure.CREDENTIALS_NOT_CONFIGURED)
        self.assertIn("study-room auth openai", ctx.exception.hint or "")
        self.put(state(installation_id=OTHER_INSTALL))
        with self.assertRaises(StudyRoomError):
            self.resolver().access_token("openai")

    def test_a_foreign_value_is_never_used_or_silently_replaced(self) -> None:
        self.store.values[OPENAI_SECRET] = "rt_FAKE_value_the_captain_pasted"
        with self.assertRaises(StudyRoomError) as ctx:
            self.resolver().access_token("openai")
        self.assertIn("did not write", ctx.exception.message)
        with self.assertRaises(StudyRoomError) as ctx2:
            self.resolver().save_new(state(), replace_foreign=lambda: False)
        self.assertEqual(ctx2.exception.failure, Failure.PERMISSION_DECLINED)
        self.assertEqual(self.store.values[OPENAI_SECRET], "rt_FAKE_value_the_captain_pasted")
        self.resolver().save_new(state(), replace_foreign=lambda: True)
        self.assertEqual(self.stored().refresh, FAKE_REFRESH)

    def test_an_empty_secret_is_filled_without_asking(self) -> None:
        self.store.values[OPENAI_SECRET] = ""
        self.resolver().save_new(state(), replace_foreign=lambda: self.fail("must not ask"))
        self.assertEqual(self.stored().generation, 1)

    def test_save_new_increments_generation(self) -> None:
        self.put(state(generation=5))
        self.resolver().save_new(state(access="fresh-access-FAKE-0009", refresh="fresh-refresh-FAKE-0009"))
        self.assertEqual(self.stored().generation, 6)


class ResolveCommandTests(TempHome):
    """`study-room resolve` as Docker Sandboxes calls it: value on stdout, nothing else."""

    def run_resolve(self, name: str, store: FakeInfisical) -> tuple[int, str, str]:
        cfg = self.make_config()
        ctx = cli.Context(FakeRunner(), env=self.env)
        ctx._config = cfg
        ctx.infisical = lambda interactive=False: store  # type: ignore[assignment]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["resolve", name], ctx=ctx)
        return code, out.getvalue(), err.getvalue()

    def test_github_value_only(self) -> None:
        store = FakeInfisical({("/", "GITHUB_GEJ_MACHINE_PAT"): FAKE_PAT})
        code, out, err = self.run_resolve("github", store)
        self.assertEqual((code, out, err), (0, FAKE_PAT + "\n", ""))

    def test_openai_value_only(self) -> None:
        far = state(expires_ms=int((time.time() + 86400) * 1000))
        store = FakeInfisical({OPENAI_SECRET: dump_document(with_entry(empty_document("openai"), far))})
        code, out, err = self.run_resolve("openai", store)
        self.assertEqual((code, out, err), (0, FAKE_ACCESS + "\n", ""))

    def test_failure_is_one_redacted_line_on_stderr(self) -> None:
        redact.REGISTRY.clear()
        code, out, err = self.run_resolve("openai", FakeInfisical({}))
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("credentials not configured", err)
        self.assertLessEqual(len(err.strip().splitlines()), 2)

    def test_disabled_provider_is_refused(self) -> None:
        code, out, err = self.run_resolve("kimi", FakeInfisical({}))
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("disabled", err)
