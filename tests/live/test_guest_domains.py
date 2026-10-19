"""Live validation of the guest_configuration / guest_users / guest_actions
operation catalogue (38 operations) against a real ClearPass 6.12.4 appliance.

Calling style
-------------
Optional parameters are OMITTED unless the assertion is specifically about one.
That is the path the registry FieldInfo bug lived on.

Safety posture for this scope
-----------------------------
* ``guest_users`` is a safe fixture family: full create -> read -> update ->
  delete lifecycles run inside the ``zzz-mcptest-*`` namespace.
* ``guest_configuration`` is treated READ-ONLY. Its delete operations are not in
  the sweepable set, so anything created there could never be cleaned up.
  Creation is recorded ``BLOCKED``. Its write operations are still exercised,
  but only along paths that provably cannot mutate a pre-existing object:
    - against ids/names verified absent immediately beforehand, or
    - against the operation's own client-side guard (confirm / JSON / required
      field), which returns before any HTTP request is issued.
* ``send_guest_receipt_sms`` / ``send_guest_receipt_email`` are denylisted and
  are contract-tested offline only: registered, describable, never dispatched.

Verdicts
--------
PASS / EXPECTED_SKIP / FAIL come from ``harness.classify``. A fourth bookkeeping
verdict, ``BLOCKED``, is recorded directly for operations whose real behaviour
cannot be exercised safely on this appliance.
"""

from __future__ import annotations

import json
import secrets

import pytest

from . import harness
from .denylist import DENYLIST, DenylistedOperation
from .harness import PASS, assert_ours, classify, fixture_name

BLOCKED = "BLOCKED"

CONFIG = "guest_configuration"
USERS = "guest_users"
ACTIONS = "guest_actions"

# Built-in ClearPass role on this appliance, and its id in the **Guest
# Manager** namespace (the namespace a guest account's role_id belongs to).
# The Policy Manager /role namespace calls this role 3, which means
# "[Employee]" to Guest Manager -- resolving there is a privilege escalation.
GUEST_ROLE = "[Guest]"
GUEST_ROLE_ID = 2

# Ids/names used for deliberate negative tests. Every test that sends a write
# verb to one of these first proves the target is absent.
ABSENT_ID = 999999
ABSENT_NAME = "zzz-mcptest-nonexistent-page"


def _record_blocked(recorder, operation, domain, reason, params=None):
    recorder.record(operation, domain, "blocked", BLOCKED, params or {}, reason, 0.0)


# ==========================================================================
# guest_users -- the safe fixture family. Full lifecycle.
# ==========================================================================


@pytest.fixture
def guest(run_async, recorder, run_id, cleanup):
    """Create one fixture guest user and yield (username, id).

    The session sweep is the backstop; an explicit cleanup is registered too so
    nothing survives a mid-test explosion.
    """
    name = fixture_name(run_id, secrets.token_hex(2))
    password = f"Zz!{secrets.token_urlsafe(12)}"
    cleanup.add(lambda: harness.sweep_fixtures())

    created = run_async(recorder.run(
        "create_guest_user", domain=USERS, tier="create",
        username=name, password=password, role_name=GUEST_ROLE,
    ))
    assert classify(created, "create_guest_user") == PASS, \
        f"create_guest_user -> {created}"
    uid = (created.get("user") or {}).get("id")
    assert uid is not None, f"create_guest_user returned no id: {created}"
    yield name, uid, created


def test_list_guest_users_no_params(run_async, recorder):
    """Omission path: every optional parameter left off."""
    result = run_async(recorder.run("list_guest_users", domain=USERS, tier="read"))
    assert classify(result, "list_guest_users") == PASS, result
    assert "users" in result, sorted(result)
    assert "FieldInfo" not in str(result), "FieldInfo leaked into the response"


def test_guest_user_lifecycle(run_async, recorder, guest):
    """create -> get -> update -> delete, all by numeric id."""
    name, uid, _ = guest

    fetched = run_async(recorder.run(
        "get_guest_user", domain=USERS, tier="read", user_id=uid))
    assert classify(fetched, "get_guest_user") == PASS, fetched
    assert fetched["user"]["username"] == name, \
        f"id {uid} does not belong to {name}: {fetched}"

    assert_ours(fetched["user"]["username"])
    updated = run_async(recorder.run(
        "update_guest_user", domain=USERS, tier="update",
        user_id=uid, enabled=False))
    assert classify(updated, "update_guest_user") == PASS, updated

    assert_ours(name)
    deleted = run_async(recorder.run(
        "delete_guest_user", domain=USERS, tier="delete",
        user_id=uid, confirm=True))
    assert classify(deleted, "delete_guest_user") == PASS, deleted

    gone = run_async(recorder.run(
        "get_guest_user", domain=USERS, tier="negative",
        expect_absent=True, user_id=uid))
    assert gone.get("success") is not True, f"still present after delete: {gone}"
    assert classify(gone, "get_guest_user", expect_absent=True) == PASS, gone


def test_create_guest_user_pure_defaults_work_on_a_stock_appliance(
        run_async, recorder, run_id, cleanup):
    """FIXED: the role_name default is "[Guest]", a real ClearPass role.

    Every built-in ClearPass role is bracketed, so the old default "Guest"
    made a pure-defaults create -- the exact call an LLM makes first -- fail
    with ``Role 'Guest' not found``. The defaults must now produce a working
    guest account carrying the least-privilege role.
    """
    name = fixture_name(run_id, "defaultrole")
    cleanup.add(lambda: harness.sweep_fixtures())
    result = run_async(recorder.run(
        "create_guest_user", domain=USERS, tier="create",
        username=name, password=f"Zz!{secrets.token_urlsafe(12)}"))
    assert classify(result, "create_guest_user") == PASS, result
    user = result.get("user") or {}
    assert user.get("role_name") == GUEST_ROLE, result
    assert user.get("role_id") == GUEST_ROLE_ID, result

    assert_ours(name)
    run_async(harness.invoke("delete_guest_user", user_id=user.get("id"),
                             confirm=True))


def test_create_guest_user_role_name_resolves_in_the_guest_namespace(guest):
    """FIXED (was privilege escalation): role_name resolves via Guest Manager.

    ``role_name`` used to be looked up on the Policy Manager ``/role``
    endpoint, where "[Guest]" is id 3. A guest account's ``role_id`` is a
    *Guest Manager* role id, where 3 means "[Employee]" and "[Guest]" is 2, so
    every guest created through the tool silently received employee-level
    network access while the caller was told it got "[Guest]".

    The resolver now reads the Guest Manager namespace off the appliance
    itself, so asking for "[Guest]" must yield role_id 2.
    """
    _, _, created = guest
    user = created.get("user") or {}
    assert user.get("role_name") == GUEST_ROLE, (
        "create_guest_user(role_name='[Guest]') produced role_name="
        f"{user.get('role_name')!r} / role_id={user.get('role_id')!r}"
    )
    assert user.get("role_id") == GUEST_ROLE_ID, (
        f"role_id={user.get('role_id')!r}; the Guest Manager id for "
        f"{GUEST_ROLE} is {GUEST_ROLE_ID} (3 would be [Employee])"
    )


def test_guest_manager_role_namespace_is_read_from_the_appliance(run_async):
    """The resolver's mechanism, asserted directly against the appliance.

    ClearPass publishes no guest-role list endpoint, but ``POST /guest`` with
    an impossible ``role_id`` is rejected at validation time with the whole
    namespace in ``validation_messages.role_id._options``.
    """
    import src.main  # noqa: F401
    from src.app_config import get_clearpass_client

    async def _roles():
        client = await get_clearpass_client()
        return await client.list_guest_manager_roles(refresh=True)

    roles = run_async(_roles())
    assert roles.get(GUEST_ROLE) == GUEST_ROLE_ID, roles
    assert roles.get("[Employee]") == 3, roles
    assert roles.get("[Contractor]") == 1, roles


# ==========================================================================
# id-or-name matrix -- the whole point of this run
# ==========================================================================


def test_get_guest_user_honours_the_username_branch(run_async, recorder, guest):
    """get_guest_user genuinely branches to guest/username/<name>. Works."""
    name, _, _ = guest
    result = run_async(recorder.run(
        "get_guest_user", domain=USERS, tier="read", user_id=name))
    assert classify(result, "get_guest_user") == PASS, result
    assert result["user"]["username"] == name


def test_update_guest_user_honours_the_username_branch(
        run_async, recorder, guest):
    """FIXED: user_id documented "ID or username" now honours both.

    The value used to be interpolated straight into PATCH guest/<value> with
    no numeric check, so ClearPass answered 422 "ID '<name>' is invalid". It
    now branches to PATCH guest/username/<name>, exactly as get_guest_user
    does.
    """
    name, uid, _ = guest
    assert_ours(name)
    result = run_async(recorder.run(
        "update_guest_user", domain=USERS, tier="update",
        user_id=name, enabled=False))
    assert classify(result, "update_guest_user") == PASS, result

    fetched = run_async(harness.invoke("get_guest_user", user_id=uid))
    assert fetched["user"]["enabled"] is False, \
        f"update by username reported success but did not land: {fetched}"


def test_delete_guest_user_honours_the_username_branch(
        run_async, recorder, guest):
    """FIXED: DELETE guest/username/<name> instead of DELETE guest/<name>."""
    name, uid, _ = guest
    assert_ours(name)
    result = run_async(recorder.run(
        "delete_guest_user", domain=USERS, tier="delete",
        user_id=name, confirm=True))
    assert classify(result, "delete_guest_user") == PASS, result

    gone = run_async(harness.invoke("get_guest_user", user_id=uid))
    assert gone.get("success") is not True, \
        f"delete by username reported success but the account survives: {gone}"


def test_delete_guest_user_confirm_guard(run_async, recorder, guest):
    """confirm defaults to False and short-circuits before any HTTP request."""
    name, uid, _ = guest
    result = run_async(recorder.run(
        "delete_guest_user", domain=USERS, tier="negative", user_id=uid))
    assert result.get("success") is False
    assert "confirmation" in str(result.get("error")).lower(), result
    still = run_async(harness.invoke("get_guest_user", user_id=uid))
    assert still.get("success") is True, "unconfirmed delete still deleted"


def test_config_id_params_do_not_honour_a_name(run_async, recorder):
    """guest_configuration *_id params are typed Union[int, str] but no
    operation implements a name branch; only weblogin has explicit *_by_name
    twins. Documented here so the matrix is complete."""
    by_name = run_async(recorder.run(
        "get_pass_template", domain=CONFIG, tier="negative",
        expect_absent=True, template_id="Guest Receipt for Apple Passbook"))
    assert by_name.get("success") is False
    assert "invalid" in str(by_name.get("error")).lower(), by_name

    by_name = run_async(recorder.run(
        "get_print_template", domain=CONFIG, tier="negative",
        expect_absent=True, template_id="GuestManager Receipt"))
    assert by_name.get("success") is False
    assert "not found" in str(by_name.get("error")).lower(), by_name


# ==========================================================================
# guest_actions
# ==========================================================================


def test_generate_guest_receipt(run_async, recorder, guest):
    """Real receipt generation against the built-in print template id 1."""
    _, uid, _ = guest
    result = run_async(recorder.run(
        "generate_guest_receipt", domain=ACTIONS, tier="read",
        guest_id=uid, template_id=1))
    assert classify(result, "generate_guest_receipt") == PASS, result
    assert "receipt_data" in result


def test_generate_guest_receipt_rejects_a_username(run_async, recorder, guest):
    """guest_id is documented "Numeric ID"; the name path 422s, honestly."""
    name, _, _ = guest
    result = run_async(recorder.run(
        "generate_guest_receipt", domain=ACTIONS, tier="negative",
        guest_id=name, template_id=1))
    assert result.get("success") is False
    assert "Traceback" not in str(result)


def test_generate_guest_digital_pass_inspects_the_response_body(
        run_async, recorder, guest):
    """FIXED: an HTTP 200 that carries no pass is no longer reported as one.

    Pass downloads are disabled on this appliance, so the API answers HTTP 200
    with {"message": "Pass downloads have been disabled."} for ANY guest id and
    ANY template id. The operation used to wrap every 200 as "Digital pass
    generated successfully". It now requires the documented ``digital_pass``
    payload, so BOTH the real guest and the bogus one come back as structured
    failures carrying the appliance's own explanation.
    """
    _, uid, _ = guest
    for label, gid, tid in (("real", uid, 1),
                            ("bogus", ABSENT_ID, ABSENT_ID)):
        result = run_async(recorder.run(
            "generate_guest_digital_pass", domain=ACTIONS, tier="negative",
            guest_id=gid, template_id=tid))
        assert result.get("success") is not True, (
            f"generate_guest_digital_pass reported success for the {label} "
            f"case while no pass was produced: {result}"
        )
        assert "disabled" in str(result.get("error")).lower(), result
        assert "Traceback" not in str(result)


def test_process_guest_sponsor_action_does_not_claim_an_unverified_approval(
        run_async, recorder, guest):
    """FIXED: an invalid sponsor token is no longer reported as an approval.

    The appliance answers HTTP 200 with a bare {"success": true} regardless of
    token validity and changes nothing; the operation used to report "Guest
    sponsorship approved successfully". It now requires the documented
    SponsorshipApprovalResponse payload (the updated account / a _confirm_*
    flag) before claiming anything. Verified non-mutating by diffing the
    account.
    """
    _, uid, _ = guest
    before = run_async(harness.invoke("get_guest_user", user_id=uid))
    result = run_async(recorder.run(
        "process_guest_sponsor_action", domain=ACTIONS, tier="negative",
        guest_id=uid, token="zzz-mcptest-invalid",
        register_token="zzz-mcptest-invalid"))
    after = run_async(harness.invoke("get_guest_user", user_id=uid))
    assert before.get("user") == after.get("user"), \
        "sponsor action with an invalid token mutated the account"
    assert result.get("success") is not True, (
        "process_guest_sponsor_action reported an approval for an invalid "
        f"token and changed nothing: {result}"
    )


@pytest.mark.parametrize("operation", ["send_guest_receipt_sms",
                                       "send_guest_receipt_email"])
def test_denylisted_receipt_senders_contract_only(operation, run_async, recorder):
    """Never dispatched. Contract-tested offline: registered, describable."""
    import src.main  # noqa: F401
    from src.registry import registry

    spec = registry.get(operation)
    assert spec is not None, f"{operation} is not registered"
    assert spec.domain == ACTIONS, spec.domain

    from src.tools.gateway import describe_operations

    described = run_async(describe_operations(harness.StubContext(),
                                              names=[operation]))
    assert described.get("success") is not False, described
    blob = json.dumps(described, default=str)
    assert operation in blob, described
    assert "guest_id" in blob, "schema does not expose guest_id"
    assert "confirm" in blob, "schema does not expose the confirm rail"
    assert "FieldInfo" not in blob, "FieldInfo leaked into the schema"

    with pytest.raises(DenylistedOperation) as excinfo:
        run_async(harness.invoke(operation, guest_id=1, confirm=True))
    assert DENYLIST[operation] in str(excinfo.value)
    recorder.record(operation, ACTIONS, "denylist", harness.EXPECTED_SKIP, {},
                    f"DENYLISTED: {DENYLIST[operation]}", 0.0)


# ==========================================================================
# guest_configuration -- reads
# ==========================================================================


@pytest.mark.parametrize("operation,payload_key", [
    ("list_pass_templates", "templates"),
    ("list_print_templates", "templates"),
    ("list_weblogin_pages", "pages"),
    ("get_guest_manager_settings", "settings"),
    ("get_guest_authentication_settings", "settings"),
])
def test_config_reads_with_all_optionals_omitted(
        operation, payload_key, run_async, recorder):
    result = run_async(recorder.run(operation, domain=CONFIG, tier="read"))
    assert classify(result, operation) == PASS, result
    assert payload_key in result, sorted(result)
    assert "FieldInfo" not in str(result), "FieldInfo leaked into the response"
    assert "annotation=" not in str(result), "FieldInfo repr leaked"


def test_get_pass_template(run_async, recorder):
    listed = run_async(harness.invoke("list_pass_templates"))
    ids = [t.get("id") for t in listed.get("templates", []) if t.get("id")]
    assert ids, "no pass templates on this appliance to read"
    result = run_async(recorder.run(
        "get_pass_template", domain=CONFIG, tier="read", template_id=ids[0]))
    assert classify(result, "get_pass_template") == PASS, result


def test_get_print_template(run_async, recorder):
    listed = run_async(harness.invoke("list_print_templates"))
    ids = [t.get("id") for t in listed.get("templates", []) if t.get("id")]
    assert ids, "no print templates on this appliance to read"
    result = run_async(recorder.run(
        "get_print_template", domain=CONFIG, tier="read", template_id=ids[0]))
    assert classify(result, "get_print_template") == PASS, result


def test_list_print_templates_omits_ids_for_system_templates(run_async):
    """Environment observation, recorded so triage does not chase it.

    9 of the 13 print templates come back with no ``id`` field at all, so they
    are unreachable by get_print_template. That is the appliance's payload, not
    a mapping defect: the operation returns _embedded.items verbatim.
    """
    listed = run_async(harness.invoke("list_print_templates"))
    templates = listed.get("templates", [])
    without = [t.get("name") for t in templates if not t.get("id")]
    assert without, "all print templates now carry an id -- update this note"


@pytest.mark.parametrize("operation,params", [
    ("get_weblogin_page", {"page_id": ABSENT_ID}),
    ("get_weblogin_page_by_name", {"page_name": ABSENT_NAME}),
])
def test_weblogin_reads_are_structured_404s(operation, params,
                                            run_async, recorder):
    """0 web login pages exist on this appliance, so both read paths can only
    be exercised negatively. A structured 404 is the correct outcome."""
    listed = run_async(harness.invoke("list_weblogin_pages"))
    assert listed.get("total_count") == 0, \
        "web login pages now exist; revisit this test's safety assumption"
    result = run_async(recorder.run(
        operation, domain=CONFIG, tier="negative", expect_absent=True, **params))
    assert classify(result, operation, expect_absent=True) == PASS, result
    assert "Traceback" not in str(result)


# ==========================================================================
# guest_configuration -- writes against verified-absent targets
# ==========================================================================


@pytest.mark.parametrize("operation,params", [
    ("update_weblogin_page", {"page_id": ABSENT_ID,
                              "page_data": '{"title":"zzz-mcptest"}'}),
    ("replace_weblogin_page", {"page_id": ABSENT_ID,
                               "page_data": '{"name":"zzz-mcptest"}'}),
    ("update_weblogin_page_by_name", {"page_name": ABSENT_NAME,
                                      "page_data": '{"title":"zzz-mcptest"}'}),
    ("replace_weblogin_page_by_name", {"page_name": ABSENT_NAME,
                                       "page_data": '{"name":"zzz-mcptest"}'}),
    ("delete_weblogin_page", {"page_id": ABSENT_ID, "confirm": True}),
    ("delete_weblogin_page_by_name", {"page_name": ABSENT_NAME,
                                      "confirm": True}),
])
def test_weblogin_writes_against_absent_targets(operation, params,
                                                run_async, recorder):
    """The appliance has ZERO web login pages, re-verified immediately before
    each call, so these write verbs cannot touch a pre-existing object. They
    exercise the real HTTP path, the JSON-string parameter parsing and the
    error wrapper, and must come back as structured 404s."""
    listed = run_async(harness.invoke("list_weblogin_pages"))
    assert listed.get("total_count") == 0, \
        "web login pages now exist; this test is no longer safe to run"
    result = run_async(recorder.run(
        operation, domain=CONFIG, tier="negative", expect_absent=True, **params))
    assert classify(result, operation, expect_absent=True) == PASS, result
    assert "Traceback" not in str(result)
    after = run_async(harness.invoke("list_weblogin_pages"))
    assert after.get("total_count") == 0, "a web login page was created"


@pytest.mark.parametrize("operation", ["update_pass_template",
                                       "replace_pass_template"])
def test_pass_template_writes_against_an_absent_id(operation, run_async,
                                                   recorder):
    before = run_async(harness.invoke("list_pass_templates"))
    ids = {str(t.get("id")) for t in before.get("templates", [])}
    assert str(ABSENT_ID) not in ids, "the negative-test id actually exists"

    result = run_async(recorder.run(
        operation, domain=CONFIG, tier="negative", expect_absent=True,
        template_id=ABSENT_ID, template_data='{"name":"zzz-mcptest"}'))
    assert result.get("success") is False, result
    assert "Traceback" not in str(result)

    after = run_async(harness.invoke("list_pass_templates"))
    assert {str(t.get("id")) for t in after.get("templates", [])} == ids, \
        "pass template inventory changed during a negative write"


@pytest.mark.parametrize("operation", ["update_print_template",
                                       "replace_print_template"])
def test_print_template_writes_inspect_the_response_body(operation, run_async,
                                                         recorder):
    """FIXED: a write to a non-existent print template now fails structurally.

    The appliance answers HTTP 200 with an error *body*:
    ``{"error": 1, "field": "id", "message": "There is no print template with
    ID %1"}``. The operation used to inspect only the HTTP status and returned
    ``success: True`` / "Print template 999999 updated successfully", telling
    the caller a write landed that never happened.
    """
    before = run_async(harness.invoke("list_print_templates"))
    names = sorted(str(t.get("name")) for t in before.get("templates", []))
    assert str(ABSENT_ID) not in {str(t.get("id")) for t in
                                  before.get("templates", [])}

    result = run_async(recorder.run(
        operation, domain=CONFIG, tier="negative",
        template_id=ABSENT_ID, template_data='{"name":"zzz-mcptest"}'))

    after = run_async(harness.invoke("list_print_templates"))
    assert sorted(str(t.get("name")) for t in after.get("templates", [])) == names, \
        "print template inventory changed during a negative write"

    assert result.get("success") is False, (
        f"{operation} reported success while the appliance body carried an "
        f"error: {result}"
    )
    assert "no print template" in str(result.get("error")).lower(), result
    assert "Traceback" not in str(result)


# ==========================================================================
# guest_configuration -- client-side guards (verified, no HTTP issued)
# ==========================================================================


@pytest.mark.parametrize("operation,params", [
    ("delete_pass_template", {"template_id": 1}),
    ("delete_print_template", {"template_id": 1}),
])
def test_template_delete_confirm_guard_blocks_dispatch(operation, params,
                                                       run_async, recorder):
    """The destructive path is BLOCKED for this scope (real templates exist and
    are not sweepable). What IS verified is that the confirm rail returns
    before any request reaches the appliance -- proven by the object surviving.
    """
    result = run_async(harness.invoke(operation, **params))
    assert result.get("success") is False
    assert "confirmation" in str(result.get("error")).lower(), result

    read_op = ("get_pass_template" if "pass" in operation
               else "get_print_template")
    survivor = run_async(harness.invoke(read_op, template_id=1))
    assert survivor.get("success") is True, \
        f"the unconfirmed delete removed template 1: {survivor}"

    _record_blocked(recorder, operation, CONFIG,
                    "Destructive path not exercised: pass/print templates on "
                    "this appliance are pre-existing and not in the sweepable "
                    "fixture set. confirm=False guard verified, no dispatch.",
                    params)


@pytest.mark.parametrize("operation,bad_payload,expect", [
    ("create_guest_authentication_settings", '{"zzz":1}',
     "Missing required field: g_radius_internal_auth_type"),
    ("update_guest_authentication_settings", 'not json', "Invalid JSON"),
    ("create_guest_manager_settings", '{"zzz":1}', "Missing required fields"),
    ("update_guest_manager_settings", 'not json', "Invalid JSON"),
])
def test_global_settings_writes_are_blocked_but_guards_verified(
        operation, bad_payload, expect, run_async, recorder):
    """These four mutate appliance-wide guest configuration singletons; there is
    no fixture namespace and no rollback, so the mutation path is BLOCKED.

    The pre-dispatch validation gate IS exercised: both operations parse the
    JSON string and check required fields before building a client, so an
    invalid payload proves the parameter plumbing without touching config.
    Settings are read before and after to prove nothing changed.
    """
    read_op = ("get_guest_authentication_settings" if "authentication" in operation
               else "get_guest_manager_settings")
    before = run_async(harness.invoke(read_op))

    result = run_async(harness.invoke(operation, settings_data=bad_payload))
    assert result.get("success") is False, result
    assert expect in str(result.get("error")), result
    assert "Traceback" not in str(result)
    assert "FieldInfo" not in str(result)

    after = run_async(harness.invoke(read_op))
    assert before.get("settings") == after.get("settings"), \
        f"{operation} mutated global settings during a guard test"

    _record_blocked(recorder, operation, CONFIG,
                    "Mutation path not exercised: appliance-wide guest "
                    "settings singleton with no fixture namespace and no "
                    "rollback. JSON/required-field guard verified, no dispatch.",
                    {"settings_data": bad_payload})


@pytest.mark.parametrize("operation,params", [
    ("create_pass_template", {"name": "zzz-mcptest-pass",
                              "template_data": "{}"}),
    ("create_print_template", {"name": "zzz-mcptest-print",
                               "template_data": "{}"}),
    ("create_weblogin_page", {"name": "zzz-mcptest-weblogin",
                              "page_data": "{}"}),
])
def test_config_creates_are_blocked(operation, params, recorder):
    """Not dispatched. delete_pass_template / delete_print_template /
    delete_weblogin_page are not in harness._SWEEPABLE, so anything created
    here would survive the run and trip the inventory guard with an object no
    rail can remove. Registration + schema are contract-checked instead."""
    import src.main  # noqa: F401
    from src.registry import registry

    spec = registry.get(operation)
    assert spec is not None, f"{operation} is not registered"
    assert spec.domain == CONFIG, spec.domain

    _record_blocked(recorder, operation, CONFIG,
                    "Creation not dispatched: guest_configuration has no "
                    "sweepable delete, so the object could never be cleaned "
                    "up.", params)
