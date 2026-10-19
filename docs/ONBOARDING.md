# Onboarding Guide — ClearPass Sidekick MCP Server

> **Who this is for:** an engineer who is comfortable programming, but who has not
> written much Python. Every Python-specific idea is explained in plain English the
> first time it shows up. No prior knowledge of MCP or Aruba ClearPass is assumed.
>
> **How long:** 20–30 minutes to read end to end. Do that once before you touch code.
>
> **Generated from:** the project knowledge graph in `.ua/` (585 nodes, 1370 edges,
> 9 layers, 14 tour steps), analysed at commit `5e3c869`. Graph, operation counts and
> module inventories were all refreshed on 2026-07-31 and agree with each other.

---

## 1. Project Overview

### What it is

This repository is a **bridge between an AI assistant and a network-access appliance**.

- On one side: an LLM client that speaks the **Model Context Protocol (MCP)** — Claude
  Desktop, Claude Code, or anything else that implements the standard.
- On the other side: an **Aruba ClearPass Policy Manager** appliance — the box that
  decides who and what is allowed onto a corporate network.

The bridge lets a human type *"create a guest account for a contractor visiting on
Friday"* and have that actually happen against ClearPass's REST API.

> **MCP in one paragraph.** The Model Context Protocol is a small standard for letting
> an AI model call code that lives outside the model. A *server* publishes named
> *tools*. The AI *client* reads the list of tool names plus each tool's parameter
> descriptions, then decides which one to call and with what arguments. Everything in
> this codebase exists to decide **which tools appear on that list**.

### Facts

| | |
|---|---|
| Name | `clearpass-sidekick-mcp` |
| Primary language | Python (plus Dockerfile, batch, markdown) |
| Frameworks | FastMCP, MCP, Pydantic, Starlette, Uvicorn, pytest, Docker |
| Analysed files | 121 |
| ClearPass operations covered | **761** — full parity with the `pyclearpass` 1.0.8 SDK (801/801 endpoints) |
| MCP tools an AI client sees by default | **7** |

That last pair of numbers is the whole point of the project. Section 3 explains it.

### What to read, and what to ignore

Read, in this order:

1. `README.md` — what the server does, how to install and run it.
2. `CLAUDE.md` — the deep architecture guide. **This is the current, trustworthy doc.**
   `AGENTS.md` at the repo root is its byte-identical twin, kept in sync for non-Claude
   harnesses.
3. This file.

`src/AGENTS.md`, `src/tools/AGENTS.md`, `src/client_methods/AGENTS.md`,
`src/models/AGENTS.md`, `tests/AGENTS.md`, `tests/live/README.md` and
`mcp_registry_readme.md` are current directory maps and were re-synced with the
761/757/764 counts.

**Do not trust these for HOW the server works today:**

```
clearpass-sidekick-mcp-prd.md        (useful for WHY, describes the pre-refactor design)
docs/live_testing_plan_phase*.md     (historical run records)
docs/*_plan.md                        (design notes from stages already shipped)
```

They are deliberately preserved as historical records, not maintained.

### Two things in the repo that will look alarming

- **`.venv/` is committed** — 2,369 tracked third-party files. Somebody's Python virtual
  environment checked into git by accident. Worse, it is *broken*: its `bin/python` is
  3.11 but its `lib/` only holds `python3.10` site-packages, so `import fastmcp` fails
  and it has no working `pip`. **Never run the project through `.venv/`.** Create your
  own environment (this repo's is `.venv-refactor/`). See Section 10.
- **`.ua/`** — the Understand-Anything knowledge graph this guide is generated from. Data,
  not source. Leave it to the `/understand` tooling.

Neither is worth "fixing" as your first act on the repo.

---

## 2. Python vocabulary you need before reading the code

You will meet all of these within the first ten minutes. Skim now, refer back later.

**Module / package.** A `.py` file is a *module*. A directory containing an
`__init__.py` file is a *package*, and `__init__.py` is the code that runs when you
import the directory itself. It is often used as a "front door" that re-exports things
from sibling files.

**Import-as-side-effect.** Importing a module in Python *runs every line at that
module's top level, once*. There is no separate "load" and "execute" phase. This means
`import src.tools.certificates` can silently do work — like filing twenty-nine functions
into a shared catalog — with nobody calling a setup function. This codebase leans on that
behaviour heavily. The upside is zero wiring code. The downside is that deleting an
import that "looks unused" can silently delete a whole feature area, which is exactly
why a test exists that counts things (Section 7, step 5).

**Decorator.** A line starting with `@` written directly above a `def`. It is just a
function that receives the function defined below it and can do anything with it before
handing it back. It does **not** modify the decorated function's body.

```python
@operation(domain="certificates")
async def list_certificates(...):
    ...
```

Here `@operation(...)` files this function into the project's registry. Two decorators
matter in this repo and they have opposite intent:

- `@operation(domain=...)` — **catalog it, but hide it** from the AI client.
- `@mcp.tool()` — **publish it** as a real, visible MCP tool.

**Introspection.** Python can read a function's own parameter list and documentation
text at runtime. That is how the registry auto-generates a parameter schema for 757
operations without anyone hand-writing 757 schemas.

**`async def` / `await`.** A function declared `async def` may *pause* at any `await`
while it waits for something slow — here, a network reply from ClearPass. While one
request is paused, the server can serve other requests instead of sitting idle. For a
program that spends nearly all its time waiting on HTTP, this is the cheapest possible
concurrency: no threads, no locks. A caller of an `async def` function **must** `await`
it, otherwise it gets back a "coroutine" object and nothing runs. (That exact mistake
was shipped here twice and is now guarded by a test — see Section 10.)

**`async with`.** The async version of a resource block: acquires something, runs the
body, and guarantees cleanup afterwards. Used for HTTP sessions so connections always
get closed.

**Singleton.** One instance of a thing, shared everywhere. In Python you get it almost
for free: because a module's top-level code runs only once no matter how many files
import it, an object created at the top of a module is automatically shared by every
importer. No framework, no class trickery.

**Mixin.** Python lets a class inherit from several parents at once. When those parents
are small, self-contained bundles of methods that were never meant to be used alone,
they're called *mixins*.

```python
class ClearPassClient(CertificatesMixin, GuestUsersMixin, ...):
```

The new class gets every method of every parent. If two parents defined the same method
name, the one listed **first** wins — a rule called the *method resolution order*, and
the reason mixin method names here are kept distinct.

**Pydantic.** A library where you describe data by writing a class whose attributes
carry type annotations:

```python
class GuestUser(BaseModel):
    username: str
    enabled: bool = True
```

Pydantic then *enforces* that description at runtime — wrong types are rejected with a
clear message, missing required fields are caught, defaults are filled in. You get
validation and documentation from the same few lines, and the registry can read those
same annotations to generate the parameter schema the AI sees.

**Exception hierarchy.** Custom error classes that inherit from each other, so a caller
can catch the broad case (`CredentialsError`) or the narrow one
(`CredentialsNotFoundError`).

**pytest / `conftest.py`.** `pytest` is Python's standard test runner. `conftest.py` is
a filename pytest looks for automatically and loads before any test file, with no
import needed — which is how a four-line `conftest.py` can fix the import path for the
entire suite.

---

## 3. The core idea: progressive disclosure

**Read this section twice. It is the reason the codebase is shaped the way it is, and
it is the thing the stale docs get wrong.**

### The problem

There are **761 ClearPass operations**. If each were published as its own MCP tool, the
AI client would have to read 761 tool descriptions — many thousands of words — before
it could answer even *"is the server up?"*. That floods the model's limited reading
window, makes every response slower, and makes tool selection *less* accurate, not
more. It is the single biggest failure mode of naively-built MCP servers.

### The fix

Publish almost nothing. Keep everything reachable.

```
761 ClearPass operations
 ├── 757  catalogued in an in-process registry   (hidden from the client)
 └──   4  published directly as MCP tools        (server_utility.py)

Visible MCP tools in DEFAULT mode = 7
 ├── 3  gateway meta-tools   (list / describe / invoke)
 └── 4  server_utility tools

Visible MCP tools with CLEARPASS_MCP_LEGACY_TOOLS=true = 764
 ├── 757  registry operations re-exposed individually
 ├──   4  server_utility tools
 └──   3  gateway meta-tools (they stay visible too)
```

Memorise those three numbers: **761 total, 7 visible by default, 764 in legacy mode.**
Any document in this repo that says otherwise is out of date.

### The three meta-tools

Defined in `src/tools/gateway.py`:

| Tool | What it does | Cost to the model |
|---|---|---|
| `list_operations` | Browse or keyword-search the catalog. Returns a compact index: names + one-line summaries. | Cheap |
| `describe_operations` | Return full documentation and parameter schemas — but only for the handful of operations the AI actually asked about. | Pay only for what you need |
| `invoke_operation` | Look one up by name, validate the supplied parameters, run it. | The actual work |

The flow is **browse cheaply → fetch detail on demand → execute**. Three tool
descriptions in the model's context window instead of 761.

### Why four tools stayed direct

`src/tools/server_utility.py` keeps four operations as ordinary, always-visible MCP
tools: server info, connection test, credential management, and a searchable listing of
what's available. They stayed direct because they're what you reach for *before you
know anything else*. You should not have to browse a catalog to ask "can this server
even talk to ClearPass?"

### The escape hatch

`CLEARPASS_MCP_LEGACY_TOOLS=true` in `.env` calls `register_legacy_tools(mcp)`, which
re-exposes all 757 catalogued operations as individual tools — how the server behaved
before the refactor. It exists for clients that cannot drive the gateway pattern. Use
it only if you must.

---

## 4. Architecture — the nine layers

The knowledge graph assigns every one of the 121 analysed files to exactly one of nine
layers. The first five are the runtime stack; the last four are how it is tested, run and
explained. **Dependencies flow downward** through the runtime stack — nothing in a lower
layer imports from a higher one.

```
┌──────────────────────────────────────────────────────────┐
│  1. Composition Root & Shared Primitives   (5 files)     │  src/__init__.py, main.py,
│     starts the process; defines the vocabulary           │  app_config, exceptions, utils
├──────────────────────────────────────────────────────────┤
│  2. Progressive-Disclosure Core            (2 files)     │  registry.py,
│     the front door — decides what the client can see     │  tools/gateway.py
├──────────────────────────────────────────────────────────┤
│  3. Operation Tool Layer                  (21 files)     │  src/tools/*.py
│     19 domain modules (757 ops) + server_utility (4)     │
│     validate args → call down → format the answer        │
├──────────────────────────────────────────────────────────┤
│  4. ClearPass HTTP Client Layer           (22 files)     │  clearpass_client.py,
│     1 class + 19 mixins + credentials + audit_logger     │  src/client_methods/*.py
│     the ONLY place HTTP happens                          │
├──────────────────────────────────────────────────────────┤
│  5. Data Models                           (11 files)     │  src/models/*.py
│     Pydantic; imports nothing else in the project        │
└──────────────────────────────────────────────────────────┘
        ↑ everything above is exercised by ↓

  6. Hermetic Offline Test Suite  (21)   tests/*.py — no network, no credentials
  7. Live Appliance Harness       (21)   tests/live/ — opt-in, needs a real ClearPass
  8. Infrastructure & Runtime Config (5) Dockerfile, requirements, .env.example, run_mcp.bat
  9. Documentation                (13)   README, CLAUDE/AGENTS, the per-package guides
```

> The numbering is this guide's, taken from the graph's layer order. Section 8 uses the
> same nine names, so a layer number means the same thing in both places.

### Layer 1 — Composition Root & Shared Primitives

The process that starts up and the vocabulary everything else speaks. `main.py` imports
every tool module (that import *is* the registration) and starts the server loop;
`app_config.py` loads settings and hands out the shared FastMCP object and the singleton
client; `exceptions.py` and `utils.py` define the single custom error type and the
response formatters. **Read `app_config.py`, `exceptions.py` and `utils.py` first** —
they have the highest fan-in in the codebase.

### Layer 2 — Progressive-Disclosure Core

Just two files, and they are the whole point of the project. `registry.py` owns the
`@operation(...)` decorator and the in-memory catalogue of 757 operations;
`tools/gateway.py` exposes that catalogue through exactly 3 MCP meta-tools. Section 3
explains why.

### Layer 3 — Operation Tool Layer

Nineteen domain modules, one per ClearPass subject area, holding all 757 registry
operations — plus `server_utility.py`, the one module that still registers direct
`@mcp.tool()` tools, and `__init__.py`. Each operation validates its arguments, calls the
HTTP client, and shapes a result. **None of the 757 is registered directly as an MCP
tool.** Splitting by domain keeps each file browsable and lets the registry index
operations by subject.

### Layer 4 — ClearPass HTTP Client Layer

The only part of the system that talks HTTP to a real appliance.
`clearpass_client.py` builds the httpx session, handles OAuth tokens and URL
construction, then composes nineteen `*Mixin` classes that each add the concrete REST
calls for one domain. `credentials.py` and `audit_logger.py` sit here too, because they
exist to serve that one client. Isolating all network I/O here means the tool layer never
constructs a URL, and the whole system can be tested by swapping this one object.

### Layer 5 — Data Models

Eleven Pydantic modules describing the shape of things moving in and out of ClearPass.
They give the LLM precise argument schemas and turn malformed input into a clear
validation error *before* any network call happens. This layer imports nothing else in
the project, which is why it sits at the bottom of the dependency graph. Note there is
*not* a model file per domain — only the domains with rich, reusable request bodies have
one.

### Layer 6 — Hermetic Offline Test Suite

`tests/*.py`: the default `pytest` run. No network, no credentials, no appliance —
222 tests, all green. This is the fastest way to see how each layer is meant to be
called, and it includes several AST-level guards that make old bugs unmergeable.

### Layer 7 — Live Appliance Harness

`tests/live/`: an **opt-in** suite gated behind a `--live` flag, with a fixture-name
prefix, a hard denylist and an inventory diff so it can only ever touch objects it
created itself. Skipped entirely on a normal run.

### Layer 8 — Infrastructure & Runtime Config

Dependency pins, the `.env` template, the Dockerfile and `.dockerignore`, and the Windows
launcher.

### Layer 9 — Documentation

`README.md`, `CLAUDE.md`/`AGENTS.md`, `mcp_registry_readme.md`, the PRD, and the
per-package `AGENTS.md` directory maps under `src/`, `src/tools/`,
`src/client_methods/`, `src/models/` and `tests/`.

---

## 5. Key concepts and design decisions

**The tool surface is a budget, not a catalog.** Every visible tool costs context in the
model's window on every single turn. The architecture treats "number of visible tools"
as a scarce resource to be defended — hence a *test that asserts a count* (Section 7).

**Registration is a side effect of importing.** No `register_everything()` function
exists. `src/main.py` has a single `from .tools import (...)` naming all 19 domain
modules plus `server_utility` and `gateway`. Importing the `src.tools` package also runs
`src/tools/__init__.py`, which independently imports ten of those modules — so a new
domain listed in *either* place gets registered. Those import statements *are* the
wiring.

**One shared client, created once.** `app_config.py` builds exactly three shared things
at startup: the one FastMCP server object that tools attach themselves to, the ClearPass
login details, and one already-authenticated API client. Creating a fresh, freshly
logged-in client for each of 761 operations would be slow and would hammer ClearPass
with login requests.

**Matching filenames per domain.** For any domain `X`:

```
src/tools/X.py            ← the operations (thin, @operation-decorated)
src/client_methods/X.py   ← the HTTPS calls (a Mixin class)
src/models/X.py           ← the Pydantic shapes — only where they earn their keep
```

The first two always pair up: all 19 domains have both, with identical filenames. Models
are the exception — only 11 model modules exist, for the domains with rich, reusable
request bodies. Learn one pair and you have learned all nineteen.

**Destructive operations require explicit confirmation.** Disconnects, deletes, and
message-sends take a `confirm` flag. The model has to opt in deliberately; it cannot
delete a guest account by accident.

**Everything is audited.** `audit_logger.py` writes a permanent, tamper-checked record
of every operation — who did what, whether it worked, how long it took — with passwords
and tokens stripped out first. This matters because this server can change who gets onto
a corporate network.

**Errors are part of the interface.** `utils.py` turns API failures into structured
results carrying an actionable suggestion, rather than raising a bare exception. The
reasoning: a human sees an error and reasons about it; an AI client does much better
with a machine-shaped answer that *names the problem and states the next action*.

**`update` vs `replace`.** Across the guest-configuration modules, `update` patches only
the fields you supply while `replace` overwrites the whole record. Know which one you
are calling.

**Why the big modules are big.** `enforcement_profiles_dur` (142 operations) and
`policy_elements` (112 operations, 192 methods in the client layer) dwarf everything
else, but neither is complicated. Almost every operation comes in a matched pair — one
addressed by numeric id, one by name — hitting the same underlying REST endpoint; DUR
multiplies that again by 14 resource families and a `product_name` scope. Volume, not
tangle.

---

## 6. Getting it running

```bash
# 1. Create a virtual environment (an isolated per-project Python install).
#    Do NOT use the committed .venv/ — it is broken. Use .venv-refactor/.
python3 -m venv .venv-refactor
source .venv-refactor/bin/activate     # Windows: .venv-refactor\Scripts\activate

# 2. Install pinned dependencies
pip install -r requirements.txt

# 3. Configure credentials
cp .env.example .env
$EDITOR .env                       # set CLEARPASS_SERVER, CLIENT_ID, CLIENT_SECRET

# 4. Run
python src/main.py

# 5. Tests (offline, hermetic — no appliance, no credentials)
python -m pytest tests/ --ignore=tests/live -q      # from the project root
```

Notes:

- **Always invoke Python through `.venv-refactor/bin/python`**, never a bare `python3`
  and never `.venv/bin/python`. See Section 10.
- `requirements.txt` carries an explicit warning: `pydantic`, `pydantic-core` and
  `pydantic-settings` must stay on their pinned, mutually-compatible versions. Don't
  upgrade one alone.
- `.env.example` also contains eight unrelated LLM-provider API keys left over from other
  tooling. Ignore them; only the `CLEARPASS_*` block matters.
- `CLEARPASS_SERVER` **includes the `/api` suffix** (`https://host:443/api`).
  `app_config.py` strips it back off before handing the host to the client, which then
  re-adds `/api` itself. Copy the `.env.example` form exactly.
- **`run_mcp.bat` will not work unedited** — it `cd`s into a hardcoded developer path
  from another machine. Same for the `run mcp server via mcpo proxy for ollama.txt`
  snippet (`uvx mcpo --port 8000`), which also has a hardcoded Windows path. Supported
  entry points are Docker and `python src/main.py`.
- Docker: the image is built from `python:3.10-slim`, works out of `/app`, and launches
  `python src/main.py`. It binds no port — `mcp.run()` speaks stdio, so the container is
  run with `-i` and driven over stdin/stdout. Credentials are declared as *empty*
  environment variables in the image and supplied at run time — secrets must never be
  baked into an image, since anyone who can pull it can read them.

---

## 7. The guided tour — recommended learning path

These 14 steps come from the knowledge graph's tour and are **clickable in the
Understand-Anything dashboard**, which will highlight the corresponding nodes and edges
for each step. Follow them in order with the files open.

### Step 1 — What this project is
`README.md`, `clearpass-sidekick-mcp-prd.md`

`README.md` for what the server does and how to run it. The PRD tells you *why* the
project exists — read it for motivation only; it describes the pre-refactor design.

### Step 2 — The central problem
`AGENTS.md`, `CLAUDE.md`

The two are byte-identical twins (one for Claude Code, one for every other harness) and
together are the trustworthy architecture doc. They state the problem this codebase
solves: 761 operations, 7 visible tools.

### Step 3 — Server entry point
`src/main.py`, `src/app_config.py`

`main.py` reads settings, imports every tool module, then starts the server loop. The
imports **are** the setup. A small block at the top also fixes the module search path so
the file can be run directly as a script. `app_config.py` has the highest incoming-
dependency count in the project: it creates the shared FastMCP server object, reads
ClearPass credentials from the environment, and hands out one reusable, already-
authenticated client.

*New Python ideas: import-as-side-effect, and the module-level singleton (Section 2).*

### Step 4 — The operation registry
`src/registry.py`

The heart of the refactor. `@operation(domain=...)` records a function's name, domain,
summary, full documentation, parameter schema, and a handle to the function itself into
an in-memory catalog — and pointedly does **not** publish it as a visible tool. The
catalog is searchable, and `register_legacy_tools()` flips it back to publishing
everything.

*New Python ideas: decorators, and introspection (auto-generated schemas).*

### Step 5 — The three gateway meta-tools
`src/tools/gateway.py`, `src/tools/server_utility.py`, `tests/test_tool_count.py`

`list_operations`, `describe_operations`, `invoke_operation` (Section 3), plus the four
tools that stayed direct — server info, connection test, credential management, tool
listing. 3 + 4 = the 7 tools a client sees by default.

**`test_tool_count.py` is the executable specification of all of it.** It imports the
whole server, then asserts the registry holds exactly 757 domain operations while no more
than 10 tools are registered directly on the MCP server. If someone accidentally
publishes an operation as its own tool, or drops an import and loses a whole domain, this
fails immediately. A test that asserts a *count* is unusual but deliberate: the
architecture's whole value is that the visible number stays small, so the number is worth
guarding. Its module docstring also reconciles every count change since the refactor —
read it if a number ever surprises you.

*New Python idea: `@mcp.tool()` — same mechanism as `@operation`, opposite intent.*

### Step 6 — Declaring a domain operation
`src/tools/guest_users.py`, `src/tools/__init__.py`, `src/tools/AGENTS.md`

The smallest complete domain: five operations covering the guest-account lifecycle —
list, get, create, update, delete. Each carries `@operation(domain="guest_users")`.
They're thin on purpose: validate, delegate, format. The other eighteen domains have
exactly this shape, just more of it.

*New Python idea: `async def` / `await`.*

### Step 7 — The HTTP client, and two real bugs
`src/clearpass_client.py`, `tests/test_make_request_body_and_url.py`

`ClearPassClient` handles OAuth2 login, token refresh, URL construction and every HTTPS
request. Read `_endpoint_url` and `_make_request` together with the test that pins them:
both carry the measurements behind two appliance-level defects that cost real debugging
time. Section 10 summarises them.

### Step 8 — Client method mixins
`src/client_methods/{guest_users,session_control,network_devices}.py`, `src/client_methods/AGENTS.md`

Directly beneath the tool functions: build query filters, send the CRUD requests, shape
the response. `ClearPassClient` defines almost no domain methods itself — it inherits
them from nineteen small mixin classes. One object with a huge surface, built from
nineteen individually readable files. Filenames match exactly: `src/tools/X.py` always
pairs with `src/client_methods/X.py`.

*New Python idea: mixins and method resolution order.*

### Step 9 — Data models and validation
`src/models/__init__.py`, `src/models/guest_common.py`, `src/models/certificates.py`, `src/models/AGENTS.md`

Pydantic classes declaring what goes in and what comes back. `__init__.py` gathers every
model so the rest of the server imports from one place. `guest_common.py` is worth
reading closely for a non-obvious reason: several ClearPass guest endpoints answer
**HTTP 200 with an error payload in the body**, so "did it work?" cannot be decided from
the status code alone.

*New Python idea: Pydantic models.*

### Step 10 — Shared primitives
`src/exceptions.py`, `src/utils.py`, `src/credentials.py`, `src/audit_logger.py`

The single custom `ClearPassAPIError` carrying message, HTTP status and raw body; the
response formatters that turn failures into actionable suggestions and build structured
"I need clarification" replies; credential loading/validation/masking with its own
exception hierarchy; and the tamper-checked audit log.

### Step 11 — The hermetic test suite
`tests/conftest.py`, `tests/test_registry.py`, `tests/test_gateway_tools.py`, `tests/AGENTS.md`

`conftest.py` puts `src/` on the import path and monkeypatches placeholder credentials,
which is how the whole offline suite runs with no appliance and no secrets.
`test_registry.py` checks `@operation` records the right domain, summary and schema, and
rejects duplicate names. `test_gateway_tools.py` checks the browse/describe/invoke cycle,
including that an unknown operation name produces a helpful error rather than a crash.

### Step 12 — Regression guards against old bugs
`tests/test_no_async_with_client.py`, `tests/test_retired_workarounds.py`, `tests/test_no_unbound_in_except.py`

Three tests that do not test behaviour at all — they parse the source tree and fail if a
known bug *shape* reappears. `test_no_async_with_client.py` forbids
`async with get_clearpass_client(...)` anywhere under `src/` (that bug shipped twice).
`test_no_unbound_in_except.py` forbids an `except` handler referencing a local bound only
after an `await` in the `try` body — a plain 404 was enough to turn that into an
`UnboundLocalError`. `test_retired_workarounds.py` pins three defects fixed on
2026-07-31, including a dead certificate path and a `/api/v1`-era workaround.

This is the most transferable idea in the repo: when a bug class recurs, write a guard
against the *shape*, not another unit test for the instance.

### Step 13 — Live appliance harness
`tests/live/README.md`, `tests/live/conftest.py`, `tests/live/harness.py`, `tests/live/denylist.py`

The opt-in `--live` suite. Every object it creates is named `zzz-mcptest-<runid>-<n>` and
`assert_ours()` runs before every update and delete; a 32-entry `denylist.py` refuses
operations that could revoke our own API access, lock out the admins, or message real
people; a session-level inventory diff fails the run if anything outside the fixture
prefix changed. Read the README before you ever pass `--live`.

### Step 14 — Packaging and deployment
`Dockerfile`, `requirements.txt`, `.env.example`, `.dockerignore`

See Section 6. Note the Dockerfile's layer ordering: dependencies are installed *before*
application code is copied in, so editing a source file reuses the cached dependency
layer instead of reinstalling everything.

---

## 8. File map, by layer

### Layer 1 — Composition root & shared primitives (`src/`)

| File | Role |
|---|---|
| `src/main.py` | Entry point. Loads settings, imports every tool module (registration happens here as a side effect), defines a read-only config-status resource and a help prompt, starts the server. |
| `src/app_config.py` | The shared FastMCP object, credential loading (environment variables only), the singleton client. |
| `src/exceptions.py` | `ClearPassAPIError` — message, status code, raw body. |
| `src/utils.py` | Friendly error formatting with actionable suggestions; structured clarification replies. |
| `src/__init__.py` | Marks `src/` as a package. One docstring. |

### Layer 2 — Progressive-disclosure core

| File | Role |
|---|---|
| `src/registry.py` | The in-memory operation catalog. `@operation(domain=...)`, search/lookup, and `register_legacy_tools()`. |
| `src/tools/gateway.py` | `list_operations`, `describe_operations`, `invoke_operation`. |

### Layer 3 — Operation tool layer (`src/tools/`)

Nineteen domain modules holding all 757 registry operations, plus `server_utility.py`
(4 direct `@mcp.tool()` tools, not in the registry) and `__init__.py` (imports ten of the
domain modules; `main.py` names all of them).

| File | Ops | Covers |
|---|---:|---|
| `enforcement_profiles_dur.py` | 142 | The complete Downloadable User Role sub-API: 14 resource families (session/stateless/MAC/ethertype ACLs, QoS, policer and VoIP profiles, NAT pools, net destinations & services, DUR classes and policies, time ranges, captive portal) × id/name variants, each scoped by `product_name`. **The biggest module.** |
| `policy_elements.py` | 112 | Roles, role mappings, enforcement policies, services, auth methods & sources, device groups, posture policies, dynamic-auth templates, dictionaries, proxy targets. |
| `endpoint_visibility.py` | 94 | OnGuard (settings, global settings, activity, custom scripts, zones) and agentless OnGuard; device profiler & fingerprints; network scans; profiler subnet mappings; the Windows hotfix database. |
| `global_server_config.py` | 81 | Admin users & privileges, licences, custom attributes, data filters, operator profiles, SNMP/messaging, backup servers, policy-manager zones, password policies, portal, db-sync. |
| `integrations.py` | 80 | Endpoint context servers and context-server actions, Device Insight, ingress event sources & dictionaries, ClearPass Extensions (store, instances, lifecycle, logs, upgrades), syslog targets & export filters. |
| `identities.py` | 58 | Endpoints (by id and MAC), device accounts, local users, static host lists, deny-listed users, external accounts, plus the replace (PUT) variants of guests and API clients. |
| `certificates.py` | 29 | Signing requests; trust list, client, server and service certificates; revocation lists; self-signed certs. |
| `guest_configuration.py` | 28 | Guest pass templates, print templates, web-login pages (by id and name), global guest auth & guest-manager settings. |
| `audit_logs.py` | 25 | System events, admin login audits, Insight alerts & reports, Insight endpoint lookups, API operation records. |
| `network_devices.py` | 21 | Switches, controllers, APs; RADIUS/TACACS+ settings; device groups; by-name variants. |
| `session_control.py` | 20 | Live sessions: list, disconnect (composed *and* native `session-action` routes), force reauth, RADIUS Change-of-Authorization. |
| `certificate_authority.py` | 19 | Onboard CA: certificate list/get/chain, issue/sign/revoke/reject, import/export, Onboard devices and users. Every name is prefixed `onboard_` because the platform certificate domain already owns the generic names. |
| `local_server_config.py` | 15 | Per-node access-control rules, AD domain join/leave, cluster membership (`list_cluster_servers` yields the `server_uuid` the others need), versions. |
| `enforcement_profiles.py` | 8 | Base profile CRUD. Includes create-from-template and validate. |
| `tools_utilities.py` | 6 | Guest tools and utilities: random password and random MPSK generators, send email, send SMS. |
| `api_clients.py` | 5 | OAuth API client records on ClearPass. |
| `guest_actions.py` | 5 | Digital passes, receipts, SMS/email delivery, sponsor approve/reject. |
| `guest_users.py` | 5 | Guest account lifecycle. The tour's worked example. |
| `api_operations.py` | 4 | The OAuth2 surface itself: inspect the authenticated client or user, list its privileges, mint a token directly for diagnostics. |
| `server_utility.py` | *(4 direct)* | Connection testing, configuration validation, health monitoring, tool listing. **Not** in the registry. |

### Layer 4 — HTTP client (`src/client_methods/`, plus `src/clearpass_client.py`)

One file per domain, mirroring the table above; each defines a `*Mixin` class merged into
`ClearPassClient`. Notables:

- `policy_elements.py` — 192 methods, the largest client module (id/name pairs).
- `enforcement_profiles_dur.py` — 142 methods, one per DUR operation.
- `network_devices.py` — full CRUD plus bulk updates, cloning, connectivity tests,
  statistics, template creation, search, SNMP/RadSec/CLI/OnConnect settings.
- `session_control.py` — bulk disconnect by MAC, username or IP; CoA requests.
- `audit_logs.py` — reads ClearPass's *own* audit endpoints, which is a different thing
  from this project's local audit log.

`credentials.py` (load / validate / mask credentials from the environment, plus its own
exception hierarchy) and `audit_logger.py` (rotating, tamper-checked, secret-stripped
operation log; module-level singleton) belong to this layer too — they exist to serve the
one client.

### Layer 5 — Models (`src/models/`)

Eleven files: `__init__.py` re-exports everything from one place, and ten schema modules
— `api_client`, `audit`, `certificates`, `enforcement_profiles`, `global_server_config`,
`guest_common`, `guest_user`, `local_server_config`, `network_device`, `policy_elements`.
The larger ones are `policy_elements.py` and `network_device.py`;
`enforcement_profiles.py` additionally ships `PREDEFINED_TEMPLATES`, and
`guest_common.py` holds the response-inspection helpers for guest endpoints that return
HTTP 200 with an error body.

There is **no** model file for most domains, including all seven added in the
full-SDK-coverage expansion — those operations pass through `Dict[str, Any]` bodies. Three
model modules (`guest_actions.py`, `guest_configuration.py`, `session_control.py`) were
deleted on 2026-07-31 as dead code; don't go looking for them.

### Layer 6 — Hermetic offline test suite (`tests/`)

Start with `test_tool_count.py`, then `test_registry.py` and `test_gateway_tools.py`. The
AST-level regression guards are `test_no_async_with_client.py`,
`test_no_unbound_in_except.py` and `test_retired_workarounds.py`; the transport contract
is pinned by `test_make_request_body_and_url.py` and `test_make_request_error_bodies.py`.
Broader coverage lives in `test_api_client_tools.py`, `test_credentials.py`,
`test_audit_logger.py`, `test_clearpass_client_integration.py`,
`test_client_call_signatures.py`, `test_certificate_tools.py`, `test_guest_user_tools.py`,
`test_session_bulk_disconnect.py`, `test_feedback_error_reporting.py` and
`test_ambiguous_parameter_confirmation.py`. `conftest.py` puts `src/` on the import path
and supplies placeholder credentials.

Two scripts at the **repo root** are *not* pytest tests — they hit a live appliance and
are run by hand: `test_connection.py` and `test_guest_modules.py` (walks all 33
guest-actions and guest-configuration operations).

Testing policy: run pytest from the project root through `.venv-refactor/bin/python`;
mock `httpx` rather than hitting a real ClearPass server; rely on `conftest.py` for path
setup.

### Layer 7 — Live appliance harness (`tests/live/`)

`harness.py` (fixture naming, `assert_ours`, gateway dispatch, sweep), `conftest.py`
(the `--live` gate, inventory snapshot/diff, cleanup), `denylist.py` (32 forbidden
operations), `README.md` (the full contract: verdict classification, known-limitation
allowlist, artifact schemas), and per-domain `test_*_live.py` files. Recorded runs land
in `tests/live/_artifacts/results-<runid>.jsonl`.

### Layers 8 & 9 — Infrastructure and documentation

`Dockerfile`, `.dockerignore`, `requirements.txt`, `.env.example`, `run_mcp.bat`; and
`README.md`, `CLAUDE.md`/`AGENTS.md`, `mcp_registry_readme.md`, the PRD, plus the
per-package `AGENTS.md` guides.

---

## 9. Complexity hotspots

Approach these carefully. High complexity here mostly means *high volume*, not tangled
logic — but volume is its own risk.

| Area | Why it's hot |
|---|---|
| `src/tools/enforcement_profiles_dur.py` (142 ops) + its mixin (142 methods) | The largest surface in the project. Fourteen resource families × id/name variants, every one scoped by `product_name` — the same object name under two products is two different objects. |
| `src/tools/policy_elements.py` (112 ops) + `src/client_methods/policy_elements.py` (192 methods) | Almost every operation has an id-addressed and a name-addressed twin. Changing a shared helper here touches a lot. |
| `src/tools/endpoint_visibility.py` (94 ops), `src/tools/global_server_config.py` (81 ops), `src/tools/integrations.py` (80 ops) | Each spans many unrelated subject areas in one file. `global_server_config`'s mixin carries 101 methods for 81 operations. |
| `src/tools/guest_configuration.py` (28 ops) | Mixes `update` (patch) with `replace` (overwrite) semantics — easy to get wrong. |
| `src/clearpass_client.py` | Nineteen-parent inheritance. Method resolution order means a name collision between mixins silently resolves to the first parent. Keep new method names distinct — there is one known (benign) collision, see Section 10. |
| `src/tools/server_utility.py` | Small but marked complex — it is the only module using `@mcp.tool()`, and adding anything here directly changes the 7-tool budget. |
| `src/audit_logger.py` | Rotation, sanitisation, tamper-checking, and it must never itself throw in a way that breaks an operation. |
| `src/tools/session_control.py` | Genuinely destructive operations (disconnect, forced reauth on a live network), and two disconnect families — composed (`GET session` then per-session `POST .../disconnect`) and native (`session-action/disconnect*`) — with different failure modes. |
| `tests/test_api_client_tools.py`, `test_credentials.py`, `test_audit_logger.py`, `test_clearpass_client_integration.py` | The heaviest test files; expect to spend time here when the foundation changes. |

---

## 10. Rough edges, and bugs we already pinned

First half: things that are genuinely still open. Second half: bugs that are **fixed**,
written up because each one teaches something you will otherwise rediscover the hard way.

### Still open

#### The green baseline is zero failures — treat any red as real

```bash
.venv-refactor/bin/python -m pytest tests/ --ignore=tests/live -q
# 222 passed
```

The offline suite is hermetic: no network, no credentials, no appliance. It is **222
passed, 0 failed**, and that is the baseline. There is no "expected failure" count to
subtract. If a test goes red, you broke something — investigate, don't compare counts.

(An older revision of this guide told newcomers to expect ~59 failures. Long since false —
and worth flagging, because that advice trained people to ignore real breakage.)

#### The committed `.venv/` is broken — use `.venv-refactor/`

2,369 files of somebody's virtual environment are tracked in git. Its `bin/python` is
Python 3.11 but its `lib/` contains only `python3.10` site-packages, so `import fastmcp`
fails and there is no working `pip`. Purging it from the repo is still an open task.
Until then:

```bash
.venv-refactor/bin/python ...      # always
python3 ...                        # never, for project imports
.venv/bin/python ...               # never
```

#### Live tests need the environment sourced first

```bash
set -a && . ./.env && set +a
.venv-refactor/bin/python -m pytest tests/live --live -q -s
```

The live harness reads credentials from `os.environ`, not from a dotenv file. Skip the
`set -a` and every live test errors with *"--live was requested but the environment is
not ready"* — which looks like a code failure and is not.

#### `CLEARPASS_SERVER` already ends in `/api`

The documented form is `https://host:443/api`. `app_config.py` strips the suffix, and
`ClearPassClient` re-adds it, so the OAuth endpoint is effectively
`${CLEARPASS_SERVER}/oauth`. Setting the variable without `/api`, or with `/api/v1`, will
bite you.

#### `create_external_account` needs `user_name` in the body

The operation's documented required fields are `name` and `type`, but ClearPass 6.12.4
answers `422 - UserName must be specified`. Because the whole external-account family is
tested against an account the create step makes, the other nine operations record
**BLOCKED** rather than PASS in the live run. Appliance-side requirement, not a client
defect — but supply `user_name` if you call it.

#### One benign MRO duplicate

`get_cluster_servers` is defined identically in both `client_methods/audit_logs.py` and
`client_methods/local_server_config.py`. With nineteen mixins, the first parent listed
wins — here both bodies are the same, so it is harmless. It is still the exact hazard
Section 2's method-resolution-order note warns about; keep new method names distinct.

#### Windows-only launcher scripts with hardcoded paths

`run_mcp.bat` and `run mcp server via mcpo proxy for ollama.txt` both embed an absolute
path from a specific developer's machine. Neither works unedited. Use Docker or
`python src/main.py`.

### Two transport-layer traps, now fixed centrally

Both were measured by direct `curl` against a live ClearPass 6.12.4 appliance, fixed in
`src/clearpass_client.py`, and are pinned by `tests/test_make_request_body_and_url.py`.
Read that file before you touch `_make_request` or `_endpoint_url`.

**1. Everything lives at `/api`, not `/api/v1`.** The client used to default to the
versioned root with a growing exception list. That was backwards. `/api` is a strict
superset: `/api/v1/alert` and `/api/v1/report` return `404 Object not found`, every
`enforcement-profile-dur/*` write and `session-action/disconnect*` returns an
HTML-wrapped **HTTP 500**, and `POST /api/v1/oauth` 404s. Fifty-three of fifty-six GET
endpoints are byte-identical at both roots; no endpoint exists that `/api/v1` serves and
`/api` does not. This single mount defect had masqueraded as roughly **five separate
"appliance limitations"** in older docs. The exception mechanism was deleted, and
`test_unversioned_prefix_exception_mechanism_is_gone` makes sure it never returns.

**2. A body-less write still needs a body.** The shared `httpx` client always sends
`Content-Type: application/json`. Passing `json=None` sends *no bytes*, so the appliance
reads a JSON content type with an empty body and answers
`400 - JSON decoding error: Syntax error, malformed JSON`. Every body-less
PATCH/POST/PUT the API defines — alert enable/disable, report run, service start/stop,
licence activation, subnet-mapping enable/disable — hits this. `_make_request` now
normalises `None` to `{}` for those three verbs centrally, so no caller needs a local
`data={}` workaround. GET and DELETE are excluded on purpose.

### The un-awaited coroutine: a solved case study

Worth understanding even though it no longer exists, because it is the cleanest
illustration of Section 2's `async def` note.

`get_clearpass_client()` in `src/app_config.py` is a plain `async def`. Calling it
produces a **coroutine object**, not a client. A coroutine has no `__aenter__`, so this:

```python
async with get_clearpass_client() as client:      # bug: no await
```

raises `TypeError` the moment the operation is actually invoked — and *only* then, which
is why it stayed latent: unit tests mock the client. The canonical form is:

```python
client = await get_clearpass_client()
```

That bug shipped twice, first in `policy_elements.py` and then in `session_control.py`
(7 call sites). Today all **615** call sites under `src/` use the canonical form, and
`tests/test_no_async_with_client.py` walks the source tree and fails the build if the
string `async with get_clearpass_client(` reappears anywhere. Its sibling
`tests/test_no_unbound_in_except.py` does the same for a second recurring shape: an
`except` handler reading a local that is only bound *after* an `await` in the `try` body,
where a plain 404 turns the handler itself into an `UnboundLocalError`.

**The transferable lesson:** when a bug class recurs, do not write another unit test for
the instance. Write a guard against the *shape*.

### Documentation status

`README.md`, `CLAUDE.md`, `AGENTS.md`, the per-package `AGENTS.md` files,
`mcp_registry_readme.md`, `.env.example` and this guide all carry the current
761/757/764 counts. `clearpass-sidekick-mcp-prd.md`, `docs/live_testing_plan_phase*.md`
and the other `docs/*_plan.md` files are historical records of earlier states and are
deliberately left as-is.

---

## 11. Your first change: adding a new operation end to end

Suppose ClearPass exposes an endpoint this server doesn't yet cover — say, listing
"static host lists" — and you want the assistant to be able to call it.

You touch **two files, or three if the domain earns a model**, in this order.

### Step 1 (optional) — The data shapes: `src/models/static_host_lists.py`

Only worth doing when the request body is rich and reused; most of the newer domains just
pass a `Dict[str, Any]` through. When it is worth it, describe what goes in and what comes
out, using Pydantic.

```python
from typing import List, Optional
from pydantic import BaseModel, Field

class StaticHostList(BaseModel):
    id: Optional[int] = None
    name: str = Field(..., description="Name of the static host list.")
    host_format: str = Field(..., description="One of: subnet, regex, list.")
    host_entries: List[str] = Field(default_factory=list)

class StaticHostListResponse(BaseModel):
    items: List[StaticHostList] = Field(default_factory=list)
    count: int = 0
```

Then re-export it from the package front door so the rest of the server can import it
from one place:

```python
# src/models/__init__.py
from .static_host_lists import StaticHostList, StaticHostListResponse
```

> Why models first? Because the registry reads these annotations to generate the
> parameter schema the AI sees. Get the shapes right and the tool description writes
> itself.

### Step 2 — The HTTP call: `src/client_methods/static_host_lists.py`

Write a **mixin** — a class that is never instantiated on its own, only merged into
`ClearPassClient`.

```python
class StaticHostListsMixin:
    """Adds static-host-list REST calls to ClearPassClient."""

    async def list_static_host_lists(self, filter_str=None, limit=25):
        params = {"limit": limit}
        if filter_str:
            params["filter"] = filter_str
        # _make_request is the ONLY door out to the network. It adds the /api
        # root, the bearer token, retries and audit logging for you.
        return await self._make_request("GET", "static-host-list", params=params)
```

Then add it to the class definition in `src/clearpass_client.py`:

```python
class ClearPassClient(
    ApiClientsMixin,
    ...
    StaticHostListsMixin,      # ← new parent
):
```

> **Method resolution order matters.** If another mixin already defines
> `list_static_host_lists`, whichever parent is listed *first* wins and yours is silently
> ignored. Keep names distinct — that's why every mixin method here is domain-prefixed.
>
> This file is the **only** place in the project allowed to construct a URL or make an
> HTTP call.

### Step 3 — The operation: `src/tools/static_host_lists.py`

Thin. Validate, delegate, format.

```python
from typing import Any, Dict, Optional

from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..exceptions import ClearPassAPIError
from ..registry import operation
from ..utils import format_api_error

@operation(domain="static_host_lists")
async def list_static_host_lists(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter",
        description="JSON filter expression."),
    limit: Optional[int] = Field(25,
        description="Maximum number of items to return (1-1000)."),
) -> Dict[str, Any]:
    """
    List static host lists configured on ClearPass.

    Examples:
    - "Show me all static host lists"
    - "List static host lists matching 'printers'"
    """
    try:
        client = await get_clearpass_client()      # note: await, not `async with`
        result = await client.list_static_host_lists(
            filter_str=filter_str, limit=limit
        )
        return {"success": True, "static_host_lists": result}
    except ClearPassAPIError as e:
        return await format_api_error(e, "list static host lists")
```

Things that are load-bearing here:

- **The docstring is the tool description.** `describe_operations` returns it verbatim to
  the model. Write it for a reader who is deciding whether to call this. Include the
  natural-language example phrasings — that is the established convention in every
  existing module.
- **`Field(description=...)` is the parameter documentation** the model sees. Not
  optional.
- **`ctx: Context` is excluded** from the generated schema by the registry — it's plumbing,
  not a user-facing argument.
- **Anything destructive takes `confirm: bool`** and refuses to act without it.
- **Catch and format, don't raise.** `format_api_error` is itself `async` — `await` it —
  and produces a structured result with an actionable next step.

### Step 4 — Wire the import (one line)

```python
# src/tools/__init__.py
from . import static_host_lists
```

That single import is the entire registration. Importing the module runs the `@operation`
decorator, which files the function into the registry, which makes it discoverable by
`list_operations` and callable by `invoke_operation`.

**Why this is enough without editing `main.py`:** `main.py` does
`from .tools import (...)`, which first runs `src/tools/__init__.py` — and that now
imports your module. `main.py` happens to name all 19 existing domain modules explicitly
as well; adding yours there too is harmless but redundant. Pick one place and be
consistent.

**And crucially: you do not add an `@mcp.tool()` anywhere.** Your operation is reachable
through the gateway. The visible tool count stays at 7. That is the entire design.

### Step 5 — Update the count test

```python
# tests/test_tool_count.py
EXPECTED_OPERATIONS = 758     # was 757
```

Yes, you have to edit a test to add a feature. That is deliberate — it forces every
change to the operation surface to be a conscious, reviewed act. Add a line to that
file's module docstring saying *why* the number moved; it is the running ledger of every
count change since the refactor.

### Step 6 — Verify

```bash
.venv-refactor/bin/python -m pytest tests/ --ignore=tests/live -q     # must stay green
```

Then, with a live appliance configured, ask the assistant something like *"list the
static host lists"* and watch it call `list_operations` → `describe_operations` →
`invoke_operation`.

---

## 12. Quick reference

```bash
# Setup  (NOT .venv/ — that one is committed and broken)
python3 -m venv .venv-refactor && source .venv-refactor/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run
python src/main.py
docker build -t clearpass-sidekick . && docker run --rm -i --env-file .env clearpass-sidekick

# Test
.venv-refactor/bin/python -m pytest tests/ --ignore=tests/live -q   # 222 passed, 0 failed
.venv-refactor/bin/python -m pytest tests/test_tool_count.py -q     # the architectural guard
set -a && . ./.env && set +a                                        # REQUIRED before --live
.venv-refactor/bin/python -m pytest tests/live --live -q -s         # opt-in, real appliance

# Key env vars
CLEARPASS_SERVER  # includes the /api suffix: https://host:443/api
CLEARPASS_CLIENT_ID, CLEARPASS_CLIENT_SECRET, CLEARPASS_VERIFY_SSL
CLEARPASS_MCP_LEGACY_TOOLS=true               # escape hatch: 764 visible tools
```

**The numbers, one last time:** 761 operations = 757 in the registry + 4 direct utility
tools. Default visible surface = **7** (3 gateway + 4 utility). Legacy mode = **764**.

**Where to look first when something breaks:** `tests/test_tool_count.py` tells you
whether the architecture is intact. `src/app_config.py` tells you whether credentials
loaded. The audit log tells you what actually reached the appliance.

Welcome aboard.
