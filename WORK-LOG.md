# WORK-LOG — pysnmp keeper modernization

**Program:** pysnmp v5.0.0 (Ilya Etingof, d. 2022), frozen at commit `becd15c`
("Update FUNDING.yml", 2019-12-15). BSD 2-Clause — clean.
**Keeper:** Steve Wagner. Ilya Etingof's authorship and the BSD license are
kept intact throughout — every change below is additive/maintenance only.
Nothing was renamed (Steve renames on absorb; his call). Nothing was pushed
to GitHub, forked, published, or released to PyPI.

## 1. Environment

- VM: Python 3.12.3. Venv: `/tmp/pysnmp-venv` (ephemeral; recreated on demand).
- `pip install -e .` — installs cleanly. Declared runtime deps that resolve:
  `pysmi`, `pyasn1>=0.2.3` (resolved to **0.6.4**).
- Optional extras (`extra-requirements.txt`): `pysnmpcrypto` and `twisted`
  were installed manually into the venv to exercise the full crypto chain.
  - `pysnmpcrypto 0.1.0` installs on 3.12 and its DES/AES round-trips work
    (one `CryptographyDeprecationWarning` from *its own* code about CFB
    moving to `cryptography.hazmat.decrepit` — upstream's problem, not ours).
  - Note: the `pysnmpcrypto` on PyPI today is version 0.1.0, published from
    the lextudio fork lineage; Ilya's original was 0.0.4. It is API-compatible
    for what pysnmp v5 needs (`des`, `aes`, `PysnmpCryptoError`).
  - `twisted 26.4.0` installs; `pysnmp.carrier.twisted` imports fine.
- SNMPv3 auth (HMAC-MD5/SHA/SHA-2) is pure-Python via `hashlib` — no extra
  dep. Only DES/3DES/AES priv goes through `pysnmpcrypto`, and the imports
  degrade gracefully (`des = None`) when it is absent.

## 2. What was broken on Python 3.12 (before state)

The repo did not import at all under Python 3.12 with modern pyasn1:

1. **`import asyncore` — stdlib module removed in 3.12.**
   `pysnmp/carrier/asyncore/{base,dispatch}.py` raised `ModuleNotFoundError`,
   taking down the entire asyncore transport family and the sync hlapi.
2. **`from pyasn1.compat.octets import ...` — removed in pyasn1 0.5+.**
   15 modules failed at import (`null`, `oct2int`, `int2oct`, `octs2ints`,
   `str2octs`, plus the `octets` module itself in `SNMPv2-TC.py`).
3. **`@asyncio.coroutine` — removed in Python 3.11.** 26 uses across 5 files
   (`pysnmp/carrier/asyncio/dispatch.py`,
   `pysnmp/hlapi/{v1arch,v3arch}/asyncio/{cmdgen,ntforg}.py`).
4. **Invalid escape sequences in docstrings** (`\*` etc.) — `SyntaxWarning`
   on 3.12, hard `SyntaxError` on 3.14. 74 docstrings across 15 files.
5. **Latent:** `IS_PYTHON_344_PLUS = platform.python_version_tuple() >=
   ('3','4','4')` compares version components as *strings*, so it is `False`
   on Python 3.10+ (`'12' < '4'`). This silently routed
   `DgramAsyncioProtocol.openClientMode/openServerMode` into the dead
   `getattr(asyncio, 'async')` branch → `AttributeError` on 3.12.
6. **Stale metadata:** setup.py classifiers claimed Python 2.6–3.7; the
   version guard required only 2.6+; tox envlist was py26–py38.

The upstream "test suite" (`runtests.sh`) is not a test suite in the modern
sense — it runs the `examples/` scripts, ~all of which query the long-dead
`demo.snmplabs.com`. It cannot pass in any sandbox and was not runnable as a
verification gate. A new no-network functional suite was added instead (see
§4).

## 3. Changes made (minimal, faithful)

- **Vendored `asyncore`**: `pysnmp/carrier/asyncore/asyncore.py` — the stdlib
  module as of CPython 3.11 (sourced via the `pyasyncore` PyPI backport,
  original Sam Rushing copyright/license header preserved intact, with a
  keeper provenance note on top). Import sites in
  `carrier/asyncore/{base,dispatch}.py` now use the vendored copy. No
  behavioral change to the transport code.
- **New `pysnmp/compat/octets.py`** (+ `pysnmp/compat/__init__.py`): re-exports
  `pyasn1.compat.octets` when an old pyasn1 provides it; otherwise implements
  the same helpers locally with py3 semantics matching pyasn1 0.4.x
  (`null`, `int2oct`, `oct2int`, `ints2octs`, `octs2ints`, `str2octs`,
  `octs2str`, `isStringType`, `isOctetsType`, `isIntsType`, `ensureString`).
  All 15 import sites switched from `pyasn1.compat...` to `pysnmp.compat...`.
  Added `pysnmp.compat` to `setup.py` packages.
- **asyncio modernization**: `@asyncio.coroutine` decorators removed;
  `def` → `async def`; the coroutine tails `return future` → 
...[truncated 4497 chars]
