# Cipherion Python SDK

[![PyPI version](https://img.shields.io/pypi/v/cipherion.svg)](https://pypi.org/project/cipherion/)
[![Python versions](https://img.shields.io/pypi/pyversions/cipherion.svg)](https://pypi.org/project/cipherion/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Typed](https://img.shields.io/badge/typing-fully%20typed-brightgreen)](https://mypy.readthedocs.io/)

A Python  SDK for the [Cipherion](https://cipherion.io) field-level encryption API. Encrypt and decrypt individual strings, deeply-nested objects, and entire datasets, all through a single, fully-typed interface.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Simple Encrypt / Decrypt](#simple-encrypt--decrypt)
  - [Deep Encrypt / Decrypt](#deep-encrypt--decrypt)
  - [Bulk Migration](#bulk-migration)
  - [Runtime Config Updates](#runtime-config-updates)
- [Error Handling](#error-handling)
- [Logging](#logging)
- [Project Structure](#project-structure)
- [Development](#development)
- [License](#license)

---

## Features

- **Simple encryption** — encrypt and decrypt plain strings in one call
- **Deep encryption** — recursively encrypt every value in a nested dict or list while preserving its shape
- **Bulk migration** — process thousands of records in parallel batches with progress callbacks, per-item error isolation, and automatic retries
- **Automatic retries** — exponential back-off with jitter for network errors, rate limits, and 5xx responses
- **Structured logging** — rotating log files with sensitive-value redaction built in
- **Fully typed** — complete `py.typed` support for mypy and Pyright

---

## Requirements

- Python **3.10+**
- A [Cipherion](https://cipherion.io) account with a project ID and API key

---

## Installation

```bash
pip install cipherion
```

---

## Configuration

### Option A — Pass a config dict

```python
from cipherion import CipherionClient

client = CipherionClient({
    "base_url":   "https://api.cipherion.io",
    "project_id": "proj_abc123",
    "api_key":    "ak_live_...",
    "passphrase": "my-strong-passphrase",   # minimum 12 characters
})
```

### Option B — Environment variables

Create a `.env` file (or export the variables directly):

```dotenv
CIPHERION_BASE_URL=https://api.cipherion.io
CIPHERION_PROJECT_ID=proj_abc123
CIPHERION_API_KEY=ak_live_...
CIPHERION_PASSPHRASE=my-strong-passphrase
```

Then initialise with no arguments:

```python
client = CipherionClient()   # reads from environment automatically
```

### All configuration options

| Option | Type | Default | Description |
|---|---|---|---|
| `base_url` | `str` | env var | Cipherion API base URL |
| `project_id` | `str` | env var | Your project identifier |
| `api_key` | `str` | env var | API authentication key |
| `passphrase` | `str` | env var | Encryption passphrase (≥ 12 chars) |
| `timeout` | `int` | `30000` | Request timeout in milliseconds |
| `retries` | `int` | `3` | Max retry attempts per request |
| `log_level` | `str` | `"info"` | One of `"debug"`, `"info"`, `"warn"`, `"error"` |
| `enable_logging` | `bool` | `True` | Write structured logs to `cipherion-logs/` |

---

## Usage

### Simple Encrypt / Decrypt

Use `encrypt` and `decrypt` for any plain string value — API tokens, passwords, PII snippets, and so on.

```python
# Encrypt
ciphertext = client.encrypt("alice@example.com")
print(ciphertext)   # "enc:v1:AbCdEf..."

# Decrypt
email = client.decrypt(ciphertext)
print(email)        # "alice@example.com"
```

---

### Deep Encrypt / Decrypt

`deep_encrypt` recurses into any dict or list and encrypts every leaf value while preserving the original structure. `deep_decrypt` reverses the process.

#### Basic example

```python
user = {
    "id": 42,
    "name": "Alice",
    "email": "alice@example.com",
    "address": {
        "street": "123 Main St",
        "zip": "90210",
    },
}

result = client.deep_encrypt(user)
encrypted_user = result["encrypted"]

# encrypted_user looks like:
# {
#     "id":    "enc:v1:...",
#     "name":  "enc:v1:...",
#     "email": "enc:v1:...",
#     "address": {
#         "street": "enc:v1:...",
#         "zip":    "enc:v1:...",
#     },
# }
```

#### Excluding fields

Pass an `ExclusionOptions` object to skip fields you want to leave in the clear:

```python
from cipherion import ExclusionOptions

result = client.deep_encrypt(
    user,
    options=ExclusionOptions(
        exclude_fields=["id"],                  # exact field name match
        exclude_patterns=["created_*", "*_at"], # glob-style pattern match
    ),
)
# "id" and any field matching the patterns are left unencrypted
```

#### Decrypting back

```python
decrypted = client.deep_decrypt(encrypted_user)
original = decrypted["data"]
# original == user  ✓
```

#### Graceful decryption failures

When processing data you don't fully control, use `fail_gracefully` to leave undecryptable fields as-is rather than raising an error:

```python
decrypted = client.deep_decrypt(
    partially_encrypted_payload,
    options=ExclusionOptions(fail_gracefully=True),
)
```

#### `ExclusionOptions` reference

| Field | Type | Description |
|---|---|---|
| `exclude_fields` | `list[str]` | Exact field names to leave unencrypted |
| `exclude_patterns` | `list[str]` | Glob patterns — e.g. `"*_id"`, `"meta_*"` |
| `fail_gracefully` | `bool` | Skip undecryptable fields instead of raising (`deep_decrypt` only) |

---

### Bulk Migration

`migrate_encrypt` and `migrate_decrypt` process a list of records in parallel batches. Each item is handled independently — a failure on one record never aborts the rest.

```python
from cipherion import MigrationOptions

# Imagine these came from a database export
records = [
    {"id": 1, "ssn": "111-22-3333", "dob": "1990-01-15"},
    {"id": 2, "ssn": "444-55-6666", "dob": "1985-07-04"},
    # ... thousands more
]

result = client.migrate_encrypt(
    records,
    options=MigrationOptions(
        batch_size=50,                  # records per parallel batch
        delay_between_batches=250,      # ms pause between batches (avoids rate limits)
        max_retries=3,                  # per-item retry attempts
        on_progress=lambda p: print(
            f"Progress: {p.successful}/{p.total} "
            f"({p.percentage:.1f}%)  failed={p.failed}"
        ),
        on_error=lambda err, item: print(f"[WARN] item {item['id']} failed: {err}"),
    ),
)

print(result.summary)
# MigrationProgress(total=1000, processed=1000, successful=997, failed=3, percentage=99.7)

# Work with results
for encrypted_record in result.successful:
    db.save(encrypted_record["encrypted"])

for failure in result.failed:
    logger.error("Migration failure", extra={"item": failure.item, "error": str(failure.error)})
```

Decrypting a previously migrated dataset works the same way:

```python
result = client.migrate_decrypt(encrypted_records)
```

#### `MigrationOptions` reference

| Field | Type | Default | Description |
|---|---|---|---|
| `batch_size` | `int` | `10` | Records per batch (clamped 1–100) |
| `delay_between_batches` | `int` | `1000` | Milliseconds to wait between batches |
| `max_retries` | `int` | `3` | Per-item retry attempts (clamped 1–10) |
| `on_progress` | `Callable` | `None` | Called after every record with a `MigrationProgress` snapshot |
| `on_error` | `Callable` | `None` | Called when an individual item fails |
| `exclusion_options` | `ExclusionOptions` | `None` | Fields/patterns to skip during deep encrypt/decrypt |

---

### Runtime Config Updates

Read or change non-sensitive settings without restarting:

```python
# Inspect current config (api_key and passphrase are never returned)
print(client.get_config())
# {
#   "base_url": "https://api.cipherion.io",
#   "project_id": "proj_abc123",
#   "timeout": 30000,
#   "retries": 3,
#   "log_level": "info",
#   "enable_logging": True,
# }

# Increase timeout and switch to debug logging at runtime
client.update_config({"timeout": 60_000, "log_level": "debug"})
```

> **Note:** `api_key` and `passphrase` cannot be changed after initialisation. Create a new client instance instead.

---

## Error Handling

Every method raises `CipherionError` on failure. It carries enough context to decide whether to retry, what to show the user, and what to log:

```python
from cipherion import CipherionClient, CipherionError

try:
    ciphertext = client.encrypt("sensitive value")

except CipherionError as e:
    print(e.status_code)          # HTTP status (0 = network/connection error)
    print(e.message)              # Technical error message
    print(e.details)              # Optional additional context from the API
    print(e.timestamp)            # ISO-8601 UTC timestamp of the error

    print(e.get_user_message())   # Safe, friendly string for end-user display
    print(e.is_retryable())       # True for 5xx, 429, and network errors
    print(e.to_json())            # Dict safe to pass to your logging pipeline
```

#### Status code quick-reference

| Code | Meaning | `is_retryable()` |
|---|---|---|
| `0` | Network / connection error | ✅ Yes |
| `400` | Bad request (invalid input) | ❌ No |
| `401` / `403` | Authentication / authorisation failure | ❌ No |
| `429` | Rate limit exceeded | ✅ Yes |
| `5xx` | Server-side error | ✅ Yes |

---

## Logging

The SDK writes two rotating log files under `cipherion-logs/`:

| File | Content |
|---|---|
| `combined.log` | All log levels |
| `error.log` | Errors only |

Files rotate at **10 MB** with up to **5 backups** kept. A colourised console handler is added automatically unless `CIPHERION_ENV=production`.

Sensitive keys (`passphrase`, `api_key`, `token`, `secret`, `authorization`, `credential`) are automatically redacted to `[REDACTED]` before any value reaches a log handler. String values longer than 100 characters are truncated.

To disable file logging entirely:

```python
client = CipherionClient({"enable_logging": False, ...})
```

---

## Project Structure

```
cipherion-python-sdk/
├── src/
│   └── cipherion/
│       ├── __init__.py            ← public API surface
│       ├── client/
│       │   └── cipherion_client.py
│       ├── errors/
│       │   └── cipherion_error.py
│       ├── types/
│       │   ├── api.py             ← API request / response dataclasses
│       │   └── client.py          ← config & migration dataclasses
│       └── utils/
│           ├── http.py            ← requests wrapper with retry logic
│           ├── logger.py          ← structured rotating logger
│           ├── migration.py       ← parallel batch processor
│           └── validation.py      ← input validators
├── examples/
│   └── basic_usage.py
├── tests/
├── pyproject.toml
└── README.md
```

---

## Development

```bash
# Clone and install with dev dependencies
git clone https://github.com/OneBoatSolutions/Cipherion-Python-SDK
cd Cipherion-Python-SDK
pip install -e ".[dev]"

# Run the test suite
pytest

# Type-check
mypy src/cipherion

# Lint and auto-format
ruff check src/
ruff format src/
```

---

## License

MIT © Cipherion