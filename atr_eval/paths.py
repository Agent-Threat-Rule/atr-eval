"""Where ATR Eval keeps its own state. Nothing here is shared with the operator's normal agent setup."""

from __future__ import annotations

import os
from pathlib import Path

HOME = Path(os.environ.get("ATR_EVAL_HOME", Path.home() / ".config" / "atr-eval"))
# A Claude Code config directory of its own: no user hooks, plugins, CLAUDE.md or memory from the operator's setup.
CLAUDE_CONFIG_DIR = Path(os.environ.get("ATR_EVAL_CLAUDE_CONFIG_DIR", HOME / "claude"))
SIGNING_KEY_FILE = Path(os.environ.get("ATR_EVAL_SIGNING_KEY_FILE", HOME / "signing" / "ed25519.pem"))
LEDGER_FILE = HOME / "ledger.jsonl"  # every run this installation has signed (see ledger.py)
URI_BASE = "https://agentthreatrule.org/eval"
