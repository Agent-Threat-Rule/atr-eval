"""Keep test runs away from the operator's real ATR Eval home (signing key, agent logins)."""

import os
import tempfile

os.environ.setdefault("ATR_EVAL_HOME", tempfile.mkdtemp(prefix="atr-eval-test-home-"))
os.environ.pop("ATR_EVAL_SIGNING_KEY", None)
os.environ.pop("ATR_EVAL_SIGNING_KEY_FILE", None)
