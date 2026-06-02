#!/usr/bin/env python3
"""AppSec triage bot — entry point.

Defensive multi-agent triage of Dependabot alerts. The LLM never acts alone:
deterministic agents gate it on the way in (Truth Table) and on the way out
(Critic + Consistency Gate). See README and triage/cli.py for details.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from triage.cli import main

if __name__ == "__main__":
    sys.exit(main())
