"""Session setup for the suite.

JADART_TEST_NO_CAPSTONE=1 runs it the way CI's install-without-capstone job does, with
capstone unimportable in every worker: a test that decodes instructions has to skip
there, not fail. Set here rather than in a test module, so it is in place before any of
jadart is imported and in each pytest-xdist worker. `check.sh` uses it; until it did, a
test that skipped nothing was first seen failing on CI (#277)."""
import os
import sys

if os.environ.get("JADART_TEST_NO_CAPSTONE"):
    sys.modules["capstone"] = None
