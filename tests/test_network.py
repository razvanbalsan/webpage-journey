import time

import pytest

from wj import capabilities, schema
from wj.context import Context
from wj.run import orchestrate

pytestmark = pytest.mark.network


def test_real_trace_of_example_com_validates():
    caps = capabilities.detect()
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=8.0, deadline=time.monotonic() + 25.0, caps=caps, results={})
    trace = orchestrate(ctx)
    assert schema.validate(trace) == []
    assert trace["dns"]["observed"] is True
    assert trace["tcp"]["observed"] is True
    assert trace["http"]["observed"] is True
    assert trace["http"]["final"]["status"] in (200, 301, 302)
