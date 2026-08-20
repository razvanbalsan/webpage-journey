from wj import capabilities


class FakeRun:
    """Stands in for subprocess.run: returns a canned return code."""

    def __init__(self, returncode):
        self.returncode = returncode
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        class R:
            pass
        r = R()
        r.returncode = self.returncode
        r.stdout = ""
        r.stderr = ""
        return r


def test_detect_records_found_and_missing_tools():
    run = FakeRun(1)
    caps = capabilities.detect(
        which=lambda name: "/usr/bin/dig" if name == "dig" else None,
        geteuid=lambda: 501,
        run=run,
    )
    assert caps.tools["dig"] == "/usr/bin/dig"
    assert caps.tools["traceroute"] is None
    assert caps.has_tool("dig") is True
    assert caps.has_tool("traceroute") is False


def test_detect_reports_root_and_sudo_ability():
    caps = capabilities.detect(which=lambda n: None, geteuid=lambda: 0, run=FakeRun(0))
    assert caps.privileged is True

    caps = capabilities.detect(which=lambda n: "/usr/bin/sudo", geteuid=lambda: 501, run=FakeRun(0))
    assert caps.privileged is False
    assert caps.can_sudo is True

    caps = capabilities.detect(which=lambda n: "/usr/bin/sudo", geteuid=lambda: 501, run=FakeRun(1))
    assert caps.can_sudo is False


def test_to_dict_shape_matches_trace_capabilities_block():
    caps = capabilities.detect(
        which=lambda name: "/usr/bin/dig" if name == "dig" else None,
        geteuid=lambda: 501,
        run=FakeRun(1),
    )
    d = caps.to_dict()
    assert d["privileged"] is False
    assert d["tools"] == ["dig"]
    assert "cryptography" in d["libs"]
    assert d["installed_during_run"] == []


def test_ensure_libs_offline_mode_installs_nothing():
    caps = capabilities.Capabilities(
        libs={"cryptography": False}, tools={}, privileged=False,
        can_sudo=False, installed_during_run=[],
    )
    installed = []
    out = capabilities.ensure_libs(
        caps, mode="offline",
        installer=lambda pkg: installed.append(pkg) or True,
        prompt=lambda msg: True,
    )
    assert installed == []
    assert out.libs["cryptography"] is False


def test_ensure_libs_in_venv_installs_without_prompting():
    caps = capabilities.Capabilities(
        libs={"cryptography": False}, tools={}, privileged=False,
        can_sudo=False, installed_during_run=[],
    )
    installed = []
    prompted = []
    out = capabilities.ensure_libs(
        caps, mode="auto", in_venv=True,
        installer=lambda pkg: installed.append(pkg) or True,
        prompt=lambda msg: prompted.append(msg) or True,
    )
    assert installed == ["cryptography"]
    assert prompted == []
    assert out.libs["cryptography"] is True
    assert out.installed_during_run == ["cryptography"]


def test_ensure_libs_outside_venv_asks_first_and_honours_no():
    caps = capabilities.Capabilities(
        libs={"cryptography": False}, tools={}, privileged=False,
        can_sudo=False, installed_during_run=[],
    )
    installed = []
    out = capabilities.ensure_libs(
        caps, mode="auto", in_venv=False,
        installer=lambda pkg: installed.append(pkg) or True,
        prompt=lambda msg: False,
    )
    assert installed == []
    assert out.libs["cryptography"] is False


def test_ensure_libs_records_failed_install_as_unavailable():
    caps = capabilities.Capabilities(
        libs={"cryptography": False}, tools={}, privileged=False,
        can_sudo=False, installed_during_run=[],
    )
    out = capabilities.ensure_libs(
        caps, mode="auto", in_venv=True,
        installer=lambda pkg: False,
        prompt=lambda msg: True,
    )
    assert out.libs["cryptography"] is False
    assert out.installed_during_run == []


def test_pip_name_differs_from_import_name_for_dnspython():
    pip_name, reason = capabilities.OPTIONAL_LIBS["dns"]
    assert pip_name == "dnspython"
    assert reason
