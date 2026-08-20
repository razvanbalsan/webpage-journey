"""What this machine can actually do, so every 'not observed' is explainable."""

import importlib.util
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

TOOL_NAMES = (
    "dig", "traceroute", "tracepath", "openssl", "ip", "ifconfig",
    "route", "arp", "ipconfig", "ethtool", "wdutil", "scutil", "sudo",
)

# import name -> (pip name, why this run wants it)
OPTIONAL_LIBS = {
    "dns": ("dnspython", "DNS record types, TTLs, and the delegation walk"),
    "cryptography": ("cryptography", "full certificate chain parsing"),
    "h2": ("h2", "HTTP/2 negotiation"),
}


@dataclass
class Capabilities:
    libs: dict
    tools: dict
    privileged: bool
    can_sudo: bool
    installed_during_run: list = field(default_factory=list)

    def has_tool(self, name):
        return bool(self.tools.get(name))

    def has_lib(self, name):
        return bool(self.libs.get(name))

    def to_dict(self):
        return {
            "privileged": self.privileged,
            "can_sudo": self.can_sudo,
            "tools": sorted(n for n, p in self.tools.items() if p),
            "libs": dict(self.libs),
            "installed_during_run": list(self.installed_during_run),
        }


def _lib_present(import_name):
    return importlib.util.find_spec(import_name) is not None


def detect(which=shutil.which, geteuid=os.geteuid, run=subprocess.run):
    tools = {name: which(name) for name in TOOL_NAMES}
    privileged = geteuid() == 0

    can_sudo = False
    if not privileged and tools.get("sudo"):
        try:
            can_sudo = run(["sudo", "-n", "true"], capture_output=True, timeout=3).returncode == 0
        except Exception:
            can_sudo = False

    libs = {name: _lib_present(name) for name in OPTIONAL_LIBS}
    return Capabilities(libs=libs, tools=tools, privileged=privileged, can_sudo=can_sudo)


def in_virtualenv():
    return sys.prefix != sys.base_prefix


def _pip_install(pip_name):
    try:
        return subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet",
             "--disable-pip-version-check", pip_name],
            timeout=180,
        ).returncode == 0
    except Exception:
        return False


def ensure_libs(caps, mode="auto", in_venv=None, installer=None, prompt=None):
    """Install missing optional libraries, with a virtualenv guardrail.

    Inside a virtualenv we install quietly. Against a system interpreter we ask
    once, because silently mutating a system Python is unpleasant to undo.
    """
    if mode == "offline":
        return caps

    installer = installer or _pip_install
    prompt = prompt or _confirm
    if in_venv is None:
        in_venv = in_virtualenv()

    missing = [name for name, ok in caps.libs.items() if not ok]
    if not missing:
        return caps

    if not in_venv:
        names = ", ".join(OPTIONAL_LIBS[m][0] for m in missing)
        if not prompt(f"Install {names} into this system Python?"):
            return caps

    for import_name in missing:
        pip_name, _reason = OPTIONAL_LIBS[import_name]
        if installer(pip_name):
            caps.libs[import_name] = True
            caps.installed_during_run.append(import_name)

    return caps


def _confirm(message):
    try:
        return input(f"{message} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False
