"""The declared package list must cover every package that actually exists.

wj/transport/ was created by the HTTP/2 work and never added to
pyproject.toml's [tool.setuptools.packages.find] include list. Every installed
build therefore shipped without it, and wj/collect/http.py's
`from wj.transport import TRANSPORTS, h1` raised ModuleNotFoundError at
startup -- the tool was dead on arrival for anyone who installed it rather
than running from a clone, including via the Homebrew formula, which builds a
tagged release with Language::Python::Virtualenv.

Nothing in the rest of this suite could see it: the tests import wj from the
source tree, where the package directory is present regardless of what the
build config says. That is exactly the shape this file exists to close.

Deliberately stdlib-only (tomllib + fnmatch): it must RUN in this project's
own venv, which has no setuptools, rather than skip. A guard that skips is not
a guard -- this project has been burned three times by exactly that.
"""

import tomllib
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"


def _find_config():
    config = tomllib.loads(PYPROJECT.read_text())
    return config["tool"]["setuptools"]["packages"]["find"]


def _resolves(name, find):
    """Whether setuptools' package finder would keep `name`.

    Written against the include/exclude PATTERNS rather than against literal
    list membership, so it stays correct if the include list is ever switched
    to a glob such as "wj*" -- the guard must not quietly stop guarding
    because the config style changed.
    """
    included = any(fnmatchcase(name, pattern) for pattern in find.get("include", ["*"]))
    excluded = any(fnmatchcase(name, pattern) for pattern in find.get("exclude", []))
    return included and not excluded


def _actual_packages():
    """Every real package under wj/ -- any directory with an __init__.py."""
    root = ROOT / "wj"
    names = []
    for init in sorted(root.rglob("__init__.py")):
        rel = init.parent.relative_to(ROOT)
        names.append(".".join(rel.parts))
    return names


def test_the_repo_actually_has_subpackages_to_check():
    # The standing-guard blind spot, closed in the direction that matters: if
    # the walk ever stopped finding anything, every assertion below would pass
    # vacuously and prove nothing.
    packages = _actual_packages()
    assert "wj" in packages
    assert len(packages) > 1, packages


@pytest.mark.parametrize("name", _actual_packages())
def test_every_package_directory_is_shipped(name):
    # Parametrized by name so a failure says WHICH package would be missing
    # from the wheel, not merely that the sets differ. Checks the class, not
    # wj.transport specifically -- the next wj/foo/ must not sail past this.
    assert _resolves(name, _find_config()), (
        f"{name} exists in the source tree but pyproject.toml's "
        f"packages.find would not ship it; an installed build will fail to "
        f"import it")


def test_the_package_list_names_nothing_that_does_not_exist():
    # The other direction: a literal include entry that no longer corresponds
    # to a real directory is silent rot, and hides the fact that the list is
    # maintained by hand.
    find = _find_config()
    actual = set(_actual_packages())
    for pattern in find.get("include", []):
        if any(ch in pattern for ch in "*?["):
            continue  # a glob need not match anything in particular
        assert pattern in actual, (
            f"pyproject.toml lists {pattern!r}, which is not a package in this repo")
