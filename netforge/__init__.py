"""Backward-compatibility shim aliasing legacy `netforge.*` imports to `agenticnet.*`."""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
from collections.abc import Sequence
from types import ModuleType

import agenticnet
from agenticnet import __schema_version__, __version__

__all__ = ["__schema_version__", "__version__"]


class _NetForgeCompatLoader(importlib.abc.Loader):
    def __init__(self, fullname: str, target_name: str) -> None:
        self._fullname = fullname
        self._target_name = target_name

    def exec_module(self, module: ModuleType) -> None:
        target_mod = importlib.import_module(self._target_name)
        sys.modules[self._fullname] = target_mod


class _NetForgeCompatFinder(importlib.abc.MetaPathFinder):
    """Redirect `netforge.<submod>` imports to `agenticnet.<submod>`."""

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if fullname == "netforge.__main__" or not fullname.startswith("netforge."):
            return None
        target_name = "agenticnet." + fullname.removeprefix("netforge.")
        target_spec = importlib.util.find_spec(target_name)
        if target_spec is None:
            return None
        spec = importlib.machinery.ModuleSpec(
            name=fullname,
            loader=_NetForgeCompatLoader(fullname, target_name),
            origin=target_spec.origin,
            is_package=target_spec.submodule_search_locations is not None,
        )
        if target_spec.submodule_search_locations is not None:
            spec.submodule_search_locations = list(target_spec.submodule_search_locations)
        return spec


if not any(isinstance(finder, _NetForgeCompatFinder) for finder in sys.meta_path):
    sys.meta_path.insert(0, _NetForgeCompatFinder())


def __getattr__(name: str) -> object:
    if hasattr(agenticnet, name):
        return getattr(agenticnet, name)
    target_name = f"agenticnet.{name}"
    try:
        mod = importlib.import_module(target_name)
    except ModuleNotFoundError as exc:
        if exc.name == target_name:
            raise AttributeError(f"module 'netforge' has no attribute '{name}'") from exc
        raise
    sys.modules[f"netforge.{name}"] = mod
    globals()[name] = mod
    return mod
