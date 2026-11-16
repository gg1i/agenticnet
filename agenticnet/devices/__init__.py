"""Device capability registry and verified Packet Tracer model specifications."""

from __future__ import annotations

from agenticnet.devices.catalog import DeviceCatalog
from agenticnet.devices.models import DeviceCapabilityReport, DeviceProfile, InterfaceTemplate

DEFAULT_CATALOG = DeviceCatalog()

__all__ = [
    "DEFAULT_CATALOG",
    "DeviceCapabilityReport",
    "DeviceCatalog",
    "DeviceProfile",
    "InterfaceTemplate",
]
