"""SNMP Enumeration scanner.

Provides SNMPv2c enumeration by trying common community strings
and querying standard system MIB OIDs.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

from ..core.interfaces import BaseScanner, Capability, ScanContext

logger = logging.getLogger(__name__)

# Common SNMP community strings to try.
_COMMUNITY_STRINGS: List[str] = ["public", "private", "community"]

# Standard system MIB OIDs.
_OIDS: Dict[str, str] = {
    "1.3.6.1.2.1.1.1.0": "system_description",  # sysDescr
    "1.3.6.1.2.1.1.3.0": "uptime",              # sysUpTime
    "1.3.6.1.2.1.1.5.0": "system_name",         # sysName
    "1.3.6.1.2.1.1.6.0": "location",            # sysLocation
}


class SNMPEnumerator(BaseScanner[dict]):
    """Enumerate system information via SNMP.

    Tries common community strings ("public", "private", "community")
    against the target on UDP port 161.  For the first successful
    community string, queries standard system MIB OIDs:

    - sysDescr  (1.3.6.1.2.1.1.1.0)
    - sysUpTime (1.3.6.1.2.1.1.3.0)
    - sysName   (1.3.6.1.2.1.1.5.0)
    - sysLocation (1.3.6.1.2.1.1.6.0)

    Returns a dict with keys: community_string, system_description,
    uptime, system_name, location.  Returns an empty dict on failure.

    Uses pysnmp-lextudio for async SNMP operations.
    Requires no special system capabilities.
    """

    @property
    def name(self) -> str:
        return "SNMPEnumerator"

    @property
    def required_capability(self) -> Capability:
        return Capability.NONE

    async def _execute(self, target: str, context: ScanContext, **kwargs: Any) -> dict:
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                getCmd,
            )
        except ImportError:
            try:
                # Fallback for older pysnmp import paths.
                from pysnmp.hlapi.asyncio import (  # type: ignore[no-redef]
                    CommunityData,
                    ContextData,
                    ObjectIdentity,
                    ObjectType,
                    SnmpEngine,
                    UdpTransportTarget,
                    getCmd,
                )
            except ImportError:
                logger.warning(
                    "pysnmp is not installed; SNMP enumeration unavailable"
                )
                return {}

        port: int = kwargs.get("port", 161)
        timeout_sec = min(context.timeout, 5.0)

        for community in _COMMUNITY_STRINGS:
            try:
                result = await self._try_community(
                    target,
                    port,
                    community,
                    timeout_sec,
                    getCmd,
                    SnmpEngine,
                    CommunityData,
                    UdpTransportTarget,
                    ContextData,
                    ObjectType,
                    ObjectIdentity,
                )
                if result:
                    result["community_string"] = community
                    return result
            except Exception as exc:
                logger.debug(
                    "SNMP community '%s' failed for %s: %s",
                    community,
                    target,
                    exc,
                )
                continue

        return {}

    async def _try_community(
        self,
        target: str,
        port: int,
        community: str,
        timeout_sec: float,
        getCmd,
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
    ) -> dict:
        """Attempt SNMP GET requests using a specific community string.

        Returns a dict of OID results if successful, empty dict otherwise.
        """
        engine = SnmpEngine()
        result: Dict[str, str] = {}

        # Build the list of ObjectType instances for all OIDs.
        oid_objects = [ObjectType(ObjectIdentity(oid)) for oid in _OIDS]

        try:
            error_indication, error_status, error_index, var_binds = await getCmd(
                engine,
                CommunityData(community),
                await UdpTransportTarget.create((target, port), timeout=timeout_sec, retries=1),
                ContextData(),
                *oid_objects,
            )
        except TypeError:
            # Older pysnmp versions use synchronous UdpTransportTarget construction.
            try:
                error_indication, error_status, error_index, var_binds = await getCmd(
                    engine,
                    CommunityData(community),
                    UdpTransportTarget((target, port), timeout=timeout_sec, retries=1),
                    ContextData(),
                    *oid_objects,
                )
            except Exception as exc:
                logger.debug("SNMP GET failed for community '%s': %s", community, exc)
                return {}

        if error_indication:
            logger.debug("SNMP error indication: %s", error_indication)
            return {}

        if error_status:
            logger.debug(
                "SNMP error status: %s at %s",
                error_status.prettyPrint(),
                error_index and var_binds[int(error_index) - 1][0] or "?",
            )
            return {}

        # Parse the variable bindings into our result dict.
        for var_bind in var_binds:
            oid_str = str(var_bind[0])
            value_str = str(var_bind[1])

            # Match the OID to our known mapping.
            for known_oid, field_name in _OIDS.items():
                if oid_str == known_oid or oid_str.startswith(known_oid):
                    result[field_name] = value_str
                    break

        if not result:
            return {}

        # Fill in any missing fields with empty strings.
        for field_name in _OIDS.values():
            result.setdefault(field_name, "")

        return result
