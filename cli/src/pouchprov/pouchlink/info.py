# Copyright (c) 2026 Jonathan Beri
# SPDX-License-Identifier: Apache-2.0
"""Pouch GATT info characteristic (src/transport/info.cddl).

    pouch_gatt_info = { "flags" => uint .size 1, "server_cert_snr" => bstr }

The device advertises whether it already holds a server certificate (so a
gateway knows whether to push one). For local provisioning the client
reads it to decide whether the server cert exchange is needed.
"""

from __future__ import annotations

from dataclasses import dataclass

import cbor2

# flags bit meanings are internal to pouch; we only need "has a server cert"
# which is conveyed by a non-empty server_cert_snr.


@dataclass
class GattInfo:
    flags: int
    server_cert_serial: bytes

    @property
    def has_server_cert(self) -> bool:
        return len(self.server_cert_serial) > 0

    @classmethod
    def decode(cls, data: bytes) -> "GattInfo":
        obj = cbor2.loads(data)
        return cls(flags=obj["flags"], server_cert_serial=bytes(obj.get("server_cert_snr", b"")))
