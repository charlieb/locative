from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

import io
import struct


class Transaction:
    Req = struct.Struct("<32s32s32s1s")
    Rep = struct.Struct("<32s32s64s")
    # Total size here is 278 bytes
    # Reticulum packet size (- header) is 477
    # Leaving 199 bytes for a variable payload data
    # 1 byte for length and the rest possibly for data

    max_data_len = 198  # bytes

    def __init__(self):
        self.n1_id: bytes = b"\0" * 32
        self.h_t_n1n2: bytes = b"\0" * 32
        self.h_n1_chain: bytes = b"\0" * 32
        self.data_len: bytes = b"\0"
        self.data: bytes = b""
        self.n1_sig: bytes = b"\0" * 64
        self.n2_id: bytes = b"\0" * 32
        self.h_n2_chain: bytes = b"\0" * 32
        self.n2_sig: bytes = b"\0" * 64

    def __repr__(self):
        return (
            f"self.n1_id: {self.n1_id}\n"
            f"self.h_t_n1n2: {self.h_t_n1n2}\n"
            f"self.h_n1_chain: {self.h_n1_chain}\n"
            f"self.n1_sig: {self.n1_sig}\n"
            f"self.data_len: {self.data_len}\n"
            f"self.data: {self.data}\n"
            f"self.n2_id: {self.n2_id}\n"
            f"self.h_n2_chain: {self.h_n2_chain}\n"
            f"self.n2_sig: {self.n2_sig}\n"
        )

    def __eq__(self, other):
        return self.to_tx_bytes() == other.to_tx_bytes()

    def __len__(self):
        return Transaction.Req.size + Transaction.Rep.size + self.data_len[0]

    def validate_sigs(self):
        return self.validate_req_sig() and self.validate_tx_sig()

    def validate_req_sig(self):
        pkey = Ed25519PublicKey.from_public_bytes(self.n1_id)
        try:
            pkey.verify(self.n1_sig, self.to_request_bytes(incl_sig=False))
            return True
        except InvalidSignature:
            return False

    def validate_tx_sig(self):
        pkey = Ed25519PublicKey.from_public_bytes(self.n2_id)
        try:
            pkey.verify(self.n2_sig, self.to_tx_bytes(incl_reply_sig=False))
            return True
        except InvalidSignature:
            return False

    def read_tx(self, f: io.BytesIO):
        req = f.read(self.Req.size)
        if len(req) != self.Req.size:
            return None
        self.n1_id, self.h_t_n1n2, self.h_n1_chain, self.data_len = self.Req.unpack(req)

        self.data = f.read(self.data_len[0])
        if len(self.data) != self.data_len[0]:
            return None

        self.n1_sig = f.read(64)
        if len(self.n1_sig) != 64:
            return None

        rep = f.read(self.Rep.size)
        if len(rep) != self.Rep.size:
            return None

        self.from_reply_bytes(rep)
        return self

    def from_tx_bytes(self, tx):
        self.from_request_bytes(tx)
        self.from_reply_bytes(tx[self.Req.size + self.data_len[0] + 64 :])
        return self

    def to_tx_bytes(self, incl_reply_sig=True):
        return self.to_request_bytes() + self.to_reply_bytes(incl_reply_sig)

    def to_request_bytes(self, incl_sig=True):
        return (
            self.n1_id
            + self.h_t_n1n2
            + self.h_n1_chain
            + self.data_len
            + self.data[: self.data_len[0]]
            + (self.n1_sig if incl_sig else b"")
        )

    def to_reply_bytes(self, incl_sig=True):
        return self.n2_id + self.h_n2_chain + (self.n2_sig if incl_sig else b"")

    def from_request_bytes(self, req):
        self.n1_id, self.h_t_n1n2, self.h_n1_chain, self.data_len = self.Req.unpack(
            req[: self.Req.size]
        )

        self.data = req[self.Req.size : self.Req.size + self.data_len[0]]
        self.n1_sig = req[
            self.Req.size + self.data_len[0] : self.Req.size + self.data_len[0] + 64
        ]

    def from_reply_bytes(self, rep):
        self.n2_id, self.h_n2_chain, self.n2_sig = self.Rep.unpack(rep)
