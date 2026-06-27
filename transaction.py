from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

import struct


class Transaction:
    Tx = struct.Struct("<32s32s32s64s32s32s64s")
    Req = struct.Struct("<32s32s32s64s")
    Rep = struct.Struct("<32s32s64s")

    def __init__(self):
        self.n1_id: bytes = b"\0" * 32
        self.h_t_n1n2: bytes = b"\0" * 32
        self.h_n1_chain: bytes = b"\0" * 32
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
            f"self.n2_id: {self.n2_id}\n"
            f"self.h_n2_chain: {self.h_n2_chain}\n"
            f"self.n2_sig: {self.n2_sig}\n"
        )

    def __eq__(self, other: Transaction):
        return self.to_tx_bytes() == other.to_tx_bytes()

    def __len__(self):
        return Transaction.Tx.size

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
            pkey.verify(self.n2_sig, self.to_tx_bytes(incl_sig=False))
            return True
        except InvalidSignature:
            return False

    def from_tx_bytes(self, tx):
        (
            self.n1_id,
            self.h_t_n1n2,
            self.h_n1_chain,
            self.n1_sig,
            self.n2_id,
            self.h_n2_chain,
            self.n2_sig,
        ) = Transaction.Tx.unpack(tx)
        return self

    def to_tx_bytes(self, incl_sig=True):
        return (
            self.n1_id
            + self.h_t_n1n2
            + self.h_n1_chain
            + self.n1_sig
            + self.n2_id
            + self.h_n2_chain
            + (self.n2_sig if incl_sig else b"")
        )

    def to_request_bytes(self, incl_sig=True):
        return (
            self.n1_id
            + self.h_t_n1n2
            + self.h_n1_chain
            + (self.n1_sig if incl_sig else b"")
        )

    def to_reply_bytes(self):
        return self.n2_id + self.h_n2_chain + self.n2_sig

    def from_request_bytes(self, req):
        self.n1_id, self.h_t_n1n2, self.h_n1_chain, self.n1_sig = (
            Transaction.Req.unpack(req)
        )

    def from_reply_bytes(self, rep):
        self.n2_id, self.h_n2_chain, self.n2_sig = Transaction.Rep.unpack(rep)
