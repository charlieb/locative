from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.primitives.hashes import Hash, SHA256

from chain import TXChain
from transaction import Transaction

import base64


def to_str(h):
    return base64.b64encode(h).decode("utf-8")


class Node:
    def __init__(self, name):
        self.name = name
        self.privkey = None
        self.pubkey = None
        self.chain = TXChain()
        self.pending_tx = None
        self.pending_tx_n2 = None

        try:
            self.load_keys()
        except Exception as e:
            print(e)
            print(f"Failed to load keys for {self.name}, generating new keypair.")
            self.new_keys()

        try:
            self.load_chain()
        except Exception as e:
            print(e)
            print(f"Failed to load chain for {self.name}, using default empty chain.")
            self.chain = TXChain()

    def load_keys(self):
        with open(f"{self.name}_keys", "rb") as f:
            self.privkey = Ed25519PrivateKey.from_private_bytes(f.read(32))
            self.pubkey = Ed25519PublicKey.from_public_bytes(f.read(32))
            pubkey = self.privkey.public_key()
            if pubkey.public_bytes_raw() == self.pubkey.public_bytes_raw():
                print(
                    "ERROR: public key does not match private key - corrupted keypair"
                )
            return
        print(
            f"Loaded private key and public key: \n{to_str(self.pubkey.public_bytes_raw())}"
        )

    def new_keys(self):
        self.privkey = Ed25519PrivateKey.generate()
        self.pubkey = self.privkey.public_key()
        with open(f"{self.name}_keys", "wb") as f:
            f.write(self.privkey.private_bytes_raw())
            f.write(self.pubkey.public_bytes_raw())

    def load_chain(self):
        self.chain.load(self.pubkey.public_bytes_raw(), f"{self.name}_chain")

    def save_chain(self):
        self.chain.save(f"{self.name}_chain")

    def receive_request(self, packet: bytes):
        if self.pending_tx:
            print("Received Request while waiting for a reply - ignoring request.")
            return False

        tx = Transaction()
        tx.from_request_bytes(packet)
        hash_ok = bool(self.chain.validate_h_t_n1n2(self.pubkey.public_bytes_raw(), tx))
        sig_ok = tx.validate_req_sig()

        print(
            f"RCV: Validation: hash: {'OK' if hash_ok else 'NOK'},"
            f" sig: {'OK' if sig_ok else 'NOK'}"
        )

        if hash_ok and sig_ok:
            self.pending_tx = tx

        return hash_ok and sig_ok

    def recieve_reply(self, reply: bytes):
        if not self.pending_tx:
            print("REQ: Received reply for unknown request - ignoring reply")
            return False

        reply_part = Transaction()
        reply_part.from_reply_bytes(reply)
        if reply_part.n2_id != self.pending_tx_n2:
            print("REQ: Received reply from wrong node - ignoring reply")
            return False

        self.pending_tx.from_reply_bytes(reply)
        print("REQ: Reply from right ID - attempt add to chain")
        if self.chain.add(self.pubkey.public_bytes_raw(), self.pending_tx):
            self.pending_tx = None
            self.pending_tx_n2 = None
            return True
        return False

    def _make_h_my_chain(self):
        c_end = self.chain.last()
        if c_end:
            return Hash.hash(SHA256(), c_end.to_tx_bytes())
        else:
            return b"\0" * 32

    def make_reply(self):
        if not self.pending_tx:
            return

        self.pending_tx.n2_id = self.pubkey.public_bytes_raw()
        self.pending_tx.h_n2_chain = self._make_h_my_chain()
        self.pending_tx.n2_sig = self.privkey.sign(
            self.pending_tx.to_tx_bytes(incl_sig=False)
        )
        print("RCV: Adding reply to chain")
        self.chain.add(self.pubkey.public_bytes_raw(), self.pending_tx)
        self.pending_tx = None
        self.pending_tx_n2 = None  # probably unnecessary
        return self.chain.last().to_reply_bytes()

    def make_request(self, node2_id: bytes):
        tx = Transaction()
        tx.n1_id = self.pubkey.public_bytes_raw()

        t_n1n2s = self.chain.txes_with(self.pubkey.public_bytes_raw() + node2_id)
        # If there isn't one, the default 32 zero bytes is
        # correct per spec.
        if t_n1n2s:
            print(f"REQ: Found {len(t_n1n2s)} prior transactions")
            tx.h_t_n1n2 = Hash.hash(SHA256(), t_n1n2s[-1].to_tx_bytes())
        else:
            print("REQ: Found no prior transactions")

        tx.h_n1_chain = self._make_h_my_chain()

        tx.n1_sig = self.privkey.sign(tx.to_request_bytes(incl_sig=False))
        self.pending_tx = tx
        self.pending_tx_n2 = node2_id

        # print(tx.to_request_bytes())
        return tx.to_request_bytes()
