from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
)
from cryptography.hazmat.primitives.hashes import Hash, SHA256
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


class TXChain:
    def __init__(self):
        self.txes = []
        self.t_n1n2 = {}

    def last(self):
        if self.txes == []:
            return None
        return self.txes[-1]

    def txes_with(self, n):
        if n not in self.t_n1n2:
            return None
        return self.t_n1n2[n]

    def add(self, tx, replace_latest=False):
        self.txes.append(tx)
        n1n2 = tx.n1_id + tx.n2_id
        if n1n2 in self.t_n1n2:
            if replace_latest:
                self.t_n1n2[n1n2][-1] = tx
            else:
                self.t_n1n2[n1n2].append(tx)
        else:
            self.t_n1n2[n1n2] = [tx]


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
            print(f"Failed to load keys for {self.name}, generating new keypair")
            self.new_keys()

        try:
            self.load_chain()
        except Exception as e:
            print(e)
            print(f"Failed to load chain for {self.name}")
            self.new_chain()

    def load_keys(self):
        with open(f"{self.name}_keys", "rb") as f:
            self.privkey = Ed25519PrivateKey.from_private_bytes(f.read(32))
            self.pubkey = Ed25519PublicKey.from_public_bytes(f.read(32))
            # TODO validate pubkey matches privkey
        keystr = self.pubkey.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        keystr = keystr.split("\n")[1]
        print(f"Loaded private key and public key: \n{keystr}")

    def new_keys(self):
        self.privkey = Ed25519PrivateKey.generate()
        self.pubkey = self.privkey.public_key()
        with open(f"{self.name}_keys", "wb") as f:
            f.write(self.privkey.private_bytes_raw())
            f.write(self.pubkey.public_bytes_raw())

    def load_chain(self):
        pass

    def receive_request(self, packet: bytes):
        tx = Transaction()
        tx.from_request_bytes(packet)

        t_n1n2s = self.chain.txes_with(tx.n1_id + self.pubkey.public_bytes_raw())
        hash_ok = False
        if not t_n1n2s:
            hash_ok = True
        else:
            print(f"RCV: Found {len(t_n1n2s)} prior transactions")
            h_t_n1n2 = Hash.hash(SHA256(), t_n1n2s[-1].to_tx_bytes())
            hash_ok = h_t_n1n2 == tx.h_t_n1n2
            if hash_ok:
                print(f"RCV: Found valid prior transaction at head")
            if not hash_ok and len(t_n1n2s) >= 2:
                h_t_n1n2 = Hash.hash(SHA256(), t_n1n2s[-2].to_tx_bytes())
                hash_ok = h_t_n1n2 == tx.h_t_n1n2
                # If 2nd hash is OK, we must remove the first one
                # but only from the n1n2 history, not the global
                # chain
                if hash_ok:
                    print(f"RCV: Found valid prior transaction at head-1, popping head")
                    t_n1n2s.pop(-1)

        pkey = Ed25519PublicKey.from_public_bytes(tx.n1_id)
        sig_ok = True
        try:
            pkey.verify(tx.n1_sig, tx.to_request_bytes(incl_sig=False))
        except InvalidSignature:
            sig_ok = False

        print(
            f"Validation: hash: {'OK' if hash_ok else 'NOK'},"
            f" sig: {'OK' if sig_ok else 'NOK'}"
        )
        if hash_ok and sig_ok:
            self.pending_tx = tx
        # else:
        #    print(tx.to_request_bytes())

        return hash_ok and sig_ok

    def recieve_reply(self, reply: bytes):
        self.pending_tx.from_reply_bytes(reply)

        pkey = Ed25519PublicKey.from_public_bytes(self.pending_tx_n2)
        try:
            pkey.verify(
                self.pending_tx.n2_sig, self.pending_tx.to_tx_bytes(incl_sig=False)
            )
            print("Reply OK - adding to chain")
            self.chain.add(self.pending_tx)
            self.pending_tx = None
            self.pending_tx_n2 = None
        except InvalidSignature:
            print("Reply NOK")
            return False

    def _make_h_my_chain(self):
        c_end = self.chain.last()
        if c_end:
            return Hash.hash(SHA256(), c_end.to_tx_bytes())
        else:
            return b"0" * 32

    def make_reply(self):
        if not self.pending_tx:
            return

        self.pending_tx.n2_id = self.pubkey.public_bytes_raw()
        self.pending_tx.h_n2_chain = self._make_h_my_chain()
        self.pending_tx.n2_sig = self.privkey.sign(
            self.pending_tx.to_tx_bytes(incl_sig=False)
        )

        self.chain.add(self.pending_tx)
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

        tx.h_n1_chain = self._make_h_my_chain()

        tx.n1_sig = self.privkey.sign(tx.to_request_bytes(incl_sig=False))
        self.pending_tx = tx
        self.pending_tx_n2 = node2_id

        # print(tx.to_request_bytes())
        return tx.to_request_bytes()


if __name__ == "__main__":
    node1 = Node("Node1")
    node2 = Node("Node2")

    # The pubkey is available from the reticulum announce data
    # Node1 requests tx with Node2
    req = node1.make_request(node2.pubkey.public_bytes_raw())
    Transaction().from_request_bytes(req)
    node2.receive_request(req)
    rep = node2.make_reply()
    node1.recieve_reply(rep)
    # Node1 and Node2 now have the same chain
    # Node1: T1
    # Node2: T1

    # Node1 requests Node2 but doesn't get a reply
    req = node1.make_request(node2.pubkey.public_bytes_raw())
    Transaction().from_request_bytes(req)
    node2.receive_request(req)
    rep = node2.make_reply()
    # node1.recieve_reply(rep)
    # Node1's chain is one tx shorter than Node2's
    # Node1: T1
    # Node2: T1 - T2

    # Node1 requests Node2, but it's not
    # using the tx that's at the head of
    # Node2's N1/N2 chain (or global chain for that matter)
    # Node2 must validate anyway and its chain
    # N1/N2 subchain should match Node1's afterwards because it's
    # supposed to look back 1 tx if necessary.
    # Node2's global chain must also retain the superceded
    # transaction even though it's a dead branch
    req = node1.make_request(node2.pubkey.public_bytes_raw())
    Transaction().from_request_bytes(req)
    node2.receive_request(req)
    rep = node2.make_reply()
    node1.recieve_reply(rep)
    # Node1: T1 - T3
    # Node2: T1 - (T2) - T3 # Denoting that T2 remains in Node2's global chain
    # but isn't part of the N1N2 subchain anymore

    # Make a bit more history to mess with
    req = node1.make_request(node2.pubkey.public_bytes_raw())
    Transaction().from_request_bytes(req)
    node2.receive_request(req)
    rep = node2.make_reply()
    node1.recieve_reply(rep)
    # Node1: T1 - T3 - T4
    # Node2: T1 - T3 - T4

    req = node1.make_request(node2.pubkey.public_bytes_raw())
    Transaction().from_request_bytes(req)
    node2.receive_request(req)
    rep = node2.make_reply()
    node1.recieve_reply(rep)
    # Node1: T1 - T3 - T4 - T5
    # Node2: T1 - T3 - T4 - T5

    # Remove 2 txes from Node1
    # This will create irreconsilable differences between
    # Node1 and Node2, any reqeusts from Node1 to Node2
    # will fail validation
    node1.chain.txes = node1.chain.txes[:-2]
    n1n2_key = node1.pubkey.public_bytes_raw() + node2.pubkey.public_bytes_raw()
    node1.chain.t_n1n2[n1n2_key] = node1.chain.t_n1n2[n1n2_key][:-2]
    # Node1: T1 - T3
    # Node2: T1 - T3 - T4 - T5
    req = node1.make_request(node2.pubkey.public_bytes_raw())
    Transaction().from_request_bytes(req)
    node2.receive_request(req)
    rep = node2.make_reply()
    print(rep is None)
    # node1.recieve_reply(rep)
