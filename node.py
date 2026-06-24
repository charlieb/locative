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

from chain import TXChain
from transaction import Transaction


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
        self.chain.load(f"{self.name}_chain")

    def save_chain(self):
        self.chain.save(f"{self.name}_chain")

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
