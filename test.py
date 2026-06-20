from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
)
from cryptography.hazmat.primitives import hashes


class Node:
    def __init__(self, name):
        self.name = name
        self.privkey = None
        self.pubkey = None
        self.chain = []

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

    def last_tx_with(self, node_id):
        return None

    def receive(self, packet: bytes):
        pkey_id: bytes = packet[0:32]
        tx_hash: bytes = packet[32:64]
        sig: bytes = packet[96:160]

        txn = self.last_tx_with(pkey_id)
        hash_ok = False
        if txn is None:
            hash_ok = True
        # TODO validate hash against last shared tx, or the one before

        pkey = Ed25519PublicKey.from_public_bytes(pkey_id)
        sig_ok = pkey.verify(sig, packet[0:96])

        print(
            f"Validation: hash: {'OK' if hash_ok else 'NOK'},"
            f" sig: {'OK' if sig_ok else 'NOK'}"
        )
        return hash_ok and sig_ok

    def request(self, node2_id):
        txn2 = self.last_tx_with(node2_id)
        if txn2 is None:
            txn2 = b"\0" * 32

        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.chain[-1] if self.chain != [] else b"\0" * 32)
        h_chain_end = digest.finalize()

        body = self.pubkey.public_bytes_raw() + txn2 + h_chain_end
        print(len(body))
        sig_n1 = self.privkey.sign(body)
        print(len(sig_n1))

        # print(f"Request: {body.decode('utf-8') + sig_n1.decode('utf-8')}")
        print(f"Request: {body + sig_n1}")
        return body + sig_n1


if __name__ == "__main__":
    node1 = Node("Node1")
    node2 = Node("Node2")

    # The pubkey is available from the reticulum announce data
    req = node1.request(node2.pubkey)
    node2.receive(req)
