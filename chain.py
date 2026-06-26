from cryptography.hazmat.primitives.hashes import Hash, SHA256

from transaction import Transaction
import base64


def to_str(h):
    return base64.b64encode(h).decode("utf-8")


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

    def reset(self):
        self.txes = []
        self.t_n1n2 = {}

    def add(self, tx: Transaction, replace_latest=False):
        self.txes.append(tx)
        n1n2 = tx.n1_id + tx.n2_id
        if n1n2 in self.t_n1n2:
            if replace_latest:
                self.t_n1n2[n1n2][-1] = tx
            else:
                self.t_n1n2[n1n2].append(tx)
        else:
            self.t_n1n2[n1n2] = [tx]

    def latest_2_t_n1n2_hashes(self, n1n2: bytes):
        if n1n2 not in self.t_n1n2:
            return []
        if len(self.t_n1n2[n1n2]) <= 2:
            txes = self.t_n1n2[n1n2]
        else:
            txes = self.t_n1n2[n1n2][-2:]

        return [Hash.hash(SHA256(), tx.to_tx_bytes()) for tx in txes]

    def validate_h_t_n1n2(self, my_id: bytes, tx: Transaction):
        if my_id == tx.n1_id:
            n1n2 = my_id + tx.n1_id
        else:
            n1n2 = tx.n1_id + my_id

        h_t_n1n2s = self.latest_2_t_n1n2_hashes(n1n2)
        if not h_t_n1n2s:
            print("TXChain validate n1n2 hash: No prior transactions")
            return True
        else:
            hash_ok = h_t_n1n2s[-1] == tx.h_t_n1n2
            if hash_ok:
                print(
                    "TXChain validate n1n2 hash: Found valid prior transaction at head"
                )
                return True
            if len(h_t_n1n2s) == 2 and h_t_n1n2s[0] == tx.h_t_n1n2:
                # If 2nd hash is OK, we must remove the first one
                # but only from the n1n2 history, not the global
                # chain
                print("RCV: Found valid prior transaction at head-1, popping head")
                self.t_n1n2[n1n2].pop(-1)
                return True

        return False

    def validate_h_nX_chain(self, my_id: bytes, tx: Transaction):
        """Called h_nX_chain because we don't need to know which
        side of the transaction we are to validate this part
        of the tx"""
        h_nx_chain = Hash.hash(SHA256(), self.txes[-1].to_tx_bytes())
        return h_nx_chain == (tx.h_n1_chain if my_id == tx.n1_id else tx.h_n2_chain)

    def load(self, filename):
        self.reset()
        sz = len(Transaction())
        with open(filename, "rb") as f:
            while tx_bytes := f.read(sz):
                tx = Transaction()
                tx.from_tx_bytes(tx_bytes)
                self.add(tx)

    def save(self, filename):
        with open(filename, "wb") as f:
            for tx in self.txes:
                f.write(tx.to_tx_bytes())

    def validate(self, my_id: bytes):
        if self.txes == []:
            return True
        if self.txes[0].h_t_n1n2 != b"\0" * 32:
            return False

        tx = self.txes[0]
        last_h = Hash.hash(SHA256(), self.txes[0].to_tx_bytes())
        print(len(self.txes))
        for tx in self.txes[1:]:
            if not tx.validate_sigs():
                print("Chain validate: Transaction signature validation FAIL")
                return False
            print(f"Chain Last Hash: {to_str(last_h)}")
            print(f"Chain this Hash: {to_str(tx.h_n1_chain)}")
            print(f"Chain this Hash: {to_str(tx.h_n2_chain)}")
            this_h = tx.h_n1_chain if my_id == tx.n1_id else tx.h_n2_chain
            if this_h != last_h:
                print("Chain validate: Node chain validation FAIL")
                return False
            print("Chain validate: hash ok")
            last_h = Hash.hash(SHA256(), tx.to_tx_bytes())

        for t_n1n2s in self.t_n1n2.values():
            t_val = t_n1n2s[-1]
            two_back = False
            for t_n1n2 in t_n1n2s[-2::-1]:
                if t_val.h_t_n1n2 == Hash.hash(SHA256(), t_n1n2.to_tx_bytes()):
                    two_back = False
                    t_val = t_n1n2
                    continue
                if two_back:
                    print("Chain validate: N1N2 chain validation FAIL")
                    return False
                t_n1n2s.remove(t_n1n2)
                two_back = True

        return True
