from cryptography.hazmat.primitives.hashes import Hash, SHA256

from transaction import Transaction
import base64


def to_str(h):
    return base64.b64encode(h).decode("utf-8")


class TXChain:
    def __init__(self):
        self.txes = []
        self.t_n1n2 = {}

    def __repr__(self):
        return "\n".join(to_str(tx.to_tx_bytes()) for tx in self.txes)

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

    def add(self, my_id: bytes, tx: Transaction):
        valid = self.validate_h_t_n1n2(my_id, tx)
        if not (valid and self.validate_h_nX_chain(my_id, tx) and tx.validate_sigs()):
            print(f"Chain Dropped {to_str(tx.n2_sig)}")
            return False

        self.txes.append(tx)
        n1n2 = tx.n1_id + tx.n2_id
        if n1n2 in self.t_n1n2:
            if valid == -2:
                # Matches the last but one so replace the last
                print(f"Chain Replaced {to_str(tx.n2_sig)}")
                self.t_n1n2[n1n2][-1] = tx
            else:
                print(f"Chain Appended {to_str(tx.n2_sig)}")
                self.t_n1n2[n1n2].append(tx)
        else:
            print(f"Chain Started  {to_str(tx.n2_sig)}")
            self.t_n1n2[n1n2] = [tx]

        return True

    def latest_2_t_n1n2_hashes(self, n1n2: bytes):
        if n1n2 not in self.t_n1n2:
            return []
        if len(self.t_n1n2[n1n2]) <= 2:
            txes = self.t_n1n2[n1n2]
        else:
            txes = self.t_n1n2[n1n2][-2:]

        return [Hash.hash(SHA256(), tx.to_tx_bytes()) for tx in txes]

    def validate_h_t_n1n2(self, my_id: bytes, tx: Transaction):
        """Validates tx's h_t_n1n2 field matches either the
        latest or latest but one transaction between N1 and N2.
        Note: N1-request->N2 is a different history from N2-request->N1.
        Returns falsy value if validation fails
        Returns the index of the matching tx if validation succeeds.
        This value will be indexed python style from the end and thus will
        be either -1 for the end or -2 for the last but one transaction.
        If there are no prior transactions stored pretend there is and
        it matches - return -1"""
        if my_id == tx.n1_id:
            n1n2 = my_id + tx.n2_id
        else:
            n1n2 = tx.n1_id + my_id

        h_t_n1n2s = self.latest_2_t_n1n2_hashes(n1n2)
        if not h_t_n1n2s:
            if tx.h_t_n1n2 == b"\0" * len(tx.h_t_n1n2):
                return -1
            return 0
        else:
            hash_ok = h_t_n1n2s[-1] == tx.h_t_n1n2
            if hash_ok:
                return -1
            if len(h_t_n1n2s) == 1 and tx.h_t_n1n2 == b"\0" * len(tx.h_t_n1n2):
                return -1
            if len(h_t_n1n2s) == 2 and h_t_n1n2s[0] == tx.h_t_n1n2:
                # If 2nd hash is OK, we must remove the first one
                # but only from the n1n2 history, not the global
                # chain
                return -2

        return False

    def validate_h_nX_chain(self, my_id: bytes, tx: Transaction):
        """Called h_nX_chain because we don't need to know which
        side of the transaction we are to validate this part
        of the tx"""
        my_hash = tx.h_n1_chain if my_id == tx.n1_id else tx.h_n2_chain
        if self.txes == [] and my_hash == b"\0" * len(tx.h_n1_chain):
            return True
        h_nx_chain = Hash.hash(SHA256(), self.txes[-1].to_tx_bytes())
        return h_nx_chain == my_hash

    def load(self, my_id: bytes, filename):
        self.reset()
        sz = len(Transaction())
        with open(filename, "rb") as f:
            while tx_bytes := f.read(sz):
                tx = Transaction()
                tx.from_tx_bytes(tx_bytes)
                self.add(my_id, tx)

    def save(self, filename):
        with open(filename, "wb") as f:
            for tx in self.txes:
                f.write(tx.to_tx_bytes())
