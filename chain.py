from cryptography.hazmat.primitives.hashes import Hash, SHA256

from transaction import Transaction


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

    def drop_latest_t_n1n2(self, n1n2: bytes):
        if n1n2 not in self.t_n1n2:
            return
        self.t_n1n2[n1n2].pop(-1)

    def load(self, filename):
        sz = len(Transaction())
        with open(filename, "rb") as f:
            while tx_bytes := f.read(sz):
                tx = Transaction()
                tx.from_tx_bytes(tx_bytes)
                self.txes.append(tx)

    def save(self, filename):
        with open(filename, "wb") as f:
            for tx in self.txes:
                f.write(tx.to_tx_bytes())

    def validate(self):
        pass
