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

    def load(self, filename):
        sz = Transaction().len()
        with open(filename, "rb") as f:
            while not f.eof():
                tx = Transaction()
                tx.from_tx_bytes(f.read(sz))
                self.txes.append(tx)

    def save(self, filename):
        with open(filename, "wb") as f:
            for tx in self.txes:
                f.write(tx.to_tx_bytes())

    def validate(self):
        pass
