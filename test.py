from node import Node
from transaction import Transaction
import os

import unittest

import base64


def to_str(h):
    return base64.b64encode(h).decode("utf-8")


def mk_tx_between(node1, node2, drop_reply=False):
    req = node1.make_request(node2.pubkey.public_bytes_raw())
    node2.receive_request(req)
    rep = node2.make_reply()
    if not drop_reply:
        node1.recieve_reply(rep)
    return req + rep


class TestNode(unittest.TestCase):

    def setUp(self):
        try:
            os.remove("Node1_chain")
        except FileNotFoundError:
            pass
        try:
            os.remove("Node2_chain")
        except FileNotFoundError:
            pass

    def test_txes(self):
        node1 = Node("Node1")
        node2 = Node("Node2")

        node1.chain.reset()
        node2.chain.reset()
        n1n2_id = node1.pubkey.public_bytes_raw() + node2.pubkey.public_bytes_raw()

        # The pubkey is available from the reticulum announce data
        # Node1 requests tx with Node2
        req = node1.make_request(node2.pubkey.public_bytes_raw())
        node2.receive_request(req)
        rep = node2.make_reply()
        node1.recieve_reply(rep)
        # Node1 and Node2 now have the same chain
        # Node1: T1
        # Node2: T1
        # print(len(node1.chain.txes), len(node2.chain.txes))
        # print(len(node1.chain.t_n1n2[n1n2_id]), len(node2.chain.t_n1n2[n1n2_id]))
        ## print(node1.chain, "\n----------\n", node2.chain, "\n============\n")

        self.assertEqual(node1.chain.txes, node2.chain.txes)

        # Node1 requests Node2 but doesn't get a reply
        req = node1.make_request(node2.pubkey.public_bytes_raw())
        node2.receive_request(req)
        rep = node2.make_reply()
        # node1.recieve_reply(rep)
        # Node1's chain is one tx shorter than Node2's
        # Node1: T1
        # Node2: T1 - T2
        # print(len(node1.chain.txes), len(node2.chain.txes))
        # print(len(node1.chain.t_n1n2[n1n2_id]), len(node2.chain.t_n1n2[n1n2_id]))
        # print(node1.chain, "\n----------\n", node2.chain, "\n============\n")
        self.assertEqual(len(node1.chain.txes), 1)
        self.assertEqual(len(node2.chain.txes), 2)

        # Node1 requests Node2, but it's not
        # using the tx that's at the head of
        # Node2's N1/N2 chain (or global chain for that matter)
        # Node2 must validate anyway and its chain
        # N1/N2 subchain should match Node1's afterwards because it's
        # supposed to look back 1 tx if necessary.
        # Node2's global chain must also retain the superceded
        # transaction even though it's a dead branch
        req = node1.make_request(node2.pubkey.public_bytes_raw())
        node2.receive_request(req)
        rep = node2.make_reply()
        node1.recieve_reply(rep)
        # Node1: T1 - T3
        # Node2: T1 - (T2) - T3 # Denoting that T2 remains in Node2's global chain
        # but isn't part of the N1N2 subchain anymore
        # print(len(node1.chain.txes), len(node2.chain.txes))
        # print(len(node1.chain.t_n1n2[n1n2_id]), len(node2.chain.t_n1n2[n1n2_id]))
        # print(node1.chain, "\n----------\n", node2.chain, "\n============\n")
        self.assertEqual(node1.chain.txes[0], node2.chain.txes[0])
        self.assertNotEqual(node1.chain.txes[1], node2.chain.txes[1])
        self.assertEqual(node1.chain.txes[1], node2.chain.txes[2])

        # Make a bit more history to mess with
        req = node1.make_request(node2.pubkey.public_bytes_raw())
        node2.receive_request(req)
        rep = node2.make_reply()
        node1.recieve_reply(rep)
        # Node1: T1 - T3 - T4
        # Node2: T1 - (T2) - T3 - T4
        # print(len(node1.chain.txes), len(node2.chain.txes))
        # print(len(node1.chain.t_n1n2[n1n2_id]), len(node2.chain.t_n1n2[n1n2_id]))
        # print(node1.chain, "\n----------\n", node2.chain, "\n============\n")
        self.assertEqual(node1.chain.txes[0], node2.chain.txes[0])
        self.assertNotEqual(node1.chain.txes[1], node2.chain.txes[1])
        self.assertEqual(node1.chain.txes[1:], node2.chain.txes[2:])

        req = node1.make_request(node2.pubkey.public_bytes_raw())
        node2.receive_request(req)
        rep = node2.make_reply()
        node1.recieve_reply(rep)
        # Node1: T1 - T3 - T4 - T5
        # Node2: T1 - (T2) - T3 - T4 - T5

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
        node2.receive_request(req)
        rep = node2.make_reply()
        # print(len(node1.chain.txes), len(node2.chain.txes))
        # print(len(node1.chain.t_n1n2[n1n2_id]), len(node2.chain.t_n1n2[n1n2_id]))
        # print(node1.chain, "\n----------\n", node2.chain, "\n============\n")
        self.assertIsNone(rep)
        # node1.recieve_reply(rep)

    def test_txes_3_nodes(self):
        node1 = Node("Node1")
        node2 = Node("Node2")
        node3 = Node("Node3")

        mk_tx_between(node1, node2)
        mk_tx_between(node1, node3)
        mk_tx_between(node2, node3)
        mk_tx_between(node2, node1)
        mk_tx_between(node3, node1)
        mk_tx_between(node1, node2)
        mk_tx_between(node3, node3)  # this should be ignored
        # Not that self requests are explicitly forbidden,
        # rather that they are prevented by the strict ordering
        # imposed by the request/response pairing.

        # >N2 requested N2, <N2 reqeusted by N2
        # Node1 - >N2 >N3 <N2 <N3 >N2
        # Node2 - <N1 >N3 >N1 <N1
        # Node3 - <N1 <N2 >N1
        n1k = node1.pubkey.public_bytes_raw()
        n2k = node2.pubkey.public_bytes_raw()
        n3k = node3.pubkey.public_bytes_raw()

        self.assertEqual(node1.chain.txes[0].n2_id, n2k)
        self.assertEqual(node1.chain.txes[1].n2_id, n3k)
        self.assertEqual(node1.chain.txes[2].n1_id, n2k)
        self.assertEqual(node1.chain.txes[3].n1_id, n3k)
        self.assertEqual(node1.chain.txes[4].n2_id, n2k)

        self.assertEqual(node2.chain.txes[0].n1_id, n1k)
        self.assertEqual(node2.chain.txes[1].n2_id, n3k)
        self.assertEqual(node2.chain.txes[2].n2_id, n1k)
        self.assertEqual(node2.chain.txes[3].n1_id, n1k)

        self.assertEqual(node3.chain.txes[0].n1_id, n1k)
        self.assertEqual(node3.chain.txes[1].n1_id, n2k)
        self.assertEqual(node3.chain.txes[2].n2_id, n1k)

    def test_chain_save_load(self):
        node1 = Node("Node1")
        node2 = Node("Node2")
        node3 = Node("Node3")

        node1.chain.reset()
        node2.chain.reset()
        node3.chain.reset()

        mk_tx_between(node1, node2)
        mk_tx_between(node1, node3)
        mk_tx_between(node2, node3)
        mk_tx_between(node2, node1)
        mk_tx_between(node3, node1)
        mk_tx_between(node1, node2)

        node1.save_chain()
        n1_chain = node1.chain.txes
        node1.load_chain()

        self.assertEqual(n1_chain, node1.chain.txes)

        os.remove("Node1_chain")

    def test_chain_bad_save_load(self):
        node1 = Node("Node1")
        node2 = Node("Node2")

        node1.chain.reset()
        node2.chain.reset()

        t1 = mk_tx_between(node1, node2)
        t2 = mk_tx_between(node1, node2)
        t3 = mk_tx_between(node1, node2, drop_reply=True)
        t4 = mk_tx_between(node1, node2)
        t5 = mk_tx_between(node1, node2, drop_reply=True)
        t6 = mk_tx_between(node1, node2)
        t7 = mk_tx_between(node1, node2)
        t8 = mk_tx_between(node1, node2, drop_reply=True)

        # N1's chain is all the transactions that didn't get dropped
        n1_chain = [Transaction().from_tx_bytes(tx) for tx in [t1, t2, t4, t6, t7]]
        # N2's chain is all the transactions
        n2_chain = [
            Transaction().from_tx_bytes(tx) for tx in [t1, t2, t3, t4, t5, t6, t7, t8]
        ]

        self.assertEqual(node1.chain.txes, n1_chain)
        self.assertEqual(node2.chain.txes, n2_chain)

        print("=====================================================================")
        n1n2 = node1.pubkey.public_bytes_raw() + node2.pubkey.public_bytes_raw()
        # Node2's n1n2 chain has an extra tx, the one that Node1 didn't get
        # and wasn't superceded by annother tx
        # for tx in node1.chain.txes:
        #     print(to_str(tx.n2_sig))
        # print("--------------------")
        # for tx in node1.chain.t_n1n2[n1n2]:
        #     print(to_str(tx.n2_sig))
        for tx in node2.chain.txes:
            print(to_str(tx.n2_sig))
        print("--------------------")
        for tx in node2.chain.t_n1n2[n1n2]:
            print(to_str(tx.n2_sig))
        self.assertEqual(node1.chain.t_n1n2[n1n2], node2.chain.t_n1n2[n1n2][:-1])

        # node1.save_chain()
        node2.save_chain()
        print("=====================================================================")
        # node1.load_chain()
        node2.load_chain()

        # self.assertEqual(node1.chain.txes, n1_chain)
        # self.assertEqual(node2.chain.txes, n2_chain)

        n1n2 = node1.pubkey.public_bytes_raw() + node2.pubkey.public_bytes_raw()
        # Node2's n1n2 chain has an extra tx, the one that Node1 didn't get
        # and wasn't superceded by annother tx
        # for tx in node1.chain.txes:
        #     print(to_str(tx.n2_sig))
        # print("--------------------")
        # for tx in node1.chain.t_n1n2[n1n2]:
        #     print(to_str(tx.n2_sig))
        for tx in node2.chain.txes:
            print(to_str(tx.n2_sig))
        print("--------------------")
        for tx in node2.chain.t_n1n2[n1n2]:
            print(to_str(tx.n2_sig))

        self.assertEqual(node1.chain.t_n1n2[n1n2], node2.chain.t_n1n2[n1n2][:-1])


if __name__ == "__main__":
    unittest.main()
