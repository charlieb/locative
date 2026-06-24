from node import Node
from transaction import Transaction

import unittest


class TestNode(unittest.TestCase):

    def test_txes(self):
        node1 = Node("Node1")

        node2 = Node("Node2")

        # The pubkey is available from the reticulum announce data
        # Node1 requests tx with Node2
        req = node1.make_request(node2.pubkey.public_bytes_raw())
        node2.receive_request(req)
        rep = node2.make_reply()
        node1.recieve_reply(rep)
        # Node1 and Node2 now have the same chain
        # Node1: T1
        # Node2: T1
        self.assertEqual(node1.chain.txes, node2.chain.txes)

        # Node1 requests Node2 but doesn't get a reply
        req = node1.make_request(node2.pubkey.public_bytes_raw())
        node2.receive_request(req)
        rep = node2.make_reply()
        # node1.recieve_reply(rep)
        # Node1's chain is one tx shorter than Node2's
        # Node1: T1
        # Node2: T1 - T2
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
        self.assertEqual(node1.chain.txes[0], node2.chain.txes[0])
        self.assertNotEqual(node1.chain.txes[1], node2.chain.txes[1])
        self.assertEqual(node1.chain.txes[1], node2.chain.txes[2])

        # Make a bit more history to mess with
        req = node1.make_request(node2.pubkey.public_bytes_raw())
        # Transaction().from_request_bytes(req)
        node2.receive_request(req)
        rep = node2.make_reply()
        node1.recieve_reply(rep)
        # Node1: T1 - T3 - T4
        # Node2: T1 - (T2) - T3 - T4
        self.assertEqual(node1.chain.txes[0], node2.chain.txes[0])
        self.assertNotEqual(node1.chain.txes[1], node2.chain.txes[1])
        self.assertEqual(node1.chain.txes[1:], node2.chain.txes[2:])

        req = node1.make_request(node2.pubkey.public_bytes_raw())
        # Transaction().from_request_bytes(req)
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
        Transaction().from_request_bytes(req)
        node2.receive_request(req)
        rep = node2.make_reply()
        self.assertIsNone(rep)
        # node1.recieve_reply(rep)


if __name__ == "__main__":
    unittest.main()
