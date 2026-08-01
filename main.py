import argparse
import sys
import RNS

from node import Node
from transaction import Transaction

import base64


def to_str(h):
    return base64.b64encode(h).decode("utf-8")


APP_NAME = "locative"


class LocativeAnnounceHandler:
    def __init__(self, announce_cbs=[]):
        self.aspect_filter = APP_NAME
        self.announce_cbs = announce_cbs

    # This method will be called by Reticulums Transport
    # system when an announce arrives that matches the
    # configured aspect filter. Filters must be specific,
    # and cannot use wildcards.
    def received_announce(self, destination_hash, announced_identity, app_data):
        RNS.log("Received an announce from " + RNS.prettyhexrep(destination_hash))

        for cb in self.announce_cbs:
            cb(app_data, destination_hash)


class Locative:
    def __init__(self, node):
        self.node = node
        self.known_ids = {}

        # We must first initialise Reticulum
        self.reticulum = RNS.Reticulum()

        # Randomly create a new identity for our echo server
        self.rns_identity = RNS.Identity()

        # We register the announce handler with Reticulum
        RNS.Transport.register_announce_handler(
            LocativeAnnounceHandler([self.receive_announce])
        )
        # Register the incoming packet handler
        self.destination = RNS.Destination(
            self.rns_identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            APP_NAME,
        )
        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        self.destination.set_packet_callback(self.receive_packet)

        # We override the loglevel to provide feedback when
        # an announce is received
        if RNS.loglevel < RNS.LOG_INFO:
            RNS.loglevel = RNS.LOG_INFO

    def list_transactions(self):
        print(f"Transaction Partners:\n{self.node.chain.report()}")

    def ask_id(self):
        ids = [
            nid
            for nid in self.node.chain.get_known_ids()
            if nid != self.node.pubkey.public_bytes_raw()
        ]
        print("\n".join(f"[{i+1}]: {to_str(nid)}" for i, nid in enumerate(ids)))
        print("Please enter the number of the ID to send a request to.")
        try:
            id_idx = int(input())
        except ValueError:
            print("Not a valid selection: did not enter a number")
            return

        if 1 > id_idx or id_idx >= len(ids):
            print("Not a valid selection: number not in list")
            return

        return ids[id_idx - 1]

    def receive_announce(self, node_id, dest_hash):
        RNS.log(f"Got announce from Node: {to_str(node_id)}")
        # Create mapping between node_id and reticulum destination
        self.known_ids[node_id] = dest_hash

    def send_announce(self):
        self.destination.announce(app_data=self.node.pubkey.public_bytes_raw())
        RNS.log(f"Sent announce")

    def receive_packet(self, message, packet):
        print(f"Packet Received: {RNS.prettyhexrep(message)}")
        if message[0] == ord("Q"):  # Request
            RNS.log("Received request.")
            if self.node.receive_request(message[1:]):
                self.send_reply()
            else:
                RNS.log("BAD request")

        elif message[0] == ord("R"):  # Reply
            self.recieve_reply(message[1:])

    def send_request(self, node_id):
        if node_id not in self.known_ids:
            RNS.log(
                f"Don't know where to send request for {to_str(node_id)}. Need announce."
            )
            return

        dest_hash = self.known_ids[node_id]
        if not RNS.Transport.has_path(dest_hash):
            RNS.log(f"No transport path to {RNS.prettyhexrep(dest_hash)}.")
            return

        server_id = RNS.Identity.recall(dest_hash)
        dest = RNS.Destination(
            server_id,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            APP_NAME,
        )

        RNS.Packet(dest, b"Q" + self.node.make_request(node_id)).send()
        RNS.log(f"Sent locative request to {RNS.prettyhexrep(dest.hash)}")

    def send_reply(self):
        if not self.node.pending_tx:
            return

        node_id = self.node.pending_tx.n1_id
        if not (dest_hash := self.known_ids.get(node_id)):
            RNS.log(
                f"Don't know where to send reply for {to_str(node_id)}. Need announce."
            )
            return

        server_id = RNS.Identity.recall(dest_hash)
        dest = RNS.Destination(
            server_id,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            APP_NAME,
        )

        RNS.Packet(dest, b"R" + self.node.make_reply()).send()
        RNS.log(f"Sent locative reply to [ERROR]")
        RNS.log(f"Sent locative reply to {RNS.prettyhexrep(dest.hash)}")

    def receive_reply(self, reply):
        self.node.receive_reply(reply)

    def mainloop(self):
        while True:
            print("[A]nnounce or [R]equest, [L]ist or [Q]uit")
            cmd = input()
            if cmd in ["A", "a", "ann"]:
                self.send_announce()
            elif cmd in ["r", "R", "req"]:
                nid = self.ask_id()
                if nid is not None:
                    self.send_request(nid)
            elif cmd in ["l", "L", "list"]:
                self.list_transactions()
            elif cmd in ["q", "Q", "quit"]:
                return
            # Replying should be automatic


def main():
    node = Node("Node1")
    Locative(node).mainloop()


if __name__ == "__main__":
    main()
