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

        if app_data:
            RNS.log(
                "The announce contained the following app data: "
                + RNS.prettyhexrep(app_data)
            )
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

    def receive_announce(self, node_id, dest_hash):
        RNS.log(f"Got announce from Node: {RNS.prettyhexrep(node_id)}")
        # Create mapping between node_id and reticulum destination
        self.known_ids[node_id] = dest_hash

    def send_announce(self):
        self.destination.announce(app_data=self.node.pubkey.public_bytes_raw())
        RNS.log(f"Sent announce")

    def receive_packet(self, message, packet):
        if message[0] == b"Q":  # Request
            RNS.log("Received request.")
            if self.node.receive_request(message[1:]):
                self.send_reply()
            else:
                RNS.log("BAD request")

        elif message[0] == b"R":  # Reply
            pass

    def send_request(self, node_id):
        if node_id not in self.known_ids:
            RNS.log(
                f"Don't know where to send request for {RNS.prettyhexrep(node_id)}. Need announce."
            )
            return

        dest_hash = self.known_ids[node_id]
        if RNS.Transport.has_path(dest_hash):

            server_identity = RNS.Identity.recall(dest_hash)
            request_destination = RNS.Destination(
                server_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                APP_NAME,
            )

            # The destination is ready, so let's create a packet.
            # We set the destination to the request_destination
            # that was just created, and the only data we add
            # is a random hash.
            echo_request = RNS.Packet(
                request_destination, b"Q" + self.node.make_request(node_id)
            )

            # Send the packet! If the packet is successfully
            # sent, it will return a PacketReceipt instance.
            packet_receipt = echo_request.send()

            # Tell the user that the echo request was sent
            RNS.log(
                f"Sent locative request to {RNS.prettyhexrep(request_destination.hash)}"
            )

    def receive_request(self):
        pass

    def send_reply(self):
        if not self.node.pending_tx:
            return

        n2_id = self.node.pending_tx.n2_id
        if not (dest := self.known_ids.get(n2_id)):
            RNS.log(
                f"Don't know where to send reply for {RNS.prettyhexrep(n2_id)}. Need announce."
            )
            return

        reply = RNS.Packet(dest, b"R" + self.node.make_reply())
        reply.send()
        RNS.log(f"Sent locative reply to {RNS.prettyhexrep(dest.hash)}")

    def recieve_reply(self):
        pass

    def mainloop(self):
        while True:
            print("[A]nnounce or [R]equest, or [X] Quit")
            cmd = input()
            if cmd in ["A", "a", "ann"]:
                self.send_announce()
            elif cmd in ["q", "Q", "req"]:
                self.send_request(self.known_ids[-1])
            elif cmd in ["x", "X", "quit"]:
                return
            # Replying should be automatic


def main():
    node = Node("Node1")
    # node2 = Node("Node2")

    node.chain.reset()
    Locative(node).mainloop()


if __name__ == "__main__":
    main()
