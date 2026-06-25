Locative
========

Locative is a node collecting game on the reticulum network. Players visit nodes and receive crytographically verifiable tokens from the fixed nodes that can be used to concoct a score. The tokens on both the player (mobile loci) and the nodes (fixed loci) form a cryptographic chain that in aggregate forms a verifiable web of accumulating trust.

Note: this document makes a distinction between players (mobile loci) and nodes (fixed loci). This distinction is a convenient fiction as both mobile and fixed loci will use the same set of algorithms for requests, replies, chain and identity management. The only concrete difference will be that fixed loci will not actively make requests. Mobile loci should be able to both make requests and recieve requests from other loci if desired.

Each loci will maintain a hash-chain containing all the complete transactions it has sent or recieved. Within that chain (called the global chain) will be a series of transactions between a specific loci pair. This series of transactions is also linked to each other. We therefore maintain, in the same single chain, both a chain of all transactions, and within that global chain, a chain of specific loci pair transactions. Both the global chain and the loci pair sub-chains are independently and co-verifiable.

What Happens When a Player Visits a Node?
-----------------------------------------

The Player will create a request and send it to the node. The request will be cryptographically derived from the player's chain global chain as well as the sub-chain of transactions between the node and the player.

The Node recieves this request, validates it against its Player/Node sub-chain and creates a reply that is derived from the request as well as the Node's global chain. The request and reply together form a complete transaction that is added to both the Player and Node's hash-chains. In this way Player/Node transactions are linked to each other as well as being linked to the global chains of the loci that participated in the transaction.

Naming Conventions in this Document
===================================

N1, Node1, Player, mobile loci : the node that is making a request
N1-ID : the public key that identifies Node1
N2, or Node2, node, fixed loci : the node that is receiving and replying to the request
T-N1/N2 : a completed transaction between Node1 and Node2, the lastest transaction in a node's chain unless otherwise stated.
H- : a prefix denoting a SHA256 digest of the prefixed item e.g. H-T-N1/N2 is a hash of a transaction between N1 and N2.
N1-Chain : the head of N1's chain of all transactions, N2-Chain is the same thing for N2's chain.
N1 SIG : a signature using N1's private key, N2 SIG would denote a signature using N2's private key. The data that is hashed is specified in the text.

Global chain vs Nx/Ny chain - the global chain is a chain of /all/ transactions completed by that node. Within that chain are distributed transactions specifically between Nx and Ny that when take on their own form the Nx/Ny chain. Note this is not two separate chains but rather a single chain that contains transactions that when considered on their own form their own chain.

Keys and Algorithms
===================

A new node will generate a new Ed25519 keypair specifically for Locative. The public key is the Locative ID for that node and the private keys is the signing key for all signatures used in this game.
Hashes will use SHA-256.

The Structure of a Transaction
================================

The request and the reply together form a single transaction. Without both parts the transacton is incomplete. Handling dropped replies will be explained below.
Node in the following diagram is interchanable with Player.

Two nodes N1 the requestor and N2 the responder:

The request:
| N1-ID | H-T-N1/N2 | H-N1-Chain | N1-SIG |

The response:
| N2-ID | H-N2-Chain | N2-SIG |

* N1 and N2 ID - the public key of the respective node Note: this keypair is generated specifically for the game identity and does not have a relationship to the reticulum address of any specific node.
* H-T-N1/N2 - the hash of the previous TX between N1 and N2, that exists in N1's chain. If it does not exist it should be all zeros.
* H-N1 or N2-Chain - the head of the respective node's global chain, that is the chain of all the nodes transactions. If it is the first element in the chain it should be all zeros.
* N1-SIG - the signature using N1's key of the preceeding fields in N1's request.
* N2-SIG - the signature using N2's key of the preceeding fields in BOTH N1's complete request and N2's reply.

Note that the response does not contain the H-N1/N2 field. N2's chain should contain exactly the same record. N2's signature of the request and response is an acknowledgement of that fact. See the Transaction Validation section for more information.

The complete transaction, recorded identically by both N1 and N2, is the concatenation of both request and reply:
| N1-ID | H-N1/N2 | H-N1-Chain | N1-SIG | N2-ID | H-N2-Chain | N2-SIG |

Transaction Validation
======================

When N2 receives a request from N1.
N2 uses the N1-ID field to find the latest complete transaction (T-N1/N2) it has in its chain with N1.
It constructs H-T-N1/N2 by hashing the T-N1/T2 from its chain with the SHA256 algorithm.
If N1's sent H-T-N1/N2 matches the one constructed by N2, that part of the transaction is considered valid.
If they do not match, N2 find the prior transaction with N1 (T(n-1)-N1/N2), constructs H-T(n-1)-N1/N2.
If that matches the one sent in N1's reqeust, that part of the transaction is considered valid.
If it still does not match then transaction validation has failed and N2 can send a failure notification or not reply.

If H-T-N1/N2 is valid then the signature is validated.
The request message up to the start of N1-SIG is validated against the N1-ID (N1's Ed25519 public key).
If the signature is valid, the request is considered validated and N2 constructs then sends its reply.
The concatenation of request and reply is considered to be a complete transaction and is therefore added to N2's chain.

When N1 receives a reply from N2 it must only validate the signature.
N1 concatenates it's original request request with N2's response up to the start of the N2-SIG field.
This data is then validated against the N2-ID, using the HMAC+SHA256 algorithm.
If the signature is valid, the reply is considered validated. N1 does not reply to N2.
The concatenation of request and reply is considered to be a complete transaction and is therefore added to N1's chain.

What Happens When a Request Doesn't Recieve a Reply?
====================================================

N1 sends a request to N2. If N1 does not receive a reply from N2 it can retain its pending transaction until it makes another request. The pending request is forgotten and the new request becomes the only pending request. A node can only have a single pending request at a time because it's chain can only have a single head. Allowing multiple pending requests allows the possibility of multiple valid transaction completions at the same point in the local chain.

What Happens When a Reply is Missed
===================================

N1 sends a request to N2. N2 replies and adds the transaction to N2's local chain. The packet is lost and N1 never gets the reply. N1's N1/N2 chain now has one less transaction than N2's. The next time N1 requests N2 it will use its latest N1/N2 transaction. When N2 receives this request it will be invalid against it's latest N1/N2 transaction. It will, however, be valid against the immediately preceeding N1/N2 transaction (if it is valid at all). Note that N2 does not have to walk back up its chain of N1/N2 transactions because it's impossible for any transaction except the latest to be invalid.

Consider a chain of N1/N2 transactions:

N1 has: T1 - T2
N2 has: T1 - T2

N1 requests but does not receive a reply:
N1 has: T1 - T2
N2 has: T1 - T2 - T3

When N1 makes another request it must be based on T2, if it doesn't get a reply:
N1 has: T1 - T2
N2 has: T1 - T2 - T4 
(T3 is no longer in the N1/N2 chain since N1's request was based on T2)

If T3 and T4 are valid transactions, they must be based on T2, this confirms implicitly that T2 is known by N1 and thus must be the latest shared transaction.
Also note that any further transactions based on T2 will invalidate the one before in N2's chain. T5 would invalidate T4, T6 invalidates T5 and so on until a transaction is received that is based on the latest valid head.
             
N1 sends T6 and this time recieves the reply
N1 has: T1 - T2 - T6
N2 has: T1 - T2 - T6
N1 sends T7 based on T6 but again doesn't recieve the reply
N1 has: T1 - T2 - T6
N2 has: T1 - T2 - T6 - T7
Any subsequent transactions from N1 based on T2 cannot be valid, since N2's receipt of a request based on T6 (i.e T7) confirms N1 had already received the T6 reply. A non-adversarial N1 would only form requests based on the head of its N1/N2 chain.


What Happens When a Node Dies?
==============================

Hardware failures and data loss happen. When this occurs the node's chain is considered broken and a new keypair must be created for the node. This does not invalidate the historical chain elements of the players that reference this node but rather represents a normal part of the lifecycle of a node. 

Players will want to carefully backup their keys and chain because the same rules will apply to them.


An Example Session
==================

Extensions and Random Thoughts
==============================

* There's enough space in a reticulum packet for a data segment
* This is locally time ordered event list that doesn't use a clock
