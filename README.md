## Private Threshold Multi-Sigs for Mass Adoption

This project provides a way to perform threshold signatures at large scale while appearing as one signer onchain. Unlike onchain threshold schemes that cost hundreds to thousands of dollars the participants of this protocol generates a signature from a threshold offchain and just pays for the cost of one transaction onchain while keeping a threshold of up to 65535 participants.

The underlying technology is FROST threshold signatures that ensures that once agreement of the public key is establish no single participants holds the private key but instead all participants hold a group key that generates a signature once a threshold is reached.

This reduces cost of threshold signatures for large groups to just running a $5 server with the cost of submitting 1 transaction onchain.

## Threshold Architecture
