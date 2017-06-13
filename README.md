# doubleratchet

[![Go Report Card](https://goreportcard.com/badge/github.com/tiabc/doubleratchet)](https://goreportcard.com/report/github.com/tiabc/doubleratchet)
[![Build Status](https://travis-ci.org/tiabc/doubleratchet.svg?branch=master)](https://travis-ci.org/tiabc/doubleratchet)
[![Coverage Status](https://coveralls.io/repos/github/tiabc/doubleratchet/badge.svg?branch=master)](https://coveralls.io/github/tiabc/doubleratchet?branch=master)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GoDoc](https://godoc.org/github.com/tiabc/doubleratchet?status.svg)](https://godoc.org/github.com/tiabc/doubleratchet)

**IMPORTANT!** The current version is in active development at the moment, it is still incomplete
and MUST NOT be used anywhere. 

[The Double Ratchet Algorithm](https://whispersystems.org/docs/specifications/doubleratchet) is used
by two parties to exchange encrypted messages based on a shared secret key. Typically the parties
will use some key agreement protocol (such as X3DH) to agree on the shared secret key.
Following this, the parties will use the Double Ratchet to send and receive encrypted messages.

The parties derive new keys for every Double Ratchet message so that earlier keys cannot be calculated
from later ones. The parties also send Diffie-Hellman public values attached to their messages.
The results of Diffie-Hellman calculations are mixed into the derived keys so that later keys cannot
be calculated from earlier ones. These properties gives some protection to earlier or later encrypted 
messages in case of a compromise of a party's keys.

## Installation

    go get github.com/tiabc/doubleratchet

then cd into the project directory and install dependencies:

    glide up

## Usage

TODO

## Implementation notes

### The Double Ratchet logic

1. TODO: Skipped messages handling.
1. TODO: When a skipped message is deleted?
1. TODO: Header encryption?
1. Both parties' sending and receiving chains are initialized with the shared key so that both
of them could message each other from the very beginning.

### Cryptographic primitives 

1. **GENERATE_DH():** Curve25519
1. **KDF_RK(rk, dh_out):** HKDF with SHA-256
1. **KDF_CK(ck):** HMAC with SHA-256 with constant inputs
1. **ENCRYPT(mk, plaintext, associated_data):** AES-256-CTR with HMAC-SHA-256 and IV derived alongside an encryption key

## License

MIT
