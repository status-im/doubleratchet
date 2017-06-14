# doubleratchet

[![Go Report Card](https://goreportcard.com/badge/github.com/tiabc/doubleratchet)](https://goreportcard.com/report/github.com/tiabc/doubleratchet)
[![Build Status](https://travis-ci.org/tiabc/doubleratchet.svg?branch=master)](https://travis-ci.org/tiabc/doubleratchet)
[![Coverage Status](https://coveralls.io/repos/github/tiabc/doubleratchet/badge.svg?branch=master)](https://coveralls.io/github/tiabc/doubleratchet?branch=master)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GoDoc](https://godoc.org/github.com/tiabc/doubleratchet?status.svg)](https://godoc.org/github.com/tiabc/doubleratchet)

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

then `cd` into the project directory and install dependencies:

    glide up
    
If `glide` is not installed, [install it](https://github.com/Masterminds/glide).

## Usage example

```go
package main

import (
	"fmt"
	"log"

	"github.com/tiabc/doubleratchet"
)

func main() {
	// The shared key both parties have already agreed upon before the communication.
	sk := [32]byte{
		0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20,
		0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a,
		0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb,
		0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40,
	}

	// Bob is instantiated only with the shared secret.
	bob, err := doubleratchet.New(sk)
	if err != nil {
		log.Fatal(err)
	}

	// Alice is instantiaed with the shared secret and Bob's public key which
	// should be sent to Alice before the session begins.
	alice, err := doubleratchet.New(sk, doubleratchet.WithRemoteKey(bob.PublicKey()))
	if err != nil {
		log.Fatal(err)
	}

	// Alice can now encrypt messages under the Double Ratchet session.
	m := alice.RatchetEncrypt([]byte("Hi Bob!"), nil)

	// Which Bob can decrypt.
	plaintext, err := bob.RatchetDecrypt(m, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(plaintext))
}
```

## Implementation notes

### The Double Ratchet logic

1. No more than 1000 messages can be skipped in a single chain.
1. Skipped messages from a single ratchet step are deleted after 10 ratchet steps.
1. Both parties' sending and receiving chains are initialized with the shared key so that both
of them could message each other from the very beginning.
1. TODO: Header encryption

### Cryptographic primitives 

1. **GENERATE_DH():** Curve25519
1. **KDF_RK(rk, dh_out):** HKDF with SHA-256
1. **KDF_CK(ck):** HMAC with SHA-256 with constant inputs
1. **ENCRYPT(mk, plaintext, associated_data):** AES-256-CTR with HMAC-SHA-256 and IV derived alongside an encryption key

## License

MIT
