# Third-party notices

## restic 0.19.0

The release backup and clean-restore controller interoperates with the
separately installed `restic` command-line tool. No restic source or binary is
vendored in this repository.

- Upstream: https://github.com/restic/restic/tree/v0.19.0
- Source archive SHA-256: `800779b6c4c2396971c0567b09ccdd435e03155e1a0ec94e8bbf3d98641a8bc2`
- Homebrew arm64 Tahoe bottle SHA-256: `b69c21f735a13de6c74d6a097199fc6e98fd794c48e287a035dbff434bfcae41`
- License: BSD-2-Clause
- Exact license copy: `LICENSES/restic-BSD-2-Clause.txt`
- License SHA-256: `6f08a01a9fab5b24e139a09f15cc24a73087c7bc09e3bacf099fdf2d767bf897`

Copyright (c) 2014, Alexander Neumann and restic contributors.

## OpenSSL 3.6.2

The selected-receipt attestation adapter interoperates with the separately
installed OpenSSL command-line tool for Ed25519 signing and verification. No
OpenSSL source or binary is vendored in this repository.

- Upstream: https://github.com/openssl/openssl/tree/openssl-3.6.2
- Runtime interface: `openssl pkey` and `openssl pkeyutl`
- License: Apache-2.0
- Exact license copy: `LICENSES/openssl-Apache-2.0.txt`
- License SHA-256: `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a`
