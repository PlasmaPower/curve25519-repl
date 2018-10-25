# curve25519 REPL

A REPL built for working with curve25519.
See examples/nano/sign-block.txt for an example of this in use (requires `--features nano`).

## Functions:

### bytes

`bytes(in: scalar | point | string | bytes) -> bytes`

Converts its argument to bytes.

### scalar

`scalar(in: bytes | scalar) -> scalar`

Converts its argument to a scalar.

### point

`point(in: bytes | scalar | point) -> point`

Converts its argument to a point.

### rand

`rand(len?: number) -> bytes`

Generates random bytes. Length defaults to 32.

This uses a cryptographically secure RNG.

### blake2b

`blake2b(message: bytes | scalar | point | string, out_len?: number) -> bytes`

Hashes the message using blake2b.
Requires the blake2 feature.
The output length defaults to 32 bytes.

### sha256

`sha256(message: bytes | scalar | point | string) -> bytes`

Hashes the message using SHA256.
Requires the sha2 feature (enabled by default).
Produces a 32 byte output.

### sha512

`sha512(message: bytes | scalar | point | string) -> bytes`

Hashes the message using SHA512.
Requires the sha2 feature (enabled by default).
Produces a 64 byte output.

### nano_account_encode

`nano_account_encode(account: point | bytes) -> string`

Encodes the given curve point as a nano account.
Requires the nano feature.

### nano_account_decode

`nano_account_decode(account: string) -> point`

Decodes a nano account to a curve point.
Requires the nano feature.

### ed25519_extsk

`ed25519_extsk(skey: bytes, hasher?: "sha2" | "sha512" | "blake2b") -> bytes`

Extends a given 32 byte ed25519 secret key.
The default hasher is sha2.
Returns 64 bytes.

### ed25519_pub

`ed25519_pub(skey: bytes, hasher?: "sha2" | "sha512" | "blake2b") -> point`

Returns the public key as a curve point for a given ed25519 secret key.
The default hasher is sha2.

### ed25519_sign

`ed25519_sign(skey: bytes, message: bytes | scalar | point | string, hasher?: "sha2" | "sha512" | "blake2b") -> point`

Signs a message with the given ed25519 secret key.
The default hasher is sha2.
Returns 64 bytes.

### ed25519_verify

`ed25519_verify(pkey: point | bytes, message: bytes | scalar | point | string, signature: bytes, hasher?: "sha2" | "sha512" | "blake2b") -> bool`

Checks if an ed25519 signature is valid.
The default hasher is sha2.
Returns true if the signature is valid, and false otherwise.

### nano_block_hash!

`nano_block_hash!({"type":"state",...}) -> bytes`

Hashes a nano block.
Requires the nano feature.
