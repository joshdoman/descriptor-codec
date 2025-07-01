# descriptor-codec

Efficiently encode and decode Bitcoin wallet descriptors with a 30-40% size reduction.

## Features

- **Compact Encoding**: Tag-based and variable-length encoding and the avoidance of bech32 and base58 reduces descriptor size by 30-40%
- **Complete Coverage**: Supports all descriptor types including complex miniscript and private keys
- **QR Code Friendly**: Smaller encodings improve QR code reliability and scanning
- **NFC Compatible**: Fits descriptors within NFC byte limits for hardware wallet communication

## Usage

```rust
use descriptor_codec::{encode, decode};

// Encode a descriptor
let descriptor = "wsh(sortedmulti(2,\
    03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,\
    036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,\
    02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29\
))#hfj7wz7l";

let encoded = encode(descriptor).unwrap();
let decoded = decode(&encoded).unwrap();
assert_eq!(descriptor, decoded);
```

## CLI Usage

### Installation
To build the project, use the following command:
```bash
cargo build --release --features cli
```
The executable will be located at `./target/release/descriptor-codec`.

### Commands

*   #### Encode a Descriptor
    Encodes a Bitcoin descriptor and outputs the result as hex.
    ```bash
    ./target/release/descriptor-codec encode <DESCRIPTOR_STRING>
    ```
    **Arguments**:
    *   `<DESCRIPTOR_STRING>`: The Bitcoin descriptor string to encode.

*   #### Decrypt a Descriptor
    Decodes hex-encoded descriptor data.
    ```bash
    ./target/release/descriptor-codec decode <DATA>
    ```

    **Arguments**:
    *   `<DATA>`: Hex-encoded descriptor data.

## Algorithm

The encoder splits the descriptor into two parts that are concatenated: a structural **template** and a data **payload**.

### Template and Payload

The encoding separates the descriptor's structure from its raw data.

*   **Template**: This part defines the logical structure of the descriptor. It is a sequence of single-byte **Tags** that represent script components (like `wsh`, `pk`, `older`) and structural information. It also contains variable-length encoded integers for derivation paths and multisig `k`/`n` parameters.
*   **Payload**: This part contains the raw data values from the descriptor, concatenated in the order they are referenced by the template. This includes items like public keys, private keys, key fingerprints, hashes, and timelock values.

When decoding, the template is read first to understand the structure, which then dictates how to parse the subsequent payload data.

### Variable-Length Encoding

To save space, unsigned integers are encoded as variable-length LEB128 integers. This is used for:
*   Absolute and relative timelocks (`after`, `older`).
*   The `k` (threshold) and `n` (total keys) values in multisig (`multi`, `sortedmulti`) and threshold (`thresh`) scripts.
*   The length of derivation paths and the individual child numbers within them.
*   Hardened child numbers are encoded as $2c+1$, where $c$ is the child number. Unhardened child numbers 
are encoded as $2c$.

### Tags

Each component of a descriptor is represented by a single-byte tag.

| Tag Name | Hex Value | Description |
| :--- | :--- | :--- |
| `False` | $0x00$ | Miniscript `false` operator. |
| `True` | $0x01$ | Miniscript `true` operator. |
| `Pkh` | $0x02$ | Top-level Pay-to-Public-Key-Hash descriptor. |
| `Sh` | $0x03$ | Top-level Pay-to-Script-Hash descriptor. |
| `Wpkh` | $0x04$ | Top-level Witness-Pay-to-Public-Key-Hash descriptor. |
| `Wsh` | $0x05$ | Top-level Witness-Pay-to-Script-Hash descriptor. |
| `Tr` | $0x06$ | Top-level Pay-to-Taproot descriptor. |
| `Bare` | $0x07$ | Top-level Bare Script descriptor. |
| `TapTree` | $0x08$ | A Taproot script path tree or leaf. |
| `SortedMulti`| $0x09$ | A sorted multisig script. |
| `Alt` | $0x0A$ | Miniscript `alt` operator. |
| `Swap` | $0x0B$ | Miniscript `swap` operator. |
| `Check` | $0x0C$ | Miniscript `check` operator. |
| `DupIf` | $0x0D$ | Miniscript `dupif` operator. |
| `Verify` | $0x0E$ | Miniscript `verify` operator. |
| `NonZero` | $0x0F$ | Miniscript `nonzero` operator. |
| `ZeroNotEqual`| $0x10$ | Miniscript `zeronotequal` operator. |
| `AndV` | $0x11$ | Miniscript `and_v` operator. |
| `AndB` | $0x12$ | Miniscript `and_b` operator. |
| `AndOr` | $0x13$ | Miniscript `andor` operator. |
| `OrB` | $0x14$ | Miniscript `or_b` operator. |
| `OrC` | $0x15$ | Miniscript `or_c` operator. |
| `OrD` | $0x16$ | Miniscript `or_d` operator. |
| `OrI` | $0x17$ | Miniscript `or_i` operator. |
| `Thresh` | $0x18$ | Miniscript `thresh` operator. |
| `Multi` | $0x19$ | Miniscript `multi` operator. |
| `MultiA` | $0x1A$ | Miniscript `multi_a` operator. |
| `PkK` | $0x1B$ | Miniscript `pk_k` (CHECKSIG). |
| `PkH` | $0x1C$ | Miniscript `pk_h` (CHECKSIG from hash). |
| `RawPkH` | $0x1D$ | Miniscript `raw_pkh` (raw public key hash). |
| `After` | $0x1E$ | Miniscript absolute timelock (`after`). |
| `Older` | $0x1F$ | Miniscript relative timelock (`older`). |
| `Sha256` | $0x20$ | A SHA256 hash. |
| `Hash256` | $0x21$ | A double-SHA256 hash. |
| `Ripemd160` | $0x22$ | A RIPEMD-160 hash. |
| `Hash160` | $0x23$ | A HASH160 (SHA256 then RIPEMD-160) hash. |
| `Origin` | $0x24$ | Indicates a key has an origin (fingerprint + path). |
| `NoOrigin` | $0x25$ | Indicates a key has no origin. |
| `UncompressedFullKey` | $0x26$ | An uncompressed public key. |
| `CompressedFullKey` | $0x27$ | A compressed public key. |
| `XOnly` | $0x28$ | An x-only (Taproot) public key. |
| `XPub` | $0x29$ | An extended public key (`xpub`). |
| `MultiXPub` | $0x2A$ | An `xpub` with multiple derivation paths. |
| `UncompressedSinglePriv`| $0x2B$ | An uncompressed private key. |
| `CompressedSinglePriv` | $0x2C$ | A compressed private key. |
| `XPriv` | $0x2D$ | An extended private key (`xprv`). |
| `MultiXPriv` | $0x2E$ | An `xprv` with multiple derivation paths. |
| `NoWildcard`| $0x2F$ | No wildcard `/*` in a derivation path. |
| `UnhardenedWildcard` | $0x30$ | Unhardened wildcard `/*` in a derivation path. |
| `HardenedWildcard` | $0x31$ | Hardened wildcard `/*h` in a derivation path. |

## Use Cases

- Sharing complex multisig configurations via QR codes
- NFC communication with hardware wallets  
- Reducing bandwidth in wallet coordination protocols
- Storing descriptors in constrained environments

## License

This project is licensed under the CC0-1.0 License.

## Author

Joshua Doman <joshsdoman@gmail.com>