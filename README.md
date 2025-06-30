# descriptor-codec

Efficiently encode and decode Bitcoin wallet descriptors with 30-40% size reduction.

## Features

- **Compact Encoding**: Tag-based and variable-length encoding reduces descriptor size by 30-40%
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

## Use Cases

- Sharing complex multisig configurations via QR codes
- NFC communication with hardware wallets  
- Reducing bandwidth in wallet coordination protocols
- Storing descriptors in constrained environments

## License

CC0-1.0