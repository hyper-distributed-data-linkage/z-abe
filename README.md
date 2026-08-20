[日本語](README_ja.md)

# Zenoh NAC-ABE

NAC-ABE implementation using [Eclipse Zenoh](https://github.com/eclipse-zenoh/zenoh)

## Description

NAC-ABE^[Zhang, Zhiyi, et al. "NAC: Automating access control via named data." _MILCOM 2018._ IEEE, 2018.] (Name-based Access Control with Attribute-based Encryption) enables secure data sharing in content-centric networks through attribute-based encryption. Zenoh NAC-ABE implements the NAC-ABE scheme using Zenoh protocols.

Key components and their roles:

1. **Attribute Authority**

   - Manages ABE keys (master and public keys)
   - Issues attribute-based secret keys (SK) to authorized consumers

2. **Access Manager**

   - Manages access policies (e.g., `"A" or "B"`, `"C" and "D"`) for contents

3. **Producer**

   - Retrieves access policies from Access Manager via Zenoh
   - Retrieves public key from Attribute Authority via Zenoh
   - Encrypts content with symmetric Content Key (CK)
   - Encrypts CK with public key from Attribute Authority, based on access policies from Access Manager
   - Publishes encrypted content and encrypted CK via Zenoh

4. **Consumer**

   - Retrieves SK from Attribute Authority via Zenoh
   - Retrieves encrypted content and encrypted CK from Producer via Zenoh
   - Decrypts encrypted CK using SK from Attribute Authority
   - Decrypts encrypted content using CK

## How to Build

```bash
cargo build --release --all-targets
```

## How to Run Examples

**Required services (start first):**

```bash
# Attribute Authority
RUST_LOG=info ./target/release/examples/attribute_authority

# Access Manager
RUST_LOG=info ./target/release/examples/access_manager
```

**Data operations:**

```bash
# Producer
RUST_LOG=info ./target/release/examples/producer

# Consumer
RUST_LOG=info ./target/release/examples/consumer
```

> [!NOTE]
> Ensure the Attribute Authority and Access Manager are running before starting the Producer and Consumer.

## How to Use Zenoh NAC-ABE

Refer to the examples below for usage:

- Attribute Authority: [`examples/attribute_authority.rs`](examples/attribute_authority.rs)
- Access Manager: [`examples/access_manager.rs`](examples/access_manager.rs)
- Producer: [`examples/producer.rs`](examples/producer.rs)
- Consumer: [`examples/consumer.rs`](examples/consumer.rs)

## Acknowledgements

This work is based on results obtained from the project, “Research and Development Project of the Enhanced Infrastructures for Post-5G Information and Communication Systems” (JPNP20017), commissioned by the New Energy and Industrial Technology Development Organization (NEDO).
