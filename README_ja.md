[English](README.md)

# Zenoh NAC-ABE

[Eclipse Zenoh](https://github.com/eclipse-zenoh/zenoh) を用いた NAC-ABE の実装

## 説明

NAC-ABE^[Zhang, Zhiyi, et al. "NAC: Automating access control via named data." _MILCOM 2018._ IEEE, 2018.]（Name-based Access Control with Attribute-based Encryption）は、コンテンツ指向ネットワークにおける属性ベース暗号化を通じて安全なデータ共有を実現する仕組みです。Zenoh NAC-ABE は、Zenoh プロトコルを用いてこの NAC-ABE スキームを実装しています。

主要なコンポーネントとその役割：

1. **Attribute Authority**

   - ABE 暗号鍵（マスターキーおよび公開鍵）を管理
   - 認可された Consumer に属性ベースの秘密鍵（SK）を発行

2. **Access Manager**

   - コンテンツのアクセスポリシー（例：`"A" or "B"`、`"C" and "D"`）を管理

3. **Producer**

   - Zenoh を介して Access Manager からアクセスポリシーを取得
   - Zenoh を介して Attribute Authority から公開鍵を取得
   - コンテンツを共通鍵（CK）で暗号化
   - Access Manager からのアクセスポリシーに基づいて、Attribute Authority から取得した公開鍵で CK を暗号化
   - Zenoh を介して暗号化されたコンテンツと暗号化された CK を公開

4. **Consumer**

   - Zenoh を介して Attribute Authority から SK を取得
   - Zenoh を介して Producer から暗号化されたコンテンツと暗号化された CK を取得
   - Attribute Authority から取得した SK を用いて暗号化された CK を復号
   - CK を用いて暗号化されたコンテンツを復号

## ビルド方法

```bash
cargo build --release --all-targets
```

## 実例の実行方法

**必要なサービス（最初に起動）：**

```bash
# Attribute Authority
RUST_LOG=info ./target/release/examples/attribute_authority

# Access Manager
RUST_LOG=info ./target/release/examples/access_manager
```

**データ操作：**

```bash
# Producer
RUST_LOG=info ./target/release/examples/producer

# Consumer
RUST_LOG=info ./target/release/examples/consumer
```

> [!NOTE]
> Attribute Authority と Access Manager が起動された状態で Producer と Consumer を起動すること。

## Zenoh NAC-ABE の使用方法

下記の例を参照して使用してください：

- Attribute Authority: [`examples/attribute_authority.rs`](examples/attribute_authority.rs)
- Access Manager: [`examples/access_manager.rs`](examples/access_manager.rs)
- Producer: [`examples/producer.rs`](examples/producer.rs)
- Consumer: [`examples/consumer.rs`](examples/consumer.rs)

## 謝辞

この成果は、ＮＥＤＯ（国立研究開発法人新エネルギー・産業技術総合開発機構）の委託事業「ポスト５Ｇ情報通信システム基盤強化研究開発事業」（JPNP20017）の結果得られたものです。
