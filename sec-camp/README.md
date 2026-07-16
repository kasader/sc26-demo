# sec-camp: eBPF DDoS Guard デモ

*[English version here / 英語版はこちら](README.en.md)*

セキュリティ・キャンプ2026 ブースセッション用の実演デモ。大量のパケットが襲いかかる
DoS/DDoS攻撃に対し、Linuxカーネルの eBPF (XDP) を使って低レイヤーで高速に
「検知・防御・回避対策」を行う様子をリアルタイムで見せるためのコンテナ一式です。

このディレクトリは `sample01`〜`sample04` とは独立した新しいプログラム
(`guard`/`attacker`/`victim`) ですが、同じ Go module (`go-ebpf-sample`) の
サブパッケージとして動きます。`guard` は sample02 のブロックリスト方式
(送信元単位の遮断) と sample04 のプロトコル検証方式 (UDPペイロードの
フラグバイト検証) を組み合わせた、このデモ専用の新しい XDP プログラムです。

## 見せ方(ストーリー)

1本のコンテナの中に、veth で繋いだ2つの network namespace
(`atk` = 攻撃者, `vic` = 被害者) を作り、`vic` 側の veth に XDP プログラム
`guard` をアタッチします。

| 段階 | 攻撃者 (`attacker -mode ...`) | eBPF guard の反応 |
| --- | --- | --- |
| 検知1: 通常時 | `legit` — 少数の送信元から正しいプロトコルフラグのパケット | ほぼ全て `passed` |
| 防御1: 単純フラッド | `flood` — 1〜2送信元から高速に不正パケット | 送信元ごとのパケットレートを検知し、カーネル内で自動遮断 (`dropped-rate`) |
| 防御2: 低速な不正パケット | `garbage` — レート制限を超えない速度で不正なフラグ | ペイロードのフラグバイト検証で `dropped-protocol` |
| 回避への対策 | `evasive` — 送信元(ポート)を50個に分散し、1つ当たりのレートは制限未満 | 送信元ベースのレート制限は回避されるが、プロトコル検証層で結局全て `dropped-protocol` |

「レート制限だけでは分散された攻撃者に回避されてしまうが、ペイロード検証を
併用することで低レイヤーのまま防御できる」という多層防御の必要性を、
最後の evasive で見せるのがこのデモの核です。

## アーキテクチャ

```text
                 container (--privileged)
  ┌─────────────────────────────────────────────────────────┐
  │  netns: atk (10.10.0.1/24)      netns: vic (10.10.0.2/24) │
  │  ┌───────────────────┐ veth  ┌───────────────────────┐  │
  │  │ attacker           │◄────►│ veth-vic               │  │
  │  │ (Go, UDP flood)     │      │  ▲ XDP: guard.c        │  │
  │  └───────────────────┘      │  │ (rate limit + proto)  │  │
  │                              │  ▼                       │  │
  │                              │ victim (Go, UDP server)  │  │
  │                              │ guard (Go, HTTP :5555 +  │  │
  │                              │        live dashboard)   │  │
  │                              └───────────────────────┘  │
  └─────────────────────────────────────────────────────────┘
```

`guard` は eBPF が「検知して即ドロップ」した事実をリングバッファ経由で
ユーザースペースへ通知し、送信元を一時的にブロックリストへ追加します
(TTL 経過で自動的に解除)。パケットのドロップ自体はカーネル内 (XDP) で
完了しており、ユーザースペースの介入を待たずに行われます。

## 前提条件

* eBPF/XDP は **Linux カーネルでしか動きません**。macOS/Windows では
  Docker Desktop の Linux VM 経由で動かしてください。
* コンテナは `--privileged` で実行します(eBPFのロードとnetwork namespace
  の作成に `CAP_SYS_ADMIN`/`CAP_BPF`/`CAP_NET_ADMIN` 等が必要なため、
  1回限りのデモではこれが最も確実です)。
* ホストのカーネルが XDP generic mode をサポートしていること(5.x系以降
  ならほぼ問題ありません)。

## ビルド

リポジトリのルート(`go-ebpf-sample` の `go.mod` がある場所)から:

```bash
docker build -f sec-camp/Dockerfile -t sec-camp-demo .
```

## 実行

```bash
docker run --rm -it --privileged --name sec-camp sec-camp-demo
```

起動すると自動で:

1. `atk`/`vic` の network namespace と veth を作成
2. `victim` (UDPサーバ) を `vic` 側で起動
3. `guard` (XDPプログラム) を `vic` 側で起動し、HTTP API (`:5555`) を公開
4. `guard` を `veth-vic` にアタッチし、`10.10.0.2:9999` を保護対象に設定
5. tmux セッション `sec-camp` を開き、3分割ペイン
   (左: guard のライブダッシュボード / 右上: victim のログ /
   右下: attacker 用のシェル) にアタッチ

そのまま右下のペインで攻撃コマンドを打てば、左のダッシュボードに
`total` / `passed` / `dropped-rate` / `dropped-protocol` の pps と
現在のブロックリストがリアルタイムに表示されます。

```bash
# 正常系: ほぼ全てpassedになることを見せる
/usr/local/bin/attacker -target 10.10.0.2:9999 -mode legit

# 高速フラッド: dropped-rate が跳ね上がり、自動でブロックリストに載る
/usr/local/bin/attacker -target 10.10.0.2:9999 -mode flood

# 低速な不正パケット: レート制限には引っかからないが dropped-protocol で防げる
/usr/local/bin/attacker -target 10.10.0.2:9999 -mode garbage

# 回避を試みる攻撃者: 送信元を50個に分散してレート制限を回避しようとするが、
# プロトコル検証層で結局すべて弾かれる
/usr/local/bin/attacker -target 10.10.0.2:9999 -mode evasive
```

同時に複数のモードを別ペインで動かして「善良なユーザーのトラフィックは
攻撃中も生き残る」ことを見せるのも効果的です。

### 手動操作 (Q&A用)

コンテナ内の別シェル (`docker exec -it sec-camp bash`) から:

```bash
cd /src/sec-camp/scripts

# 任意の送信元を手動でブロック
./vic.sh curl -s -X POST http://10.10.0.2:5555/block \
  -d '[{"address":"1.2.3.4:5555","duration":"1m"}]'

# ブロックリストを全解除
./vic.sh curl -s -X POST http://10.10.0.2:5555/unblock-all
```

## 後片付け

```bash
docker rm -f sec-camp
```

コンテナを削除すれば namespace/veth も含めて全て消えます(コンテナ内で
作った netns なので、ホストには何も残りません)。

## パラメータ

`guard` の起動フラグ(`scripts/run-demo.sh` の環境変数で上書き可能):

| フラグ / 環境変数 | 既定値 | 意味 |
| --- | --- | --- |
| `-rate` / `RATE_THRESHOLD` | 30 | 1送信元あたり、これを超えるpps(パケット/秒)で自動ブロック |
| `-block-ttl` / `BLOCK_TTL` | 15s | 自動/手動ブロックの有効期間 |

例: `docker run --rm -it --privileged -e RATE_THRESHOLD=10 sec-camp-demo`

## トラブルシューティング

* **`AttachXDP` が失敗する**: veth には XDP native mode がアタッチできません。
  `guard/main.go` は常に `link.XDPGenericMode` (SKB mode) を指定しているので
  通常は問題になりませんが、カーネルが古すぎる場合は generic XDP 自体が
  使えないことがあります。
* **`--privileged` を使いたくない場合**: 最低限
  `--cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON`
  が必要です。環境によって足りない capability が変わるので、booth 当日は
  `--privileged` を推奨します。
* **`-debug` を付けたときの eBPF トレース確認**:
  `docker exec -it sec-camp cat /sys/kernel/debug/tracing/trace_pipe`
  (要 `/sys/kernel/debug` がホストからマウントされていること。難しい場合は
  ダッシュボードの数値だけで十分に伝わります。)

## ファイル構成

```text
sec-camp/
├── Dockerfile           # ビルド一式(clang/libbpf-dev/go)
├── guard/                # XDP プログラム本体 + Goローダー + ダッシュボード
│   ├── guard.c
│   ├── gen.go
│   ├── main.go
│   └── dashboard.go
├── attacker/main.go      # UDPフラッドツール (legit/garbage/flood/evasive)
├── victim/main.go        # 保護対象のUDPサーバ
└── scripts/
    ├── setup-netns.sh    # atk/vic netns + veth の作成
    ├── teardown-netns.sh
    ├── run-demo.sh        # コンテナのENTRYPOINT。全体のオーケストレーション
    ├── atk.sh / vic.sh    # 各namespace内でコマンドを実行する補助スクリプト
```
