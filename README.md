# wsslirp

Ethernetフレームを吐く非特権ゲストのためのユーザーモードNATデーモン。

ブラウザで動くエミュレータ([rustx86](https://github.com/yoshiharu-ishii/rustx86) WASM版)は生ソケットを持てない。そこでゲストOSの仮想NICが吐くEthernetフレームをWebSocketでそのまま運び、サーバー側のgVisor netstackでTCP/UDPを終端して、本物のソケットでインターネットへ出る。QEMUの `-netdev user`(内蔵slirp)を独立デーモンに切り出し、WebSocketという口を付けたもの、と考えると正確。

```mermaid
flowchart TB
    subgraph browser["ブラウザ ×N (rustx86 WASM)"]
        guest["ゲストOS"] --> nic["仮想NIC (virtio-net / e1000)"]
    end
    subgraph native["ネイティブゲスト"]
        guest2["rustx86 ネイティブ版など"]
    end
    nic -- "wss:// 1フレーム=1バイナリメッセージ" --> ws
    guest2 -- "ws://localhost 同一プロトコル" --> ws
    subgraph daemon["wsslirpd (Go・1プロセス)"]
        ws["WSハンドラ (1ゲスト=1 goroutine)"] --> stack["gVisor netstack (DHCP / DNS / TCP終端)"]
        stack --> nat["NAT (net.Dial で外へ)"]
    end
    nat --> inet["インターネット"]
```

## プロトコル

トランスポートとの契約はこれだけ:

- **1 WebSocketバイナリメッセージ = 1 Ethernetフレーム**(最大1514バイト、L3 MTU 1500)
- エンドポイント: `GET /net?token=<共有トークン>` → WebSocketアップグレード
- TLS終端はデプロイに任せる(リバースプロキシで `wss://` にする)

コア(`pkg/slirpstack`)はWebSocketを知らない。`FrameIO`(ReadFrame/WriteFrame)にだけ依存するので、UDSやインプロセスchannelなど別トランスポートを後から足せる。

## ゲストから見えるネットワーク

slirp互換のレイアウト。ゲストごとに独立したスタックを作るので、ゲスト同士は互いに見えない。

| アドレス | 役割 |
|---|---|
| 10.0.2.0/24 | サブネット(DHCPで配布) |
| 10.0.2.2 | ゲートウェイ(ARP/ICMP echo応答あり) |
| 10.0.2.3 | DNS(上流リゾルバへ転送) |
| 10.0.2.15 | ゲストのアドレス(DHCPリース) |

- DHCP応答はnetstackに入る前のフレーム層で処理(discover→offer、request→ack)
- TCP: `tcp.NewForwarder` でゲストのTCPを終端し、`net.Dial` で張り直す。ハーフクローズは伝搬する(片方向のFINは `CloseWrite` で相手側に届き、逆方向は流れ続ける)
- UDP: フローごとに転送、60秒アイドルで回収。10.0.2.3:53宛は上流DNSへ
- ICMP: ゲートウェイ宛echoはスタック自身が応答。外向きecho requestは非特権pingソケット(SOCK_DGRAM + IPPROTO_ICMP)で代理送信し、応答をecho replyフレームで返す。macOSはそのまま動く。Linuxはデーモンのグループが sysctl `net.ipv4.ping_group_range` に入っている必要がある(入っていなければ外向きpingだけタイムアウトし、他は無影響)

## セキュリティ

公開されたリレーは放っておくと踏み台(オープンプロキシ)になるため:

- `-token` : 接続時の共有トークン認証(定数時間比較)
- egressフィルタ: loopback・RFC1918・リンクローカル・マルチキャスト宛を遮断(SSRF対策)。TCP・UDP・外向きICMP echoすべてに適用。開発時のみ `-allow-private` で解除
- ゲストのフレームは全てユーザーランドで処理され、ホストのネットワークスタックには触れない

## 使い方

```
go run ./cmd/wsslirpd -listen 127.0.0.1:8087 -token <secret>
```

| フラグ | 意味 |
|---|---|
| `-listen` | 待ち受けアドレス(デフォルト 127.0.0.1:8087) |
| `-token` | 共有トークン(`WSSLIRP_TOKEN` 環境変数でも可。空で認証なし) |
| `-allow-private` | プライベート宛egress許可(開発用) |
| `-upstream-dns` | 上流リゾルバ host:port(デフォルト: resolv.conf → 1.1.1.1:53) |
| `-log-flows` | フローログ(デフォルト有効。`-log-flows=false` で停止) |

## フローログ

ゲストがどこへ出ていったかを1行ずつ記録する。行の形は固定で、**矢印は常に接続を開いた向き**(左がゲスト):

```
slirp: [g1] guest connected from 127.0.0.1:51531
slirp: [g1] udp open  10.0.2.15:39060 -> 10.0.2.3:53 (dns via 192.168.10.1:53)
slirp: [g1] tcp open  10.0.2.15:62640 -> 104.20.23.154:80
slirp: [g1] tcp close 10.0.2.15:62640 -> 104.20.23.154:80 (97ms, -> 56 B, <- 868 B)
slirp: [g1] udp close 10.0.2.15:39060 -> 10.0.2.3:53 (268ms, -> 29 B, <- 61 B)
slirp: [g1] guest disconnected after 272ms (...)
slirp: [g2] icmp echo  10.0.2.15 -> 1.1.1.1 (seq=1, 16 B)
slirp: [g2] icmp reply 10.0.2.15 <- 1.1.1.1 (seq=1, 13ms)
slirp: [g2] tcp deny  10.0.2.15:53659 -> 10.99.0.1:80
```

- `[gN]` はゲスト識別子。50ゲスト並行でもフローの持ち主が分かる。実クライアントとの対応は `guest connected from` の行だけが持つ
- クローズ行のバイト数は方向つき。`-> 56 B` はゲストが送った量、`<- 868 B` は返ってきた量
- `<-` が主役になるのはICMPの応答行だけ。それ以外の行の矢印は接続方向で固定なので、grepで数えられる
- 送信元ポートはopen行とclose行で一致する。フローの対応付けはこれで行う
- `deny` / `fail` / `drop` はフローログを切っていても常に出る(セキュリティ事象なので)
- ゲストIPは常に 10.0.2.15(ゲストごとに独立スタックのため)。ゲストの区別は `[gN]` で行う

ライブラリとして使う場合、`Config.LogFlows` のデフォルトは false。フロー行はゲストのアクセス先の完全な記録になるため、組み込み側が明示的に有効化する。デーモン(`wsslirpd`)は監査目的なのでデフォルト有効。

## テスト

```
go test ./...
```

合成ゲスト(gVisor netstackをクライアント側にも立てて本物のARP/TCPハンドシェイクを喋らせる)でフレーム経路をE2E検証している。実インターネットへの疎通テストは起動中のデーモンを指して:

```
WSSLIRP_E2E_URL='ws://127.0.0.1:8098/net?token=test' go test ./pkg/wsstransport -run RealInternet -v
```

## ロードマップ(台帳)

未実装。必要になった実測時点で取り出す:

- UDS / インプロセストランスポート
- ゲストごとの帯域制限・メトリクス
- IPv6
- DHCPオプションのカスタマイズ(NTP、ドメイン名など)
