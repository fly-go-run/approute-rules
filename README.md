# approute-rules

[AppRoute](https://github.com/fly-go-run/AppRoute) 内置规则集的数据仓库。每天从许可证清楚的上游自动编译，发布到 `release` 分支。`main` 分支放编译器和构建脚本。

## 数据来源

| 输出 | 来源 | 许可证 |
|---|---|---|
| `geosite/*.txt` | [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | MIT |
| `geosite/cn.txt`（补充） | [felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) 的 `accelerated-domains.china.conf`，只并入 `cn` | WTFPL |
| `geoip/<cc>.txt`（国家 / 地区代码，小写两位，含 `cn`） | [APNIC delegated-apnic-latest](https://ftp.apnic.net/stats/apnic/delegated-apnic-latest) 该国家 / 地区的 IPv4 / IPv6 分配记录 | APNIC 使用条款，可自由下载使用 |
| `geoip/telegram.txt` | [Telegram 官方 cidr.txt](https://core.telegram.org/resources/cidr.txt) | 官方公布 |
| `geoip/google.txt` | Google 官方 [goog.json](https://www.gstatic.com/ipranges/goog.json) 减去 [cloud.json](https://www.gstatic.com/ipranges/cloud.json) | 官方公布 |
| `geoip/private.txt` | 本仓库写死的局域网列表 | MIT |

各来源的声明见 [NOTICE](NOTICE)。APNIC 数据是地址分配登记，不是物理位置，和商业 GeoIP 库的结果不会完全一致。**APNIC 只登记亚太地区**：`cn`、`jp`、`sg`、`kr` 等亚太国家的数据基本完整，但 `us`、`gb`、`de`、`fr` 等国家的大部分地址由 ARIN、RIPE NCC 等登记，这里只有 APNIC 下发的那一小部分，不能当完整列表用。这四个机构之外没有数据的代码不提供。Netflix 没有可用的官方 IP 来源，不提供 `geoip/netflix.txt`。

## 文件和格式

两种格式都是 mihomo 规则集的 `text` 格式，每行一条，没有注释。

- `geosite/<name>.txt`（`domain` 行为）：`+.example.com` 匹配这个域名和它的所有子域名，`example.com` 只匹配这个域名。
- `geoip/<name>.txt`（`ipcidr` 行为）：每行一个 CIDR，IPv4 在前，IPv6 在后，已合并相邻和重叠的段。

`geosite` 是 v2fly 的全部分类（约 1500 个，文件名和 v2fly 的 `data/` 一致，小写，带 `!` 的也在，例如 `category-ai-!cn`），`cn` 另并入 dnsmasq-china-list；只有 `keyword:` / `regexp:` 条目的分类没有可输出的内容，会跳过并记在 `report.txt`。`geoip` 是 APNIC 覆盖的每个国家 / 地区代码（约 80 个），外加 `private`、`telegram`、`google`。内置默认用到的 15 个 `geosite` 和 4 个 `geoip` 为空时整次构建失败。`index.txt` 列出发布的全部文件，客户端可以用它判断某个名字是否存在。

`domain` 行为放不下 `keyword:` 和 `regexp:` 条目，编译时跳过，`report.txt` 里记着每个集合跳过了多少条。`geosite` 的 `include:` 和 `@属性` 过滤按 v2fly 自己的规则展开，`full:` 条目被同名或父级的后缀条目覆盖时会去重。

`geoip/private.txt` 是 IANA 特殊用途地址段（RFC 6890）：RFC 1918、运营商 NAT（`100.64.0.0/10`）、环回、链路本地、文档与测试段、基准测试段（`198.18.0.0/15`）、组播与保留段、IPv6 的未指定与环回、ULA、链路本地、组播。

## 下载地址

```
https://github.com/fly-go-run/approute-rules/raw/release/geosite/<name>.txt
https://github.com/fly-go-run/approute-rules/raw/release/geoip/<name>.txt
```

例如 `https://github.com/fly-go-run/approute-rules/raw/release/geosite/cn.txt`。`release` 分支还有 `NOTICE`、`index.txt` 和 `report.txt`（各集合条目数、跳过数、上游版本）。

## 构建

```sh
go run ./cmd/rulegen fetch -work work                       # 下载上游数据（GITHUB_TOKEN 可选，用于查 dnsmasq-china-list 的提交号）
go run ./cmd/rulegen build -work work -out out              # 编译、校验、写出
go run ./cmd/rulegen build -work work -out out -prev <上一次发布的目录>
go vet ./... && go test ./...
```

`build` 先在内存里编译并校验：每个文件非空、每行语法正确，给了 `-prev` 时每个文件的条目数、以及文件总数都不少于上一次的一半。任何一项不通过就以非零状态退出，不写任何文件。GitHub Actions（`.github/workflows/build.yml`）每天运行一次，也可手动触发，规则数据有变化才提交到 `release` 分支。

## 许可证

编译器和脚本：MIT（[LICENSE](LICENSE)）。输出数据的许可证随各自的来源，见 [NOTICE](NOTICE)。
