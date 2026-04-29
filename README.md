# NetScope 网络视镜

NetScope 网络视镜是一个基于 Go 和 Gin 的 IP 查询与网络检测工具。项目同时提供网页工具和 JSON API，可用于查询 IP/域名归属地、ASN、运营商、安全风险、NAT 信息，以及 IPv4/IPv6 连通性等网络信息。

## 项目亮点

- 多数据源聚合：支持本地 MMDB 数据库和多个第三方 IP 数据源，按字段合并查询结果。
- 双栈检测：提供当前访问者 IPv4、IPv6、双栈状态和浏览器侧检测缓存。
- NAT 检测：支持服务端 STUN 检测和浏览器 WebRTC NAT 检测结果分析。
- 工具页面：内置 CIDR、子网、地址范围、NAT64、反向 DNS、带宽换算和屏幕测试等页面。
- API 优先：主要能力均提供 JSON 接口，便于接入监控、运维脚本或其他系统。

## 功能

- 查询当前访问者 IP、IPv4、IPv6 和双栈状态。
- 查询指定 IP 或域名的地理位置、网络信息、ASN 和安全风险信息。
- 聚合 MaxMind、DB-IP、IP2Location、IPInfo、ip-api、IPData、IPDataCloud、IPing、IP9、ProxyCheck 等数据源。
- 支持本地 MMDB 数据库和第三方 API 数据源混合使用。
- 提供 NAT 检测、IPv6 测试、CDN IPv6 测试、带宽换算、屏幕测试等页面。
- 提供 IPv4/IPv6、CIDR、子网掩码、地址范围、NAT64、反向 DNS 等工具页面。

## 技术栈

- Go 1.26
- Gin
- MaxMind GeoLite2 / DB-IP Lite MMDB
- HTML 模板和原生 JavaScript

## 目录结构

```text
.
├── assets/          # 前端静态资源
├── config/          # 环境变量和配置读取
├── data/            # MaxMind / DB-IP MMDB 数据库
├── model/           # API 响应和请求模型
├── provider/        # 第三方和本地数据源适配
├── service/         # 查询聚合、NAT、DNS、ASN 等业务逻辑
├── templates/       # HTML 页面模板
├── main.go          # HTTP 路由和服务入口
├── go.mod
└── go.sum
```

## 运行

项目当前监听端口固定为 `8779`。

### 环境要求

- Go 1.26 或兼容版本
- 可选：MaxMind / DB-IP MMDB 数据库文件
- 可选：第三方 IP 数据源 API Key

### 快速开始

克隆项目后进入目录：

```bash
git clone https://github.com/pseuo/NetScope.git
cd NetScope
```

安装依赖：

```bash
go mod download
```

复制配置文件：

```bash
cp .env.example .env
```

按需编辑 `.env`。没有 API Key 时服务仍可启动，但部分第三方数据源会被跳过或返回有限数据。

启动服务：

```bash
go run .
```

访问：

```text
http://localhost:8779
```

构建二进制：

```bash
go build -o ip-query .
```

运行测试：

```bash
go test ./...
```

## 数据库文件

项目默认从 `data/` 目录读取 MMDB 数据库：

- `GeoLite2-City.mmdb`
- `GeoLite2-Country.mmdb`
- `GeoLite2-ASN.mmdb`
- `dbip-city-lite-*.mmdb`
- `dbip-country-lite-*.mmdb`
- `dbip-asn-lite-*.mmdb`

MMDB 文件通常较大，且可能受各数据源许可限制。请自行从 MaxMind、DB-IP 等数据源下载，并上传到部署环境的 `data/` 目录，或通过环境变量指定文件路径。

## 配置

服务启动时会读取当前目录或可执行文件目录中的 `.env` 文件，也可以直接使用系统环境变量。未配置第三方 API Key 时，对应 provider 会跳过或返回有限数据。

### 数据库配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `MAXMIND_CITY_DB` | `./data/GeoLite2-City.mmdb` | MaxMind 城市库 |
| `MAXMIND_COUNTRY_DB` | `./data/GeoLite2-Country.mmdb` | MaxMind 国家库 |
| `MAXMIND_ASN_DB` | `./data/GeoLite2-ASN.mmdb` | MaxMind ASN 库 |
| `DBIP_CITY_DB` | `data/dbip-city-lite-*.mmdb` 最新文件 | DB-IP 城市库 |
| `DBIP_COUNTRY_DB` | `data/dbip-country-lite-*.mmdb` 最新文件 | DB-IP 国家库 |
| `DBIP_ASN_DB` | `data/dbip-asn-lite-*.mmdb` 最新文件 | DB-IP ASN 库 |

### 第三方数据源

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `IP2LOCATION_API_KEY` | 空 | IP2Location API Key |
| `IPINFO_API_KEY` | 空 | IPInfo API Key |
| `IPAPI_BASE_URL` | `http://ip-api.com/json` | ip-api 查询地址 |
| `IPDATA_API_KEY` | 空 | IPData API Key |
| `IPDATACLOUD_API_KEY` | 空 | IPDataCloud API Key |
| `IPING_BASE_URL` | `https://api.iping.cc/v1/query` | IPing API 地址 |
| `IP9_TOKEN` | 空 | IP9 Token |
| `PROXYCHECK_API_KEY` | 空 | ProxyCheck API Key |

### 连通性和超时

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `TRUSTED_PROXIES` | `127.0.0.1,::1` | Gin 信任的反向代理 IP/CIDR，逗号分隔；生产部署按实际代理显式配置，设为 `none` 可关闭信任代理 |
| `IPV4_CHECK_URL` | 空 | 浏览器 IPv4 检测 URL |
| `IPV6_CHECK_URL` | 空 | 浏览器 IPv6 检测 URL |
| `IPV6_CHECK_URLS` | 空 | 多个 IPv6 检测 URL，逗号分隔 |
| `PROVIDER_TIMEOUT_MS` | `2500` | 单个 provider 查询超时，毫秒 |
| `PROXYCHECK_TIMEOUT_MS` | `5000` | ProxyCheck 查询超时，毫秒 |
| `AGGREGATOR_TIMEOUT_MS` | `3000` | 聚合查询等待超时，毫秒 |
| `DNS_TIMEOUT_MS` | `1500` | 域名 A/AAAA 解析超时，毫秒 |
| `REVERSE_DNS_TIMEOUT_MS` | `1200` | 反向 DNS 查询超时，毫秒 |

### NAT 检测

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `NAT_STUN_URLS` | 内置多个公共 STUN 地址 | STUN 地址列表，逗号分隔 |
| `NAT_TURN_URLS` | 空 | TURN 地址列表，逗号分隔 |
| `NAT_TURN_USERNAME` | 空 | TURN 用户名 |
| `NAT_TURN_CREDENTIAL` | 空 | TURN 密码或凭据 |

可复制 `.env.example` 为 `.env` 后按需填写。示例：

```env
IPINFO_API_KEY=your_ipinfo_key
IPDATA_API_KEY=your_ipdata_key
PROXYCHECK_API_KEY=your_proxycheck_key
TRUSTED_PROXIES=127.0.0.1,::1,10.0.0.10
IPV6_CHECK_URL=https://ipv6.example.com/api/my-ipv6
PROVIDER_TIMEOUT_MS=2500
AGGREGATOR_TIMEOUT_MS=3000
DNS_TIMEOUT_MS=1500
```

## 页面路由

| 路由 | 说明 |
| --- | --- |
| `/` | 首页；HTML 请求返回页面，非 HTML 请求返回双栈 IP JSON |
| `/ip-search` | IP 查询页面 |
| `/ip-look` | 当前 IP 信息页面 |
| `/nat-test` | NAT 检测页面 |
| `/ipv6-test` | IPv6 测试页面 |
| `/cdn-ipv6` | CDN IPv6 测试页面 |
| `/bandwidth-calculator` | 带宽换算页面 |
| `/screen-test` | 屏幕测试页面 |
| `/tools` | IP 工具大全 |
| `/tools/:slug` | 指定 IP 工具页面 |

### IP 工具页面

`/tools/:slug` 当前支持：

- `ipv4-representations`
- `ipv6-nat64`
- `ipv4-range-to-cidr`
- `cidr-aggregator`
- `ipv4-cidr-to-netmask`
- `ipv6-range-to-cidr`
- `ipv4-wildcard-mask`
- `ipv4-subnet-calculator`
- `ipv6-subnet-calculator`
- `network-ip-calculator`
- `ipv6-expand-compress`
- `address-count-by-prefix`
- `cidr-to-ip-range`
- `netmask-to-cidr`
- `ipv6-cidr-to-range`
- `ip-address-type`
- `ip-validator`
- `reverse-dns-generator`
- `subnet-splitter`
- `bulk-ip-calculator`

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/more?lang=zh` | 查询当前访问者网络信息 |
| `GET` | `/img` | 返回包含当前 IP 和位置的图片 |
| `GET` | `/api/device-info` | 返回请求头、客户端 IP 和设备相关信息 |
| `GET` | `/api/ip?q=8.8.8.8&lang=zh` | 查询指定 IP 或域名 |
| `GET` | `/api/myip` | 返回当前访问者 IP 和 IP 版本 |
| `GET` | `/api/my-ipv4` | 返回当前访问者 IPv4 检测结果 |
| `GET` | `/api/my-ipv6` | 返回当前访问者 IPv6 检测结果 |
| `GET` | `/api/my-dual` | 返回当前访问者双栈检测结果 |
| `POST` | `/api/ip-cache` | 缓存浏览器侧检测到的 IPv4/IPv6 结果 |
| `GET` | `/api/ip-check-config` | 返回前端 IP 检测 URL 配置 |
| `GET` | `/api/my/network?lang=zh` | 查询当前访问者完整网络信息 |
| `GET` | `/api/nat/browser-config` | 返回浏览器 NAT 检测所需 ICE/STUN/TURN 配置 |
| `GET` | `/api/nat/server-stun?lang=zh` | 服务端 STUN NAT 检测 |
| `POST` | `/api/nat/browser-report?lang=zh` | 提交浏览器 WebRTC NAT 检测结果并分析 |

查询示例：

```bash
curl "http://localhost:8779/api/ip?q=8.8.8.8&lang=zh"
```

返回结构主要包含：

- `address`：查询目标、IP 版本、域名解析结果。
- `network`：ISP、组织、ASN、公司信息。
- `location`：国家、地区、城市、经纬度、时区等。
- `security`：代理、VPN、Tor、机房、移动网络和风险评分。
- `ip_type`：IP 类型标签。
- `nat`：NAT 检测信息。
- `source`：各字段采用的数据来源。

## 部署建议

- 反向代理后部署时，显式配置 `TRUSTED_PROXIES`，只信任自己的代理 IP 或 CIDR。
- 生产环境不要把 `TRUSTED_PROXIES` 设置为不受控的公网网段。
- 将 `.env`、API Key、TURN 凭据和数据库文件保留在服务器本地，不要提交到仓库。
- 如需浏览器侧 IPv4/IPv6 检测，请分别配置可通过对应网络访问的 `IPV4_CHECK_URL`、`IPV6_CHECK_URL` 或 `IPV6_CHECK_URLS`。
- 第三方 provider 有速率限制或超时风险，建议按业务需要调整 `PROVIDER_TIMEOUT_MS`、`AGGREGATOR_TIMEOUT_MS` 等参数。

## 注意事项

- 本地 MMDB 数据库文件需要放在 `data/` 目录，或通过环境变量指定路径。
- 如果部署在反向代理后，请确保代理正确传递 `CF-Connecting-IP`、`X-Forwarded-For`、`X-Real-IP` 等客户端 IP 头。
