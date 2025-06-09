# netproxy

本项目用于自动管理 Cloudflare DNS 中的 A 记录，结合远程/本地的 IP 列表动态变更，适合用于临时节点轮换、代理解析等场景。

## 功能简介

- **远程 IP 源管理**：可通过 `ip/url` 文件指定包含 IP 地址的远程链接，自动抓取最新 IP。
- **本地 IP 文件支持**：支持本地上传含 IP 地址的文件，兼容 `.txt`、`.zip`、`.yaml`、`.rar` 多种格式，自动正则提取其中所有 IPv4 地址。
- **Cloudflare DNS 自动同步**：自动将收集到的 IP 作为指定子域名的 A 记录批量同步到 Cloudflare，仅保留最近 3 小时内的记录，最多 10 条。
- **GitHub Actions 自动化**：支持手动触发、定时（每 3 小时）、文件变更自动运行，无需本地部署。
- **一键运行**：通过 GitHub Actions 工作流即可自动完成所有流程。

## 使用方法

### 1. 准备环境变量（Secrets）

在仓库的 **Settings → Secrets and variables → Actions** 下，添加以下 Repository secrets：

- `CLOUDFLARE_API_KEY`：Cloudflare 的 API Token，需具备 Zone DNS 编辑权限
- `CLOUDFLARE_ZONE_ID`：Cloudflare 的 Zone ID（可在 Cloudflare 后台获取）
- `CLOUDFLARE_DOMAIN`：主域名，例如 `example.com`

可选：你可以在 `ip/url` 中填写远程 IP 列表的链接，每行一个 URL，格式示例：

```
https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestProxy/bestproxy.txt
```

### 2. 本地上传 IP 文件

将含有 IP 地址的文件（支持 txt、zip、yaml、rar 格式）上传至 `ip/local/` 目录。例如：

- `ip/local/mylist.txt`
- `ip/local/proxies.yaml`
- `ip/local/ips.zip`

### 3. 触发同步

- **自动触发**：每 3 小时自动运行；或每次 `ip/local/` 目录有文件变化时自动运行。
- **手动触发**：在 GitHub Actions 页面选择 `Run Cloudflare DNS Script`，点击 **Run workflow**。

### 4. 工作流文件说明

`.github/workflows/run-cloudflare-dns.yml`  
定义了自动化流程，无需修改即可使用。

主要步骤：

1. 检出仓库代码
2. 安装依赖（见 `requirements.txt`）
3. 运行 `cloudflare_dns.py`，完成 IP 收集、去重、Cloudflare 记录同步

### 5. 主要脚本说明

- `cloudflare_dns.py`：主逻辑脚本，负责 IP 抓取/解析、DNS 记录增删、历史记录清理等
- `requirements.txt`：依赖库（requests、pyyaml、rarfile 等）

### 6. 注意事项

- 每次最多只会保留 10 条最新 IP 作为 DNS 记录，超时（>3 小时）记录会自动删除。
- 远程 URL 或本地文件中的 IP 支持混合使用，自动去重。
- 需要 Cloudflare 账户的 API 权限，且主域名 Zone ID 配置正确。
- 适用于临时节点、动态出口等场景，不建议用于正式生产环境的主域名。

### 7. 目录结构示例

```
.
├── cloudflare_dns.py
├── requirements.txt
├── ip/
│   ├── url                # 远程IP源URL，每行一个
│   └── local/             # 本地上传的文件目录
│       ├── result.csv
│       ├── proxies.zip
│       └── ...
├── .github/
│   └── workflows/
│       └── run-cloudflare-dns.yml
└── README.md
```

## 参考/致谢

- [Cloudflare API 文档](https://api.cloudflare.com/)
- [GitHub Actions 官方文档](https://docs.github.com/en/actions)
- [ymyuuu/IPDB](https://github.com/ymyuuu/IPDB) 等公共 IP 数据

---

如有问题，欢迎提 Issue 或 PR！
