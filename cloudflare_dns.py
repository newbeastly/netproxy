print("=== [DEBUG] cloudflare_dns.py start ===")

import os
import glob
import zipfile
import yaml
import requests
import time

# 获取 Cloudflare 相关环境变量
api_token = os.environ.get('CLOUDFLARE_API_KEY')
zone_id = os.environ.get('CLOUDFLARE_ZONE_ID')
domain = os.environ.get('CLOUDFLARE_DOMAIN')

print(f"[DEBUG] DOMAIN={domain}, ZONE_ID={zone_id}, API_TOKEN={'SET' if api_token else 'MISSING'}")

if not (api_token and zone_id and domain):
    raise RuntimeError("请设置 CLOUDFLARE_API_KEY、CLOUDFLARE_ZONE_ID、CLOUDFLARE_DOMAIN 环境变量")

def extract_ips_from_txt(filename):
    with open(filename) as f:
        return [line.strip() for line in f if line.strip()]

def extract_ips_from_yaml(filename):
    with open(filename) as f:
        y = yaml.safe_load(f)
        if isinstance(y, dict) and 'ips' in y:
            return y['ips']
        elif isinstance(y, list):
            return y
        return []

def extract_ips_from_zip(filename):
    ips = []
    with zipfile.ZipFile(filename) as z:
        for name in z.namelist():
            if name.endswith('.txt'):
                with z.open(name) as f:
                    ips += [line.decode().strip() for line in f if line.strip()]
            elif name.endswith('.yaml') or name.endswith('.yml'):
                with z.open(name) as f:
                    y = yaml.safe_load(f)
                    if isinstance(y, dict) and 'ips' in y:
                        ips += y['ips']
                    elif isinstance(y, list):
                        ips += y
    return ips

# 汇总ip目录下所有IP，去重
ips = set()
for fn in glob.glob("ip/*"):
    if fn.endswith('.txt'):
        ips.update(extract_ips_from_txt(fn))
    elif fn.endswith('.yaml') or fn.endswith('.yml'):
        ips.update(extract_ips_from_yaml(fn))
    elif fn.endswith('.zip'):
        ips.update(extract_ips_from_zip(fn))
ips = list({ip for ip in ips if ip})

print("[DEBUG] IPs to add:", ips)

if not ips:
    print("[WARNING] 没有找到任何可用IP，脚本结束。")
    exit(0)

headers = {
    "Authorization": f"Bearer {api_token}",
    "Content-Type": "application/json"
}

def list_a_records():
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&per_page=100"
    result = []
    page = 1
    while True:
        resp = requests.get(url + f"&page={page}", headers=headers).json()
        if not resp.get("success") or "result" not in resp:
            print("Cloudflare API 返回异常：", resp)
            break
        result += resp['result']
        if page >= resp['result_info']['total_pages']:
            break
        page += 1
    return result

def delete_record(record_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    resp = requests.delete(url, headers=headers)
    print(f"Deleted record {record_id}: {resp.status_code}")

# 只操作 netproxy.<domain>
record_name = f"netproxy.{domain}"

# 查询所有现有的 netproxy.<domain> A记录并删除
existing_records = list_a_records()
for rec in existing_records:
    if rec["name"] == record_name:
        delete_record(rec["id"])
        time.sleep(0.2)

# 给每个IP都添加 netproxy.<domain> 记录
for ip in ips:
    data = {
        "type": "A",
        "name": record_name,
        "content": ip,
        "ttl": 1,
        "proxied": True
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    resp = requests.post(url, json=data, headers=headers)
    print(f"Add {record_name} {ip}: {resp.json()}")
    time.sleep(0.5)

print("=== [DEBUG] cloudflare_dns.py end ===")
