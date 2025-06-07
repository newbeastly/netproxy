import os
import glob
import zipfile
import yaml
import requests
import time
from datetime import datetime, timezone, timedelta

# 获取 Cloudflare 相关环境变量
api_token = os.environ.get('CLOUDFLARE_API_KEY')
zone_id = os.environ.get('CLOUDFLARE_ZONE_ID')
domain = os.environ.get('CLOUDFLARE_DOMAIN')

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
        result += resp['result']
        if page >= resp['result_info']['total_pages']:
            break
        page += 1
    return result

def delete_record(record_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    resp = requests.delete(url, headers=headers)
    print(f"Deleted record {record_id}: {resp.status_code}")

# 删除所有超过24小时的 proxy<n>.<domain> 的A记录
existing_records = list_a_records()
now = datetime.now(timezone.utc)
for rec in existing_records:
    if rec["name"].startswith("proxy") and rec["name"].endswith(domain):
        created = datetime.strptime(rec["created_on"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        if now - created > timedelta(hours=24):
            delete_record(rec["id"])

# 遍历ip，按 proxy1.domain, proxy2.domain ... 重新写入
for idx, ip in enumerate(ips, 1):
    record_name = f"proxy{idx}.{domain}"

    # 查找同名A记录
    matched = [r for r in existing_records if r["name"] == record_name]
    for rec in matched:
        delete_record(rec["id"])
        time.sleep(0.2)

    # 添加新A记录
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
