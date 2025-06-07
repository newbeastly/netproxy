import os
import zipfile
import yaml
import requests
import time
import re
import rarfile

# 环境变量
api_token = os.environ.get('CLOUDFLARE_API_KEY')
zone_id = os.environ.get('CLOUDFLARE_ZONE_ID')
domain = os.environ.get('CLOUDFLARE_DOMAIN')

def is_valid_ip(ip):
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return False
    return all(0 <= int(x) <= 255 for x in ip.split('.'))

def extract_ips_from_txt(filename_or_obj):
    ips = []
    try:
        if hasattr(filename_or_obj, 'read'):
            lines = filename_or_obj.read().decode() if hasattr(filename_or_obj, 'decode') else filename_or_obj.read()
            if isinstance(lines, bytes): lines = lines.decode()
            lines = lines.splitlines()
        else:
            with open(filename_or_obj) as f:
                lines = f.readlines()
        for line in lines:
            line = line.strip()
            if is_valid_ip(line):
                ips.append(line)
    except Exception as e:
        print(f"[ERROR] 读取TXT失败: {e}")
    return ips

def extract_ips_from_yaml(filename_or_obj):
    ips = []
    try:
        if hasattr(filename_or_obj, 'read'):
            content = filename_or_obj.read().decode() if hasattr(filename_or_obj, 'decode') else filename_or_obj.read()
            if isinstance(content, bytes): content = content.decode()
            y = yaml.safe_load(content)
        else:
            with open(filename_or_obj) as f:
                y = yaml.safe_load(f)
        if isinstance(y, dict) and 'ips' in y:
            ips = y['ips']
        elif isinstance(y, list):
            ips = y
        ips = [ip.strip() for ip in ips if isinstance(ip, str) and is_valid_ip(ip.strip())]
    except Exception as e:
        print(f"[ERROR] 读取YAML失败: {e}")
    return ips

def extract_ips_from_zip(filename):
    ips = []
    try:
        with zipfile.ZipFile(filename) as z:
            for name in z.namelist():
                if name.endswith('.txt'):
                    with z.open(name) as f:
                        ips += extract_ips_from_txt(f)
                elif name.endswith('.yaml') or name.endswith('.yml'):
                    with z.open(name) as f:
                        ips += extract_ips_from_yaml(f)
    except Exception as e:
        print(f"[ERROR] 读取ZIP失败: {e}")
    return ips

def extract_ips_from_rar(filename):
    ips = []
    try:
        with rarfile.RarFile(filename) as r:
            for name in r.namelist():
                if name.endswith('.txt'):
                    with r.open(name) as f:
                        ips += extract_ips_from_txt(f)
                elif name.endswith('.yaml') or name.endswith('.yml'):
                    with r.open(name) as f:
                        ips += extract_ips_from_yaml(f)
    except Exception as e:
        print(f"[ERROR] 读取RAR失败: {e}")
    return ips

def extract_ips_from_url(url):
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        ips = [line.strip() for line in lines if is_valid_ip(line.strip())]
        print(f"[DEBUG] 从远程 {url} 获取到 {len(ips)} 个合法IP")
        return ips
    except Exception as e:
        print(f"[ERROR] 下载远程IP列表失败 {url} : {e}")
        return []

# 1. 读取远程源
ips = set()
remote_url_file = 'ip/url'
if os.path.exists(remote_url_file):
    with open(remote_url_file, encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if url:
                ips.update(extract_ips_from_url(url))

# 2. 读取本地上传
local_dir = 'ip/local'
if os.path.isdir(local_dir):
    for fn in os.listdir(local_dir):
        path = os.path.join(local_dir, fn)
        if fn.endswith('.txt'):
            ips.update(extract_ips_from_txt(path))
        elif fn.endswith('.yaml') or fn.endswith('.yml'):
            ips.update(extract_ips_from_yaml(path))
        elif fn.endswith('.zip'):
            ips.update(extract_ips_from_zip(path))
        elif fn.endswith('.rar'):
            ips.update(extract_ips_from_rar(path))

ips = list(ips)
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

record_name = f"netproxy.{domain}"
existing_records = list_a_records()
for rec in existing_records:
    if rec["name"] == record_name:
        delete_record(rec["id"])
        time.sleep(0.2)

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
