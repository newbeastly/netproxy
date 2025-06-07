import os
import zipfile
import yaml
import requests
import time
import re
import rarfile
import datetime

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
print("[DEBUG] 本次收集到的待添加IP:", ips)

if not ips:
    print("[WARNING] 没有找到任何可用IP，脚本结束。")
    exit(0)

headers = {
    "Authorization": f"Bearer {api_token}",
    "Content-Type": "application/json"
}

def list_a_records():
    """获取所有A记录"""
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
    """删除指定ID的记录"""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    resp = requests.delete(url, headers=headers)
    print(f"Deleted record {record_id}: {resp.status_code}")

def parse_cloudflare_time(timestr):
    """解析Cloudflare时间格式"""
    return datetime.datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%SZ")

record_name = f"netproxy.{domain}"
now = datetime.datetime.utcnow()

# 3. 查询所有 netproxy.<domain> 的 A记录
all_a_records = list_a_records()
netproxy_records = [rec for rec in all_a_records if rec['name'] == record_name]

# 4. 检查是否有超时(>3小时)记录
expired_ids = []
unexpired_ips = set()
for rec in netproxy_records:
    created_on = parse_cloudflare_time(rec.get('created_on', "1970-01-01T00:00:00Z"))
    age_hours = (now - created_on).total_seconds() / 3600
    if age_hours > 3:
        expired_ids.append(rec['id'])
    else:
        unexpired_ips.add(rec['content'])

if expired_ids:
    print(f"[INFO] 存在 {len(expired_ids)} 条超过3小时的 netproxy 记录，将删除这些记录。")
    for record_id in expired_ids:
        delete_record(record_id)
        time.sleep(0.2)
else:
    print("[INFO] 所有 netproxy 记录均未超过3小时，将直接添加新IP。")

# 5. 合并未超时的旧IP和本次新IP，去重，最多只保留50条
all_ips = list(unexpired_ips.union(set(ips)))
all_ips = all_ips[:50]  # 最多50条

print("[DEBUG] 最终将添加的IP列表：", all_ips)

# 6. 添加新IP记录（避免Cloudflare报错，可以先检查已存在IP是否已存在于现有记录，若已存在可不再添加；如果要全量覆盖可全加）
for ip in all_ips:
    # 不重复添加已存在的未超时IP
    if ip in unexpired_ips:
        continue
    data = {
        "type": "A",
        "name": record_name,
        "content": ip,
        "ttl": 1,
        "proxied": False  # 关闭代理，灰色云朵
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    resp = requests.post(url, json=data, headers=headers)
    print(f"Add {record_name} {ip}: {resp.json()}")
    time.sleep(0.5)
