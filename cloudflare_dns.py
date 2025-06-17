import os
import zipfile
import yaml
import requests
import time
import re
import rarfile
from datetime import datetime, timezone
import csv

# 环境变量
api_token = os.environ.get('CLOUDFLARE_API_KEY')
zone_id = os.environ.get('CLOUDFLARE_ZONE_ID')
domain = os.environ.get('CLOUDFLARE_DOMAIN')

record_name = f"netproxy.{domain}"
now = datetime.now(timezone.utc)

def is_valid_ip(ip):
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return False
    return all(0 <= int(x) <= 255 for x in ip.split('.'))

def extract_ips_from_txt(filename_or_obj):
    ips = []
    source = filename_or_obj if isinstance(filename_or_obj, str) else 'stream'
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
        if ips:
            print(f"[INFO] 从TXT文件 {source} 中获取到 {len(ips)} 个IP：", ", ".join(ips))
    except Exception as e:
        print(f"[ERROR] 读取TXT失败 {source}: {e}")
    return ips

def extract_ips_from_yaml(filename_or_obj):
    ips = []
    source = filename_or_obj if isinstance(filename_or_obj, str) else 'stream'
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
        if ips:
            print(f"[INFO] 从YAML文件 {source} 中获取到 {len(ips)} 个IP：", ", ".join(ips))
    except Exception as e:
        print(f"[ERROR] 读取YAML失败 {source}: {e}")
    return ips

def extract_ips_from_zip(filename):
    ips = []
    try:
        with zipfile.ZipFile(filename) as z:
            print(f"[INFO] 正在处理ZIP文件 {filename}")
            for name in z.namelist():
                if name.endswith('.txt'):
                    with z.open(name) as f:
                        new_ips = extract_ips_from_txt(f)
                        if new_ips:
                            print(f"[INFO] 从ZIP中的文件 {name} 获取到 {len(new_ips)} 个IP")
                        ips += new_ips
                elif name.endswith('.yaml') or name.endswith('.yml'):
                    with z.open(name) as f:
                        new_ips = extract_ips_from_yaml(f)
                        if new_ips:
                            print(f"[INFO] 从ZIP中的文件 {name} 获取到 {len(new_ips)} 个IP")
                        ips += new_ips
    except Exception as e:
        print(f"[ERROR] 读取ZIP失败 {filename}: {e}")
    return ips

def extract_ips_from_rar(filename):
    ips = []
    try:
        with rarfile.RarFile(filename) as r:
            print(f"[INFO] 正在处理RAR文件 {filename}")
            for name in r.namelist():
                if name.endswith('.txt'):
                    with r.open(name) as f:
                        new_ips = extract_ips_from_txt(f)
                        if new_ips:
                            print(f"[INFO] 从RAR中的文件 {name} 获取到 {len(new_ips)} 个IP")
                        ips += new_ips
                elif name.endswith('.yaml') or name.endswith('.yml'):
                    with r.open(name) as f:
                        new_ips = extract_ips_from_yaml(f)
                        if new_ips:
                            print(f"[INFO] 从RAR中的文件 {name} 获取到 {len(new_ips)} 个IP")
                        ips += new_ips
    except Exception as e:
        print(f"[ERROR] 读取RAR失败 {filename}: {e}")
    return ips

def extract_ips_from_url(url):
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        ips = [line.strip() for line in lines if is_valid_ip(line.strip())]
        print(f"[INFO] 从远程URL {url} 获取到 {len(ips)} 个IP：", ", ".join(ips))
        return ips
    except Exception as e:
        print(f"[ERROR] 下载远程IP列表失败 {url}: {e}")
        return []

def extract_ips_from_csv(filename):
    ips = []
    try:
        with open(filename, mode='r', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip the header row
            for row in reader:
                ip = row[0].strip()
                if is_valid_ip(ip):
                    ips.append(ip)
        if ips:
            print(f"[INFO] 从CSV文件 {filename} 中获取到 {len(ips)} 个IP：", ", ".join(ips))
    except Exception as e:
        print(f"[ERROR] 读取CSV文件失败 {filename}: {e}")
    return ips

def extract_ips_from_any_file(filename):
    """通用正则提取所有本地文件中的IP地址"""
    ips = []
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        found = re.findall(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', content)
        ips = [ip for ip in found if is_valid_ip(ip)]
        if ips:
            print(f"[INFO] 从本地文件 {filename} 中提取到 {len(ips)} 个IP：", ", ".join(ips))
    except Exception as e:
        print(f"[ERROR] 读取文件失败 {filename}: {e}")
    return ips

# 采集IP逻辑：优选本地再补远程
MAX_IPS = 10
local_dir = 'ip/local'
local_ips = []
if os.path.isdir(local_dir):
    print(f"[INFO] 开始扫描本地目录：{local_dir}")
    for fn in os.listdir(local_dir):
        path = os.path.join(local_dir, fn)
        if os.path.isfile(path):
            if fn.lower().endswith('.csv'):
                new_ips = extract_ips_from_csv(path)
            else:
                new_ips = extract_ips_from_any_file(path)
            local_ips.extend(new_ips)
print(f"[INFO] 本地收集到 {len(local_ips)} 个IP")

# 如本地不足MAX_IPS，再补充远程
remote_ips = []
if len(local_ips) < MAX_IPS:
    url_file = 'ip/url'
    if os.path.exists(url_file):
        print(f"[INFO] 处理远程URL文件：{url_file}")
        with open(url_file, encoding="utf-8") as f:
            for line in f:
                url = line.strip()
                if url:
                    new_ips = extract_ips_from_url(url)
                    remote_ips.extend(new_ips)
    # 去除已在本地的IP
    remote_ips = [ip for ip in remote_ips if ip not in local_ips]
    # 只补充到足额
    need = MAX_IPS - len(local_ips)
    remote_ips = remote_ips[:need]
ips = local_ips + remote_ips
print(f"[INFO] 最终用于同步的IP数量：{len(ips)}，列表：")
for ip in ips:
    print(ip)


# 第二轮筛选：与现有IP进行对比并去重
# 如果netproxy_records未定义则使用空列表
if 'netproxy_records' not in locals() and 'netproxy_records' not in globals():
    print("[ERROR] netproxy_records未定义，使用空列表代替")
    netproxy_records = []

existing_records = [rec['content'] for rec in netproxy_records]
ips_before_dedup = local_ips + remote_ips
ips_after_dedup = [ip for ip in ips_before_dedup if ip not in existing_records]

# 如果有重复IP被移除，则从远程IP池中补充
need补充 = MAX_IPS - len(ips_after_dedup)
if need补充 > 0:
    # 从远程IP池中获取新的IP补充
    fresh_ips = []
    for ip in remote_ips:
        if ip not in ips_after_dedup and ip not in existing_records:
            fresh_ips.append(ip)
            if len(fresh_ips) >= need补充:
                break
    ips_after_dedup += fresh_ips

# 最终用于同步的IP列表
ips = ips_after_dedup[:MAX_IPS]
print(f"[INFO] 经过第二轮筛选后的最终IP数量：{len(ips)}，列表：")
for ip in ips:
    print(ip)

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

def delete_record(record_id, ip):
    """删除指定ID的记录"""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    resp = requests.delete(url, headers=headers)
    if resp.status_code == 200:
        print(f"[INFO] 删除IP记录： {ip}")
    else:
        print(f"[ERROR] 删除IP记录失败： {ip}, 响应: {resp.json()}")

def parse_cloudflare_time(timestr):
    """解析Cloudflare时间格式，兼容带微秒和不带微秒"""
    try:
        return datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

record_name = f"netproxy.{domain}"
now = datetime.now(timezone.utc)

# 查询所有 netproxy.<domain> 的 A记录
print(f"[INFO] 开始查询域名 {record_name} 的现有记录")
all_a_records = list_a_records()
netproxy_records = [rec for rec in all_a_records if rec['name'] == record_name]

# 按创建时间降序排序，最新的在前面
netproxy_records.sort(key=lambda x: parse_cloudflare_time(x.get('created_on', "1970-01-01T00:00:00Z")), reverse=True)

# 第二轮筛选：与现有IP进行对比并去重
existing_records = [rec['content'] for rec in netproxy_records]
ips_before_dedup = local_ips + remote_ips
ips_after_dedup = [ip for ip in ips_before_dedup if ip not in existing_records]

# 如果有重复IP被移除，则从远程IP中补充
need补充 = MAX_IPS - len(ips_after_dedup)
if need补充 > 0:
    # 从远程IP池中获取新的IP补充
    fresh_ips = []
    for ip in remote_ips:
        if ip not in ips_after_dedup and ip not in existing_records:
            fresh_ips.append(ip)
            if len(fresh_ips) >= need补充:
                break
    ips_after_dedup += fresh_ips

# 最终用于同步的IP列表
ips = ips_after_dedup[:MAX_IPS]
print(f"[INFO] 最终用于同步的IP数量：{len(ips)}，列表：")
for ip in ips:
    print(ip)

# 计算需要保留的旧记录数量
num_new_ips = len(ips)
num_old_ips_to_keep = max(MAX_IPS - num_new_ips, 0)

# 保留最新的旧记录
old_ips_to_keep = [(rec['id'], rec['content']) for rec in netproxy_records[:num_old_ips_to_keep]]

# 需要删除的所有旧记录（包括不需要保留的旧记录）
records_to_delete = [(rec['id'], rec['content']) for rec in netproxy_records[num_old_ips_to_keep:]]

if records_to_delete:
    print(f"[INFO] 需要删除 {len(records_to_delete)} 条多余记录以保持最多 {MAX_IPS} 条记录")
    for record_id, ip in records_to_delete:
        delete_record(record_id, ip)
        time.sleep(0.2)
else:
    print("[INFO] 所有记录均无需删除")

# 合并未超时的旧IP和本次新IP，去重并保持顺序
current_ips_set = set([rec[1] for rec in old_ips_to_keep])
final_ips = []
for ip in ips:
    if ip not in current_ips_set:
        final_ips.append(ip)
        current_ips_set.add(ip)
    if len(final_ips) >= MAX_IPS - num_old_ips_to_keep:
        break

print(f"[INFO] 最终将添加 {len(final_ips)} 个IP记录：")
for ip in final_ips:
    print(ip)

# 添加新IP记录
new_added = 0
skipped = 0
for ip in final_ips:
    if any(rec['content'] == ip for rec in old_ips_to_keep):
        skipped += 1
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
    if resp.status_code == 200:
        print(f"[INFO] 添加记录 {record_name} -> {ip}")
        new_added += 1
    else:
        print(f"[ERROR] 添加记录失败： {record_name} -> {ip}, 响应: {resp.json()}")
    time.sleep(0.5)

print(f"[INFO] 完成！新增 {new_added} 条记录，跳过 {skipped} 条已存在记录")
