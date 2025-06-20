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
            print(f"[INFO] 从TXT文件 {source} 中获取到 {len(ips)} 个IP：{ips}")
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
            print(f"[INFO] 从YAML文件 {source} 中获取到 {len(ips)} 个IP：{ips}")
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
        print(f"[INFO] 从远程URL {url} 获取到 {len(ips)} 个IP：{ips}")
        return ips
    except Exception as e:
        print(f"[ERROR] 下载远程IP列表失败 {url}: {e}")
        return []

def extract_ips_from_any_file(filename):
    """通用正则提取所有本地文件中的IP地址"""
    ips = []
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        found = re.findall(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', content)
        ips = [ip for ip in found if is_valid_ip(ip)]
        if ips:
            print(f"[INFO] 从本地文件 {filename} 中提取到 {len(ips)} 个IP：{ips}")
    except Exception as e:
        print(f"[ERROR] 读取文件失败 {filename}: {e}")
    return ips

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
    # 根据内存偏好优化日志输出：仅保留关键数据（IP地址）
    ip_address = next((rec['content'] for rec in netproxy_records if rec['id'] == record_id), record_id)
    print(f"[INFO] 删除记录 {ip_address}")
    time.sleep(0.2)

def parse_cloudflare_time(timestr):
    """解析Cloudflare时间格式，兼容带微秒和不带微秒"""
    try:
        return datetime.datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return datetime.datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%SZ")

record_name = f"netproxy.{domain}"
now = datetime.datetime.utcnow()

# 查询所有 netproxy.<domain> 的 A记录
print(f"[INFO] 开始查询域名 {record_name} 的现有记录")
all_a_records = list_a_records()
netproxy_records = [rec for rec in all_a_records if rec['name'] == record_name]

# 检查是否有超时(>3小时)记录
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
    print(f"[INFO] 发现 {len(expired_ids)} 条超过3小时的记录需要删除")
    for record_id in expired_ids:
        # 根据内存偏好优化删除逻辑：增加错误码处理
        try:
            delete_record(record_id)
            time.sleep(0.2)
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] 删除记录失败 {record_id}: {str(e)}")
else:
    print("[INFO] 所有记录均未超过3小时")

# 采集IP逻辑：优选本地再补远程
MAX_IPS = 10
local_dir = 'ip/local'
local_ips = []  # ✅ 改用列表保持顺序
if os.path.isdir(local_dir):
    print(f"[INFO] 开始扫描本地目录：{local_dir}")
    for fn in sorted(os.listdir(local_dir)):  # 按文件名排序处理
        path = os.path.join(local_dir, fn)
        if os.path.isfile(path):
            new_ips = extract_ips_from_any_file(path)  # 保持文件内原始顺序
            # 保留顺序的去重合并
            for ip in new_ips:
                if ip not in local_ips:  # 🔁 顺序保留的去重
                    local_ips.append(ip)
print(f"[INFO] 本地收集到 {len(local_ips)} 个IP")

# 第二轮筛选：与现有IP去重
existing_ips = set(unexpired_ips)
local_ips = [ip for ip in local_ips if ip not in existing_ips]

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
    # 去除已在本地和现有IP的IP
    remote_ips = [ip for ip in remote_ips if ip not in local_ips and ip not in existing_ips]
    # 只补充到足额
    need = MAX_IPS - len(local_ips)
    remote_ips = remote_ips[:need]
ips = local_ips + remote_ips
print(f"[INFO] 初步用于同步的IP数量：{len(ips)}，列表：{ips}")

# 最终合并逻辑
ips = list(set(ips))  # 对新获取的IP自身去重
print(f"[INFO] 去重后可用新IP数量：{len(ips)}")

# 根据内存规范第7条：新IP达到最大值时应全部添加
if len(ips) >= MAX_IPS:
    all_ips = ips[:MAX_IPS]  # 直接使用新IP替换旧记录
else:
    # 根据内存规范第15条：合并新旧记录时必须全局去重
    total_records = list(existing_ips) + ips
    all_ips = list(set(total_records))[:MAX_IPS]  # 全局去重后取前MAX_IPS个

print(f"[INFO] 最终将添加 {len(all_ips)} 个IP记录：")
for ip in all_ips:
    print(ip)

if not ips:
    print("[WARNING] 没有找到任何可用IP，脚本结束。")
    exit(0)

# 添加新IP记录
new_added = 0
skipped = 0

# 获取当前有效记录数量
current_records = [rec for rec in netproxy_records if rec['content'] in all_ips]
current_count = len(current_records)

for ip in all_ips:
    if current_count >= MAX_IPS:
        print(f"[INFO] 当前有效记录已达上限({MAX_IPS}条)，停止添加新记录。")
        break

    if ip in unexpired_ips:
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
    print(f"[INFO] 添加记录：{ip}")
    new_added += 1
    current_count += 1  # 更新当前记录数量
    time.sleep(0.5)

print(f"[INFO] 完成！新增 {new_added} 条记录，跳过 {skipped} 条已存在记录")
