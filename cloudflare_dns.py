import os
import re
import requests
import datetime
import time

# 环境变量
API_TOKEN = os.environ.get('CLOUDFLARE_API_KEY')
ZONE_ID = os.environ.get('CLOUDFLARE_ZONE_ID')
DOMAIN = os.environ.get('CLOUDFLARE_DOMAIN')
IP_MAX = int(os.environ.get('IP_MAX', 10))  # 支持自定义最大A记录数量

RECORD_NAME = f"netproxy.{DOMAIN}"
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

def is_valid_ip(ip):
    return re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip) and all(0 <= int(x) <= 255 for x in ip.split('.'))

def list_a_records():
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/dns_records?type=A&per_page=100"
    records = []
    page = 1
    while True:
        resp = requests.get(f"{url}&page={page}", headers=HEADERS).json()
        if not resp.get("success") or "result" not in resp:
            print("[ERROR] Cloudflare API error:", resp)
            break
        records += resp["result"]
        if page >= resp["result_info"]["total_pages"]:
            break
        page += 1
    return [rec for rec in records if rec["name"] == RECORD_NAME]

def parse_time(timestr):
    try:
        return datetime.datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%S.%fZ")
    except:
        return datetime.datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%SZ")

def delete_record(record_id, ip_address):
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/dns_records/{record_id}"
    requests.delete(url, headers=HEADERS)
    print(f"[删除] {ip_address} ({record_id})")
    time.sleep(0.2)

def extract_ips_from_file(filename):
    ips = []
    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        for ip in re.findall(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', content):
            if is_valid_ip(ip) and ip not in ips:
                ips.append(ip)
    except Exception as e:
        print(f"[ERROR] 读取本地文件失败 {filename}: {e}")
    return ips

def extract_ips_from_url(url):
    ips = []
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            ip = line.strip()
            if is_valid_ip(ip) and ip not in ips:
                ips.append(ip)
    except Exception as e:
        print(f"[ERROR] 下载远程IP失败 {url}: {e}")
    return ips

def main():
    print(f"[INFO] 查询现有A记录: {RECORD_NAME}")
    now = datetime.datetime.utcnow()
    netproxy_records = list_a_records()
    expired_ids = []
    valid_records = []
    valid_ips = []
    for rec in netproxy_records:
        created = parse_time(rec.get("created_on", "1970-01-01T00:00:00Z"))
        age = (now - created).total_seconds() / 3600
        if age > 3:
            expired_ids.append((rec["id"], rec["content"]))
        else:
            valid_records.append(rec)
            valid_ips.append(rec["content"])

    # 删除过期记录
    if expired_ids:
        print(f"[INFO] 发现 {len(expired_ids)} 条超过3小时的记录需要删除")
        for rid, ip in expired_ids:
            delete_record(rid, ip)
    else:
        print("[INFO] 没有过期记录")

    # 本地提取
    local_ips = []
    local_dir = "ip/local"
    if os.path.isdir(local_dir):
        for fn in sorted(os.listdir(local_dir)):
            path = os.path.join(local_dir, fn)
            if os.path.isfile(path):
                for ip in extract_ips_from_file(path):
                    if ip not in local_ips:
                        local_ips.append(ip)
    print(f"[INFO] 本地收集到 {len(local_ips)} 个IP: {local_ips}")

    # 去除已存在
    new_ips = [ip for ip in local_ips if ip not in valid_ips]

    # 如不足IP_MAX, 补远程
    if len(new_ips) < IP_MAX:
        url_file = "ip/url"
        remote_ips = []
        if os.path.exists(url_file):
            with open(url_file) as f:
                for line in f:
                    url = line.strip()
                    if url:
                        for ip in extract_ips_from_url(url):
                            if ip not in new_ips and ip not in local_ips and ip not in valid_ips:
                                remote_ips.append(ip)
        need = IP_MAX - len(new_ips)
        new_ips += remote_ips[:need]

    print(f"[INFO] 新获取IP共 {len(new_ips)} 个：{new_ips}")

    # 决策逻辑
    if len(new_ips) >= IP_MAX:
        # 1. 新IP充足，直接替换所有老记录（包括未过期）
        print(f"[INFO] 新IP已达{IP_MAX}个，将全部替换旧记录")
        for rec in valid_records:
            delete_record(rec["id"], rec["content"])
        all_ips = new_ips[:IP_MAX]
    else:
        # 2. 新IP不足，保留老的，补够到IP_MAX
        print(f"[INFO] 新IP不足{IP_MAX}个，保留现有未过期记录，补齐到{IP_MAX}个")
        retain_ips = [ip for ip in valid_ips if ip not in new_ips]
        all_ips = retain_ips + new_ips
        all_ips = all_ips[:IP_MAX]

    print(f"[INFO] 最终将添加的IP: {all_ips}")

    # 统计现有还存在的（未被删掉的）A记录
    now_records = list_a_records()
    now_ips = [rec["content"] for rec in now_records]

    # 添加新IP（只添加不存在的）
    added, skipped = 0, 0
    for ip in all_ips:
        if ip in now_ips:
            print(f"[跳过] 已存在: {ip}")
            skipped += 1
            continue
        data = {
            "type": "A",
            "name": RECORD_NAME,
            "content": ip,
            "ttl": 1,
            "proxied": False
        }
        url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/dns_records"
        resp = requests.post(url, json=data, headers=HEADERS)
        print(f"[添加] {ip}")
        added += 1
        time.sleep(0.5)

    # 再次确认总数量，如大于IP_MAX则清理多余
    final_records = list_a_records()
    if len(final_records) > IP_MAX:
        # 按创建时间排序，保留最新的IP_MAX条，其余删除
        sorted_records = sorted(final_records, key=lambda rec: parse_time(rec["created_on"]))
        records_to_delete = sorted_records[:-IP_MAX]
        print(f"[INFO] A记录数量超出上限，需删除 {len(records_to_delete)} 条多余记录")
        for rec in records_to_delete:
            delete_record(rec["id"], rec["content"])
        # 最终确认
        final_records = list_a_records()
        print(f"[INFO] 清理后A记录总数: {len(final_records)} (上限: {IP_MAX})")
    else:
        print(f"[INFO] 现有A记录总数: {len(final_records)} (上限: {IP_MAX})")

if __name__ == "__main__":
    main()
