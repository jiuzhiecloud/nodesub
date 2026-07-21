import requests
import base64
import json
import re
import urllib.parse
import ipaddress

# 1. 在这里填入你的订阅地址列表
SUB_URLS = [
    "https://www.xrayvip.com/free.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://github.com/ermaozi/get_subscribe/raw/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://raw.githubusercontent.com/jiuzhiecloud/free-node/refs/heads/main/testnode.txt",
    "https://raw.githubusercontent.com/jiuzhiecloud/free-sub/refs/heads/main/data/sub.txt"
]

# 2. 推广词黑名单（正则表达式）
AD_KEYWORDS = r"(官网|网址|获取|地址|最新|免费|更新|订阅|频道|群|TG|QQ|github|vip|proxy|节点|云|https://|Pawdroid|ermaozi|推荐|机场|)"

def decode_base64(s):
    """修复Base64并解码"""
    s = s.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except:
        return ""

def clean_alias(alias):
    """清洗节点别名中的推广信息"""
    alias = re.sub(AD_KEYWORDS, "", alias, flags=re.IGNORECASE)
    alias = re.sub(r'[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+', '', alias)
    alias = re.sub(r'^[_\-\|*\s,]+|[_\-\|*\s,]+$', '', alias)
    return alias if alias.strip() else "Auto_Node"

def is_valid_host(host):
    """校验 IPv4, IPv6 或合法域名"""
    if not host:
        return False
    # 检查是否为合法 IPv4 / IPv6
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    
    # 检查是否为合法域名
    # 域名正则规则：字母数字开头，包含中划线和点
    domain_regex = r"^(?=^.{1,254}$)(^([a-zA-Z0-9_]([a-zA-Z0-9-_]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z0-9-_]{2,63}$)"
    if re.match(domain_regex, host):
        return True
        
    return False

def is_valid_port(port):
    """校验端口合法性 (1-65535)"""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False

def validate_node(link):
    """节点合法性校验核心函数：检查 UUID、Host、Port 及高级参数"""
    link = link.strip()
    if not link:
        return False

    try:
        if link.startswith("vmess://'"):
            link = link.strip("'")
            
        # 1. VMess 协议校验
        if link.startswith("vmess://"):
            b64_str = link[8:]
            node_data = json.loads(decode_base64(b64_str))
            
            # 必须包含核心字段
            host = node_data.get("add", "")
            port = node_data.get("port", "")
            uuid = node_data.get("id", "")
            
            # 校验 Host 和 Port
            if not is_valid_host(host) or not is_valid_port(port):
                return False
                
            # 校验 UUID 格式
            uuid_regex = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
            if uuid and not re.match(uuid_regex, uuid):
                return False
                
            return True

        # 2. VLESS / Trojan / SS / Hysteria2 / TUIC 等通用 URI 协议校验
        elif link.startswith(("vless://", "trojan://", "ss://", "ssr://", "hy2://", "hysteria2://", "tuic://")):
            # 提取主干和参数部分
            match = re.search(r'://(?:([^@]+)@)?([^:/]+):(\d+)', link)
            if not match:
                return False
                
            userinfo, host, port = match.groups()
            
            # 校验主机与端口
            if not is_valid_host(host) or not is_valid_port(port):
                return False
                
            # 如果是 VLESS/Trojan，可以顺便校验 UUID（针对 VLESS）
            if link.startswith("vless://") and userinfo:
                uuid_regex = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
                # 部分 VLESS 可能带 flow 等参数，userinfo 的第一部分通常是 UUID
                potential_uuid = userinfo.split("?")[0]
                if not re.match(uuid_regex, potential_uuid):
                    return False

            return True
            
    except Exception:
        return False
        
    return False

def parse_and_clean_node(link):
    """解析节点、重命名并提取去重特征码"""
    link = link.strip()
    unique_key = link 
    
    try:
        if link.startswith("vmess://"):
            b64_str = link[8:]
            node_data = json.loads(decode_base64(b64_str))
            
            if "ps" in node_data:
                node_data["ps"] = clean_alias(node_data["ps"])
            
            host = node_data.get("add", "")
            port = str(node_data.get("port", ""))
            if host and port:
                unique_key = f"vmess://{host}:{port}"
            
            new_b64 = base64.b64encode(json.dumps(node_data, ensure_ascii=False).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}", unique_key

        elif link.startswith(("vless://", "trojan://", "ss://", "ssr://", "hy2://", "hysteria2://", "tuic://")):
            if "#" in link:
                main_part, alias = link.split("#", 1)
                new_alias = clean_alias(urllib.parse.unquote(alias))
                new_link = f"{main_part}#{urllib.parse.quote(new_alias)}"
            else:
                main_part = link
                new_link = link
                
            match = re.search(r'://(?:[^@]+@)?([^:/]+):(\d+)', main_part)
            if match:
                host, port = match.groups()
                protocol = link.split("://")[0]
                unique_key = f"{protocol}://{host}:{port}"
            else:
                unique_key = main_part
                
            return new_link, unique_key
            
    except Exception:
        return link, link

def main():
    merged_nodes = []
    bad_nodes = []
    seen_keys = set() 
    
    total_downloaded = 0
    
    for url in SUB_URLS:
        try:
            print(f"正在获取: {url}")
            resp = requests.get(url, timeout=10)
            text = resp.text.strip()
            
            if "://" not in text:
                text = decode_base64(text)
                
            lines = text.splitlines()
            total_downloaded += len(lines)
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # 新增步骤：节点合法性校验
                if not validate_node(line):
                    bad_nodes.append(line)
                    continue

                # 协议解析与清洗
                new_link, unique_key = parse_and_clean_node(line)
                
                # 深度去重
                if new_link and unique_key not in seen_keys:
                    seen_keys.add(unique_key)
                    merged_nodes.append(new_link)
                else:
                    # 重复节点也归为无效或直接跳过（这里算作冗余过滤）
                    pass
                    
        except Exception as e:
            print(f"获取失败 {url}: {e}")

    # 1. 生成标准的 sub.txt（Hiddify 识别通常要求内容整体进行 Base64 编码）
    final_text = "\n".join(merged_nodes)
    final_b64 = base64.b64encode(final_text.encode('utf-8')).decode('utf-8')
    
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(final_b64)

    # 2. 输出坏节点文件 bad_nodes.txt
    with open("bad_nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(bad_nodes))
        
    # 3. 输出统计信息
    print("\n" + "="*30)
    print("📊 订阅处理统计信息:")
    print(f"• 下载/读取总节点数: {total_downloaded}")
    print(f"• 成功合法节点数: {len(merged_nodes)}")
    print(f"• 过滤坏节点/格式错误数: {len(bad_nodes)}")
    print("="*30)
    print("处理完成！结果已保存至 sub.txt 和 bad_nodes.txt")

if __name__ == "__main__":
    main()
