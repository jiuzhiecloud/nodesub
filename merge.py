import requests
import base64
import json
import re
import urllib.parse

# 1. 在这里填入你的订阅地址列表
SUB_URLS = [
    "https://www.xrayvip.com/free.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://github.com/ermaozi/get_subscribe/raw/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://raw.githubusercontent.com/jiuzhiecloud/free-node/refs/heads/main/testnode.txt",
    "https://raw.githubusercontent.com/jiuzhiecloud/free-sub/refs/heads/main/data/sub.txt",
    "https://raw.githubusercontent.com/jiuzhiecloud/free-node/refs/heads/main/data/sub.txt"
]

# 2. 推广词黑名单（正则表达式）
# 会自动把节点名称中的这些词语以及多余的符号删掉
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
    # 移除黑名单词汇
    alias = re.sub(AD_KEYWORDS, "", alias, flags=re.IGNORECASE)
    # 移除多余的网址链接 (如 xxx.com)
    alias = re.sub(r'[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+', '', alias)
    # 清理两端残留的特殊符号（如 - | _ ）
    alias = re.sub(r'^[_\-\|*\s,]+|[_\-\|*\s,]+$', '', alias)
    return alias if alias.strip() else "Auto_Node"

def parse_and_clean_node(link):
    """解析节点、重命名并提取去重特征码"""
    link = link.strip()
    if not link:
        return None, None
    
    unique_key = link # 默认唯一特征码为原始链接
    
    try:
        if link.startswith("vmess://"):
            b64_str = link[8:]
            node_data = json.loads(decode_base64(b64_str))
            
            # 清洗别名 (ps)
            if "ps" in node_data:
                node_data["ps"] = clean_alias(node_data["ps"])
            
            # 提取去重特征码: vmess协议 + IP/域名 + 端口
            host = node_data.get("add", "")
            port = str(node_data.get("port", ""))
            if host and port:
                unique_key = f"vmess://{host}:{port}"
            
            new_b64 = base64.b64encode(json.dumps(node_data, ensure_ascii=False).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}", unique_key

        elif link.startswith(("vless://", "trojan://", "ss://", "ssr://")):
            # 标准URI格式: scheme://userinfo@host:port?query#alias
            if "#" in link:
                main_part, alias = link.split("#", 1)
                new_alias = clean_alias(urllib.parse.unquote(alias))
                new_link = f"{main_part}#{urllib.parse.quote(new_alias)}"
            else:
                main_part = link
                new_link = link
                
            # 正则提取去重特征码: 协议 + IP/域名 + 端口
            match = re.search(r'://(?:[^@]+@)?([^:/]+):(\d+)', main_part)
            if match:
                host, port = match.groups()
                protocol = link.split("://")[0]
                unique_key = f"{protocol}://{host}:{port}"
            else:
                unique_key = main_part
                
            return new_link, unique_key
            
    except Exception:
        # 解析失败但非空，直接返回原链接不改动
        return link, link

def main():
    merged_nodes = []
    seen_keys = set() # 用于记录服务器特征，实现深度去重
    
    for url in SUB_URLS:
        try:
            print(f"正在获取: {url}")
            resp = requests.get(url, timeout=10)
            text = resp.text.strip()
            
            # 判断是否是 Base64 编码的集合
            if "://" not in text:
                text = decode_base64(text)
                
            # 逐行处理节点
            for line in text.splitlines():
                new_link, unique_key = parse_and_clean_node(line)
                # 如果节点有效，并且 (协议+IP+端口) 是第一次出现，则加入列表
                if new_link and unique_key not in seen_keys:
                    seen_keys.add(unique_key)
                    merged_nodes.append(new_link)
        except Exception as e:
            print(f"获取失败 {url}: {e}")

    # 将合并且去重后的节点重新 Base64 编码
    final_text = "\n".join(merged_nodes)
    final_b64 = base64.b64encode(final_text.encode('utf-8')).decode('utf-8')
    
    # 写入文件
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(final_b64)
        
    print(f"处理完成！合并后共保留了 {len(merged_nodes)} 个唯一节点。")

if __name__ == "__main__":
    main()
