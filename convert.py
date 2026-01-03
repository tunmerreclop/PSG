import os
import json
import base64
import glob
from urllib.parse import urlparse, parse_qs, unquote

# --- Configuration Constants ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
GITHUB_BASE_URL = 'https://raw.githubusercontent.com/itsyebekhe/PSG/main'

ALLOWED_SS_METHODS = ["chacha20-ietf-poly1305", "aes-256-gcm", "2022-blake3-aes-256-gcm"]

# Define the Datasets to Process
# 1. Main Version
# 2. Lite Version
DATASETS = [
    {
        "name": "MAIN",
        "input_dir": os.path.join(BASE_DIR, 'subscriptions', 'xray', 'base64'),
        "output_root": os.path.join(BASE_DIR, 'subscriptions'),
        "url_path": "subscriptions/surfboard" # For Surfboard config URL
    },
    {
        "name": "LITE",
        "input_dir": os.path.join(BASE_DIR, 'lite', 'subscriptions', 'xray', 'base64'),
        "output_root": os.path.join(BASE_DIR, 'lite', 'subscriptions'),
        "url_path": "lite/subscriptions/surfboard"
    }
]

# Output Mappings for Clash/Surfboard
OUTPUT_MAPPING_CLASH = {
    'clash': ['mix', 'vmess', 'vmess_ipv4', 'vmess_ipv6', 'vmess_domain', 'trojan', 'trojan_ipv4', 'trojan_ipv6', 'trojan_domain', 'ss', 'ss_ipv4', 'ss_ipv6', 'ss_domain'],
    'meta': ['mix', 'vmess', 'vmess_ipv4', 'vmess_ipv6', 'vmess_domain', 'vless', 'vless_ipv4', 'vless_ipv6', 'vless_domain', 'reality', 'reality_ipv4', 'reality_ipv6', 'reality_domain', 'trojan', 'trojan_ipv4', 'trojan_ipv6', 'trojan_domain', 'ss', 'ss_ipv4', 'ss_ipv6', 'ss_domain'],
    'surfboard': ['mix', 'vmess', 'vmess_ipv4', 'vmess_ipv6', 'vmess_domain', 'trojan', 'trojan_ipv4', 'trojan_ipv6', 'trojan_domain', 'ss', 'ss_ipv4', 'ss_ipv6', 'ss_domain'],
}

# Singbox/Nekobox Configuration
SINGBOX_CONFIGS = {
    'singbox': {
        'folder': 'singbox',
        'template_file': 'structure.json',
        'include_header': True
    },
    'nekobox': {
        'folder': 'nekobox',
        'template_file': 'nekobox.json',
        'include_header': False
    }
}

# --- Helper Functions ---

def safe_base64_decode(s):
    s = s.strip()
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except:
        return ""

def detect_type(config):
    if config.startswith('vmess://'): return 'vmess'
    if config.startswith('vless://'): return 'vless'
    if config.startswith('trojan://'): return 'trojan'
    if config.startswith('ss://'): return 'ss'
    if config.startswith('tuic://'): return 'tuic'
    if config.startswith(('hy2://', 'hysteria2://')): return 'hy2'
    return None

def parse_config(config_str):
    """Parses a config link into a standardized dictionary."""
    ctype = detect_type(config_str)
    if not ctype: return None
    
    try:
        if ctype == 'vmess':
            b64 = config_str[8:]
            data = json.loads(safe_base64_decode(b64))
            return {
                'type': 'vmess',
                'name': data.get('ps', 'vmess'),
                'server': data.get('add', ''),
                'port': int(data.get('port', 443)),
                'uuid': data.get('id', ''),
                'alterId': int(data.get('aid', 0)),
                'cipher': data.get('scy', 'auto'),
                'network': data.get('net', 'tcp'),
                'type_header': data.get('type', 'none'),
                'host': data.get('host', ''),
                'path': data.get('path', ''),
                'tls': data.get('tls', '') == 'tls',
                'sni': data.get('sni', ''),
                'fp': data.get('fp', ''),
                'alpn': data.get('alpn', ''),
            }
        
        elif ctype == 'ss':
            parsed = urlparse(config_str)
            user_info = parsed.username
            if not user_info and '@' in parsed.netloc:
                 try:
                     b64part = parsed.netloc.split('@')[0]
                     decoded = safe_base64_decode(b64part)
                     method, password = decoded.split(':', 1)
                 except:
                     return None
            else:
                method = parsed.username
                password = parsed.password

            return {
                'type': 'ss',
                'name': unquote(parsed.fragment),
                'server': parsed.hostname,
                'port': parsed.port,
                'method': method,
                'password': password
            }

        else: # vless, trojan, tuic, hy2
            parsed = urlparse(config_str)
            params = parse_qs(parsed.query)
            clean_params = {k: v[0] for k, v in params.items()}
            
            return {
                'type': ctype,
                'name': unquote(parsed.fragment),
                'server': parsed.hostname,
                'port': parsed.port,
                'uuid': parsed.username,
                'password': parsed.username, 
                'params': clean_params,
                'path': parsed.path
            }
    except:
        return None

# #############################################################################
# CLASH / SURFBOARD CONVERTERS
# #############################################################################

def to_clash_proxy(data, is_meta=False):
    ctype = data['type']
    
    proxy = {
        "name": data['name'],
        "server": data['server'],
        "port": data['port'],
        "type": ctype,
        "skip-cert-verify": True 
    }

    if ctype == 'vmess':
        proxy.update({
            "uuid": data['uuid'],
            "alterId": data['alterId'],
            "cipher": data['cipher'],
            "network": data['network'],
            "tls": data['tls']
        })
        if data['network'] == 'ws':
            proxy['ws-opts'] = {
                "path": data['path'],
                "headers": {"Host": data['host'] if data['host'] else data['server']}
            }
        elif data['network'] == 'grpc':
            proxy['grpc-opts'] = {
                "grpc-service-name": data['path'], 
            }
            if not proxy['tls']: proxy['tls'] = True 

    elif ctype == 'vless':
        if not is_meta: return None 
        params = data['params']
        proxy.update({
            "uuid": data['uuid'],
            "network": params.get('type', 'tcp'),
            "tls": params.get('security') in ['tls', 'reality'],
            "udp": True,
            "client-fingerprint": params.get('fp', 'chrome')
        })
        
        if params.get('flow'): proxy['flow'] = 'xtls-rprx-vision'
        if params.get('sni'): proxy['servername'] = params.get('sni')
        
        if proxy['network'] == 'ws':
            proxy['ws-opts'] = {
                "path": data['path'],
                "headers": {"Host": params.get('host', data['server'])}
            }
        elif proxy['network'] == 'grpc':
            proxy['grpc-opts'] = {"grpc-service-name": params.get('serviceName', '')}
            
        if params.get('security') == 'reality':
            proxy['client-fingerprint'] = params.get('fp', 'chrome')
            proxy['reality-opts'] = {
                "public-key": params.get('pbk', ''),
                "short-id": params.get('sid', '')
            }
            
    elif ctype == 'trojan':
        proxy['password'] = data['password']
        proxy['skip-cert-verify'] = (data.get('params', {}).get('allowInsecure') == '1')
        if 'params' in data and data['params'].get('sni'):
             proxy['sni'] = data['params']['sni']

    elif ctype == 'ss':
        if data['method'] not in ALLOWED_SS_METHODS: return None
        proxy['cipher'] = data['method']
        proxy['password'] = data['password']

    else:
        return None 

    return proxy

def to_surfboard_proxy(data):
    ctype = data['type']
    if ctype not in ['vmess', 'trojan', 'ss']: return None
    
    # Name cannot contain commas in Surfboard
    name = data['name'].replace(',', ' ')
    parts = [f"{name} = {ctype}", data['server'], str(data['port'])]

    if ctype == 'vmess':
        parts.append(f"username = {data['uuid']}")
        parts.append(f"ws = {'true' if data['network'] == 'ws' else 'false'}")
        parts.append(f"tls = {'true' if data['tls'] else 'false'}")
        if data['network'] == 'ws':
             parts.append(f"ws-path = {data['path']}")
             host = data['host'] if data['host'] else data['server']
             parts.append(f'ws-headers = Host:"{host}"')

    elif ctype == 'trojan':
        parts.append(f"password = {data['password']}")
        parts.append("skip-cert-verify = true")
        if 'params' in data and data['params'].get('sni'):
            parts.append(f"sni = {data['params']['sni']}")

    elif ctype == 'ss':
         if data['method'] not in ALLOWED_SS_METHODS: return None
         parts.append(f"encrypt-method = {data['method']}")
         parts.append(f"password = {data['password']}")

    return ", ".join(parts)

# #############################################################################
# SING-BOX CONVERTERS
# #############################################################################

def to_singbox_outbound(data):
    ctype = data['type']
    out = {
        "tag": data['name'],
        "type": ctype,
        "server": data['server'],
        "server_port": data['port']
    }

    def get_tls(sni, insecure=True, fp='chrome', alpn=None, reality=None):
        tls = {
            "enabled": True,
            "server_name": sni,
            "insecure": insecure,
            "utls": {"enabled": True, "fingerprint": fp}
        }
        if alpn: tls['alpn'] = alpn
        if reality:
            tls['reality'] = reality
            tls['reality']['enabled'] = True
        return tls

    def get_transport(net, path, host, service_name):
        if net == 'ws':
            return {"type": "ws", "path": path, "headers": {"Host": host}}
        if net == 'grpc':
            return {"type": "grpc", "service_name": service_name}
        if net == 'http':
             return {"type": "http", "host": [host], "path": path}
        return None

    if ctype == 'vmess':
        out.update({
            "uuid": data['uuid'],
            "security": "auto",
            "alter_id": data['alterId']
        })
        if data['port'] == 443 or data['tls']:
             out['tls'] = get_tls(data['sni'] if data['sni'] else data['host'])
        
        if data['network'] in ['ws', 'grpc', 'http']:
             out['transport'] = get_transport(data['network'], data['path'], data['host'], data['path'])

    elif ctype == 'vless':
        params = data['params']
        out.update({
            "uuid": data['uuid'],
            "packet_encoding": "xudp"
        })
        if params.get('flow'): out['flow'] = "xtls-rprx-vision"
        
        security = params.get('security', '')
        if data['port'] == 443 or security in ['tls', 'reality']:
            reality = None
            if security == 'reality':
                reality = {
                    "public_key": params.get('pbk', ''),
                    "short_id": params.get('sid', '')
                }
            out['tls'] = get_tls(params.get('sni', ''), reality=reality, fp=params.get('fp', 'chrome'))
        
        net = params.get('type', 'tcp')
        if net in ['ws', 'grpc', 'http']:
            out['transport'] = get_transport(net, data['path'], params.get('host', ''), params.get('serviceName', ''))

    elif ctype == 'trojan':
        out['password'] = data['password']
        if data['port'] == 443 or data.get('params', {}).get('security') == 'tls':
             out['tls'] = get_tls(data.get('params', {}).get('sni', ''))
        
    elif ctype == 'ss':
        out['type'] = "shadowsocks"
        out['method'] = data['method']
        out['password'] = data['password']

    elif ctype == 'tuic':
        params = data['params']
        out.update({
            "uuid": data['uuid'],
            "password": data['password'],
            "congestion_control": params.get('congestion_control', 'bbr'),
            "udp_relay_mode": params.get('udp_relay_mode', 'native'),
            "tls": {
                "enabled": True,
                "server_name": params.get('sni', ''),
                "insecure": params.get('allow_insecure') == '1',
                "alpn": params.get('alpn', '').split(',') if params.get('alpn') else None
            }
        })

    elif ctype == 'hy2':
        out['type'] = 'hysteria2'
        params = data['params']
        if not params.get('obfs-password'): return None
        out.update({
            "password": data['password'],
            "obfs": {"type": params.get('obfs', 'salamander'), "password": params.get('obfs-password')},
            "tls": {
                "enabled": True,
                "server_name": params.get('sni', ''),
                "insecure": params.get('insecure') == '1',
                "alpn": ["h3"]
            }
        })
    else:
        return None

    return out

# #############################################################################
# PROCESSING LOGIC
# #############################################################################

def process_dataset(name, input_dir, output_root, url_path, singbox_templates):
    print(f"--- Processing {name} Version ---")
    
    # Create Output Directories
    os.makedirs(os.path.join(output_root, 'clash'), exist_ok=True)
    os.makedirs(os.path.join(output_root, 'meta'), exist_ok=True)
    os.makedirs(os.path.join(output_root, 'surfboard'), exist_ok=True)
    
    input_files = glob.glob(os.path.join(input_dir, '*'))
    if not input_files:
        print(f"No files found in {input_dir}")
        return

    for filepath in input_files:
        filename = os.path.basename(filepath)
        # print(f"  > Converting {filename}...")

        with open(filepath, 'r', encoding='utf-8') as f:
            b64_content = f.read().strip()
        
        decoded_content = safe_base64_decode(b64_content)
        config_lines = decoded_content.splitlines()
        
        parsed_proxies = []
        for line in config_lines:
            if not line.strip(): continue
            parsed = parse_config(line)
            if parsed:
                parsed_proxies.append(parsed)

        # 1. Generate Clash / Meta / Surfboard
        for out_type, allowed in OUTPUT_MAPPING_CLASH.items():
            if filename in allowed:
                is_meta = (out_type == 'meta')
                
                if out_type == 'surfboard':
                    proxies_ini = []
                    proxy_names = []
                    for p in parsed_proxies:
                        res = to_surfboard_proxy(p)
                        if res: 
                            proxies_ini.append(res)
                            proxy_names.append(p['name'].replace(',', ' '))
                    
                    if proxies_ini:
                        tpl_path = os.path.join(TEMPLATES_DIR, 'surfboard.ini')
                        if os.path.exists(tpl_path):
                            with open(tpl_path, 'r', encoding='utf-8') as f: content = f.read()
                            
                            # Construct correct URL for Main vs Lite
                            config_url = f"{GITHUB_BASE_URL}/{url_path}/{filename}"
                            
                            content = content.replace('##CONFIG_URL##', config_url)
                            content = content.replace('##PROXIES##', '\n'.join(proxies_ini))
                            content = content.replace('##PROXY_NAMES##', ', '.join(proxy_names))
                            
                            with open(os.path.join(output_root, 'surfboard', filename), 'w', encoding='utf-8') as f:
                                f.write(content)
                
                else: # Clash / Meta
                    proxies_yaml = []
                    proxy_names_yaml = []
                    
                    for p in parsed_proxies:
                        res = to_clash_proxy(p, is_meta)
                        if res:
                            json_str = json.dumps(res, ensure_ascii=False)
                            proxies_yaml.append(f"  - {json_str}")
                            safe_name = p['name'].replace("'", "''")
                            proxy_names_yaml.append(f"      - '{safe_name}'")
                    
                    if proxies_yaml:
                        tpl_path = os.path.join(TEMPLATES_DIR, 'clash.yaml')
                        if os.path.exists(tpl_path):
                            with open(tpl_path, 'r', encoding='utf-8') as f: content = f.read()
                            
                            content = content.replace('##PROXIES##', '\n'.join(proxies_yaml))
                            content = content.replace('##PROXY_NAMES##', '\n'.join(proxy_names_yaml))
                            
                            with open(os.path.join(output_root, out_type, filename), 'w', encoding='utf-8') as f:
                                f.write(content)

        # 2. Generate Sing-box / Nekobox
        for task, conf in SINGBOX_CONFIGS.items():
            if task not in singbox_templates: continue
            
            # Prepare Output Dir
            target_dir = os.path.join(output_root, conf['folder'])
            os.makedirs(target_dir, exist_ok=True)

            structure = json.loads(json.dumps(singbox_templates[task]))
            if 'outbounds' not in structure: structure['outbounds'] = []
            
            tags_added = []
            for p in parsed_proxies:
                outbound = to_singbox_outbound(p)
                if outbound:
                    structure['outbounds'].append(outbound)
                    tags_added.append(outbound['tag'])

            if tags_added:
                for i in [0, 1]:
                    if len(structure['outbounds']) > i and 'outbounds' in structure['outbounds'][i]:
                        structure['outbounds'][i]['outbounds'].extend(tags_added)
            
            final_content = ""
            if conf['include_header']:
                b64_title = base64.b64encode(f"PSG | {filename.upper()}".encode()).decode()
                final_content += f"//profile-title: base64:{b64_title}\n"
                final_content += "//profile-update-interval: 1\n"
                final_content += "//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531\n"
                final_content += "//support-url: https://t.me/yebekhe\n"
                final_content += "//profile-web-page-url: https://github.com/itsyebekhe/PSG\n\n"
            
            final_content += json.dumps(structure, indent=2, ensure_ascii=False)
            
            with open(os.path.join(target_dir, f"{filename}.json"), 'w', encoding='utf-8') as f:
                f.write(final_content)


def main():
    print("Starting Multi-Format Conversion...")

    # Load Singbox Templates once
    singbox_templates = {}
    for task, conf in SINGBOX_CONFIGS.items():
        tpl_path = os.path.join(TEMPLATES_DIR, conf['template_file'])
        if os.path.exists(tpl_path):
             with open(tpl_path, 'r', encoding='utf-8') as f:
                 singbox_templates[task] = json.load(f)
        else:
            print(f"Warning: Template {conf['template_file']} not found.")

    # Iterate over datasets (MAIN and LITE)
    for dataset in DATASETS:
        process_dataset(
            dataset['name'],
            dataset['input_dir'],
            dataset['output_root'],
            dataset['url_path'],
            singbox_templates
        )

    print("\nAll conversions complete!")

if __name__ == "__main__":
    main()
