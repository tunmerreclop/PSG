import os
import json
import datetime
import pytz

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_HTML_FILE = os.path.join(BASE_DIR, "index.html")
GITHUB_REPO_URL = "https://raw.githubusercontent.com/itsyebekhe/PSG/main"

# Directory Mapping
SCAN_DIRECTORIES = {
    "Standard": os.path.join(BASE_DIR, "subscriptions"),
    "Lite": os.path.join(BASE_DIR, "lite", "subscriptions"),
    "Channels": os.path.join(BASE_DIR, "subscriptions", "channels"),
}

IGNORE_EXTENSIONS = {".php", ".md", ".ini", ".txt", ".log", ".conf", ".py", ".json", ".html"}

def get_client_info():
    return {
        "clash": {
            "windows": [{"name": "Clash Verge (Rev)", "url": "https://github.com/clash-verge-rev/clash-verge-rev/releases"}],
            "android": [{"name": "Clash for Android", "url": "https://github.com/Kr328/ClashForAndroid/releases"}],
            "ios": [{"name": "Stash", "url": "https://apps.apple.com/us/app/stash/id1596063349"}],
            "linux": [{"name": "Clash Verge", "url": "https://github.com/clash-verge-rev/clash-verge-rev/releases"}]
        },
        "singbox": {
            "windows": [{"name": "Hiddify Next", "url": "https://github.com/hiddify/hiddify-next/releases"}],
            "android": [{"name": "Hiddify Next", "url": "https://github.com/hiddify/hiddify-next/releases"}, {"name": "v2rayNG", "url": "https://github.com/2dust/v2rayNG/releases"}],
            "ios": [{"name": "Streisand", "url": "https://apps.apple.com/us/app/streisand/id6450534064"}, {"name": "V2Box", "url": "https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690"}]
        },
        "xray": {
            "windows": [{"name": "v2rayN", "url": "https://github.com/2dust/v2rayN/releases"}],
            "android": [{"name": "v2rayNG", "url": "https://github.com/2dust/v2rayNG/releases"}],
            "ios": [{"name": "Shadowrocket", "url": "https://apps.apple.com/us/app/shadowrocket/id932747118"}]
        }
    }

def scan_directory(directory):
    if not os.path.exists(directory): return []
    file_list = []
    for root, _, files in os.walk(directory):
        for file in files:
            _, ext = os.path.splitext(file)
            if ext.lower() not in IGNORE_EXTENSIONS:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, BASE_DIR).replace("\\", "/")
                file_list.append(rel_path)
    return file_list

def process_files_to_structure(files_by_category):
    structure = {}
    for cat_key, cat_path in SCAN_DIRECTORIES.items():
        if cat_key not in files_by_category: continue
        base_rel = os.path.relpath(cat_path, BASE_DIR).replace("\\", "/")
        
        for file_path in files_by_category[cat_key]:
            if file_path.startswith(base_rel):
                clean_path = file_path[len(base_rel):].strip("/")
            else: continue

            parts = clean_path.split("/")
            if len(parts) < 2: continue
            
            type_prefix = parts[0]
            remaining_parts = parts[1:]
            if len(remaining_parts) > 0 and remaining_parts[0] == "base64": remaining_parts.pop(0)
            if len(remaining_parts) == 0: continue

            final_name_with_ext = "/".join(remaining_parts)
            final_name, _ = os.path.splitext(final_name_with_ext)
            url = f"{GITHUB_REPO_URL}/{file_path}"
            
            if cat_key not in structure: structure[cat_key] = {}
            if type_prefix not in structure[cat_key]: structure[cat_key][type_prefix] = {}
            structure[cat_key][type_prefix][final_name] = url

    return structure

def generate_html(data, client_info, timestamp):
    json_data = json.dumps(data, ensure_ascii=False)
    json_client = json.dumps(client_info, ensure_ascii=False)

    html_content = f"""<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PSG | Proxy Subscription Generator</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/davidshimjs-qrcodejs@0.0.2/qrcode.min.js"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <script>
      tailwind.config = {{
        darkMode: 'class',
        theme: {{
          extend: {{
            fontFamily: {{ sans: ['Outfit', 'sans-serif'], }},
            colors: {{ brand: {{ 50: '#f0f9ff', 100: '#e0f2fe', 500: '#0ea5e9', 600: '#0284c7', 900: '#0c4a6e' }} }}
          }}
        }}
      }}
    </script>
    <style>
        body {{ font-family: 'Outfit', sans-serif; }}
        .glass {{ background: rgba(255, 255, 255, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.3); }}
        .dark .glass {{ background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.05); }}
        .step-active {{ border-color: #0ea5e9; opacity: 1; }}
        .step-inactive {{ opacity: 0.6; pointer-events: none; }}
        .step-icon-active {{ background-color: #0ea5e9; color: white; }}
    </style>
</head>
<body class="bg-slate-50 dark:bg-[#0B1120] text-slate-800 dark:text-slate-200 min-h-screen flex flex-col transition-colors duration-300">
    <div class="fixed inset-0 z-[-1] overflow-hidden pointer-events-none">
        <div class="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-blue-500/10 rounded-full blur-3xl"></div>
        <div class="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-purple-500/10 rounded-full blur-3xl"></div>
    </div>

    <div class="container max-w-5xl mx-auto px-4 py-8 flex-grow">
        <header class="flex flex-col md:flex-row justify-between items-center mb-12">
            <div class="flex items-center gap-4 mb-4 md:mb-0">
                <div class="w-12 h-12 bg-white dark:bg-slate-800 rounded-full flex items-center justify-center shadow-lg border border-slate-200 dark:border-slate-700">
                    <i data-lucide="zap" class="w-6 h-6 text-brand-500"></i>
                </div>
                <div>
                    <h1 class="text-2xl font-bold">PSG <span class="text-brand-500">Builder</span></h1>
                    <p class="text-xs text-slate-500 dark:text-slate-400 font-medium tracking-wide">PROXY SUBSCRIPTION GENERATOR</p>
                </div>
            </div>
            <button id="theme-toggle" class="p-2.5 rounded-xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:border-brand-500 transition-all shadow-sm">
                <i id="theme-icon" data-lucide="moon" class="w-5 h-5 text-slate-600 dark:text-slate-300"></i>
            </button>
        </header>

        <nav class="mb-8">
            <div class="glass rounded-2xl p-1.5 flex flex-wrap sm:flex-nowrap shadow-sm">
                <button data-id="simple" class="nav-btn flex-1 py-2.5 px-4 rounded-xl text-sm font-semibold transition-all text-brand-600 bg-white dark:bg-slate-700 shadow-md">Simple</button>
                <button data-id="composer" class="nav-btn flex-1 py-2.5 px-4 rounded-xl text-sm font-semibold transition-all text-slate-600 dark:text-slate-400 hover:bg-white/50">Composer</button>
            </div>
        </nav>

        <main class="glass rounded-3xl p-6 md:p-8 shadow-xl">
            <!-- SIMPLE MODE -->
            <div id="simpleModeContainer" class="mode-container">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <!-- Step 1 -->
                    <div id="step1" class="border-2 border-brand-500 rounded-2xl p-5 transition-all duration-300">
                        <div class="w-10 h-10 rounded-full bg-brand-500 text-white flex items-center justify-center mb-4 font-bold">1</div>
                        <h3 class="font-bold text-lg mb-2">Category</h3>
                        <select id="configType" class="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-brand-500 outline-none"></select>
                    </div>
                    <!-- Step 2 -->
                    <div id="step2" class="step-inactive border-2 border-slate-200 dark:border-slate-700 rounded-2xl p-5 transition-all duration-300">
                        <div class="w-10 h-10 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 flex items-center justify-center mb-4 font-bold step-icon">2</div>
                        <h3 class="font-bold text-lg mb-2">Client</h3>
                        <select id="ipType" class="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-brand-500 outline-none" disabled></select>
                    </div>
                    <!-- Step 3 -->
                    <div id="step3" class="step-inactive border-2 border-slate-200 dark:border-slate-700 rounded-2xl p-5 transition-all duration-300">
                        <div class="w-10 h-10 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 flex items-center justify-center mb-4 font-bold step-icon">3</div>
                        <h3 class="font-bold text-lg mb-2">Result</h3>
                        <input type="search" id="searchBar" placeholder="Search..." class="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2.5 text-sm mb-2 outline-none" disabled>
                        <select id="otherElement" class="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2.5 text-sm outline-none" disabled></select>
                    </div>
                </div>

                <div id="resultArea" class="hidden mt-8 pt-8 border-t border-slate-200 dark:border-slate-700">
                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        <div>
                            <label class="block text-sm font-semibold mb-2 ml-1 text-slate-600 dark:text-slate-300">Subscription Link</label>
                            <div class="flex items-center gap-0 mb-4">
                                <input type="text" id="subscriptionUrl" readonly class="flex-grow bg-slate-100 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-l-xl px-4 py-3 text-xs md:text-sm font-mono focus:outline-none">
                                <button id="copyButton" class="bg-brand-500 hover:bg-brand-600 text-white px-4 py-3 rounded-r-xl transition-colors">
                                    <i data-lucide="copy" class="w-5 h-5"></i>
                                </button>
                            </div>
                            <div id="qrcode" class="p-3 bg-white rounded-xl shadow-sm border border-slate-200 w-fit"></div>
                        </div>
                        <div id="client-info-container" class="bg-slate-50 dark:bg-slate-900/50 rounded-xl p-6 border border-slate-200 dark:border-slate-700">
                            <h4 class="font-bold text-slate-700 dark:text-slate-200 mb-4 flex items-center gap-2">
                                <i data-lucide="download-cloud" class="w-5 h-5 text-brand-500"></i> Supported Clients
                            </h4>
                            <div id="client-info-list" class="space-y-3 text-sm"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- COMPOSER MODE -->
            <div id="composerModeContainer" class="mode-container hidden">
                <div class="text-center py-10 text-slate-500">Composer Mode coming soon...</div>
            </div>
        </main>

        <footer class="mt-12 text-center text-slate-500 dark:text-slate-400 text-sm">
            <p>Generated at: {timestamp}</p>
        </footer>
    </div>

    <!-- TOAST -->
    <div id="messageBox" class="fixed bottom-6 right-6 z-50 transform translate-y-20 opacity-0 transition-all duration-300">
        <div class="bg-slate-800 text-white px-6 py-3 rounded-xl shadow-2xl flex items-center gap-3">
            <i data-lucide="info" class="w-5 h-5 text-brand-500"></i>
            <span id="messageBoxText">Notification</span>
        </div>
    </div>

    <script>
        const structuredData = {json_data};
        const clientInfoData = {json_client};

        // --- THEME & NAV LOGIC ---
        document.addEventListener('DOMContentLoaded', () => {{
            lucide.createIcons();
            const html = document.documentElement;
            const themeBtn = document.getElementById('theme-toggle');
            const themeIcon = document.getElementById('theme-icon');

            function setTheme(isDark) {{
                if(isDark) {{ html.classList.add('dark'); localStorage.setItem('theme', 'dark'); themeIcon.setAttribute('data-lucide', 'sun'); }}
                else {{ html.classList.remove('dark'); localStorage.setItem('theme', 'light'); themeIcon.setAttribute('data-lucide', 'moon'); }}
                lucide.createIcons();
            }}
            if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) setTheme(true); else setTheme(false);
            themeBtn.addEventListener('click', () => setTheme(!html.classList.contains('dark')));

            const navBtns = document.querySelectorAll('.nav-btn');
            const modeContainers = document.querySelectorAll('.mode-container');
            navBtns.forEach(btn => {{
                btn.addEventListener('click', () => {{
                    navBtns.forEach(b => {{ b.classList.remove('bg-white', 'dark:bg-slate-700', 'shadow-md', 'text-brand-600'); b.classList.add('text-slate-600', 'dark:text-slate-400'); }});
                    btn.classList.add('bg-white', 'dark:bg-slate-700', 'shadow-md', 'text-brand-600');
                    btn.classList.remove('text-slate-600', 'dark:text-slate-400');
                    const id = btn.dataset.id;
                    modeContainers.forEach(c => c.classList.add('hidden'));
                    document.getElementById(id + 'ModeContainer').classList.remove('hidden');
                }});
            }});
        }});

        // --- SIMPLE MODE LOGIC (FIXED) ---
        const configType = document.getElementById('configType');
        const ipType = document.getElementById('ipType');
        const searchBar = document.getElementById('searchBar');
        const otherElement = document.getElementById('otherElement');
        const resultArea = document.getElementById('resultArea');
        const subUrlInput = document.getElementById('subscriptionUrl');
        const copyBtn = document.getElementById('copyButton');
        const clientList = document.getElementById('client-info-list');
        const step2 = document.getElementById('step2');
        const step3 = document.getElementById('step3');

        // 1. Populate Config Types
        function initSimpleMode() {{
            configType.innerHTML = '<option value="">Select Category...</option>';
            Object.keys(structuredData).forEach(key => {{
                const opt = document.createElement('option');
                opt.value = key;
                opt.textContent = key;
                configType.appendChild(opt);
            }});
        }}
        initSimpleMode();

        // 2. Change Category -> Unlock Step 2
        configType.addEventListener('change', () => {{
            const cat = configType.value;
            ipType.innerHTML = '<option value="">Select Client...</option>';
            
            if (cat && structuredData[cat]) {{
                Object.keys(structuredData[cat]).forEach(k => {{
                    const opt = document.createElement('option');
                    opt.value = k;
                    opt.textContent = k.toUpperCase();
                    ipType.appendChild(opt);
                }});
                
                // Activate Step 2
                step2.classList.remove('step-inactive');
                step2.classList.add('border-brand-500');
                step2.querySelector('.step-icon').classList.add('step-icon-active');
                step2.querySelector('.step-icon').classList.remove('bg-slate-100', 'text-slate-500');
                ipType.disabled = false;
                
                // Reset Step 3
                resetStep3();
            }} else {{
                resetStep2();
            }}
        }});

        // 3. Change Client -> Unlock Step 3
        ipType.addEventListener('change', () => {{
            const cat = configType.value;
            const type = ipType.value;
            otherElement.innerHTML = '<option value="">Select Config...</option>';
            searchBar.value = '';

            if (cat && type && structuredData[cat][type]) {{
                const keys = Object.keys(structuredData[cat][type]).sort();
                keys.forEach(k => {{
                    const opt = document.createElement('option');
                    opt.value = k;
                    opt.textContent = k;
                    otherElement.appendChild(opt);
                }});

                // Activate Step 3
                step3.classList.remove('step-inactive');
                step3.classList.add('border-brand-500');
                step3.querySelector('.step-icon').classList.add('step-icon-active');
                step3.querySelector('.step-icon').classList.remove('bg-slate-100', 'text-slate-500');
                searchBar.disabled = false;
                otherElement.disabled = false;
                
                renderClients(type);
            }} else {{
                resetStep3();
            }}
        }});

        // 4. Select Config -> Show Result
        otherElement.addEventListener('change', () => {{
            const cat = configType.value;
            const type = ipType.value;
            const key = otherElement.value;

            if (key) {{
                const url = structuredData[cat][type][key];
                subUrlInput.value = url;
                resultArea.classList.remove('hidden');
                
                // QR Code
                const qrContainer = document.getElementById('qrcode');
                qrContainer.innerHTML = '';
                new QRCode(qrContainer, {{ text: url, width: 128, height: 128 }});
            }} else {{
                resultArea.classList.add('hidden');
            }}
        }});

        // Search Filter
        searchBar.addEventListener('input', (e) => {{
            const val = e.target.value.toLowerCase();
            Array.from(otherElement.options).forEach(opt => {{
                if(opt.value === "") return;
                const txt = opt.textContent.toLowerCase();
                opt.style.display = txt.includes(val) ? 'block' : 'none';
            }});
        }});

        // Copy Button
        copyBtn.addEventListener('click', () => {{
            navigator.clipboard.writeText(subUrlInput.value);
            const box = document.getElementById('messageBox');
            document.getElementById('messageBoxText').textContent = "Copied to clipboard!";
            box.classList.remove('translate-y-20', 'opacity-0');
            setTimeout(() => box.classList.add('translate-y-20', 'opacity-0'), 2000);
        }});

        function resetStep2() {{
            ipType.innerHTML = '';
            ipType.disabled = true;
            step2.classList.add('step-inactive');
            step2.classList.remove('border-brand-500');
            step2.querySelector('.step-icon').classList.remove('step-icon-active');
            resetStep3();
        }}

        function resetStep3() {{
            otherElement.innerHTML = '';
            otherElement.disabled = true;
            searchBar.disabled = true;
            resultArea.classList.add('hidden');
            step3.classList.add('step-inactive');
            step3.classList.remove('border-brand-500');
            step3.querySelector('.step-icon').classList.remove('step-icon-active');
        }}

        function renderClients(type) {{
            // Simple mapping for demo
            let key = 'xray';
            if(type.includes('clash') || type.includes('meta')) key = 'clash';
            if(type.includes('singbox')) key = 'singbox';
            
            const data = clientInfoData[key] || clientInfoData['xray'];
            clientList.innerHTML = '';
            
            Object.keys(data).forEach(os => {{
                const div = document.createElement('div');
                div.innerHTML = `<h5 class="capitalize font-semibold text-slate-500 mb-1">${{os}}</h5>`;
                const links = document.createElement('div');
                links.className = 'flex flex-wrap gap-2';
                data[os].forEach(app => {{
                    const a = document.createElement('a');
                    a.href = app.url;
                    a.target = '_blank';
                    a.className = 'px-3 py-1.5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg hover:border-brand-500 transition-colors';
                    a.textContent = app.name;
                    links.appendChild(a);
                }});
                div.appendChild(links);
                clientList.appendChild(div);
            }});
        }}
    </script>
</body>
</html>"""
    
    return html_content

def main():
    print("Starting Python PSG Builder...")
    all_files = {}
    total_count = 0
    for cat, path in SCAN_DIRECTORIES.items():
        if os.path.exists(path):
            files = scan_directory(path)
            all_files[cat] = files
            total_count += len(files)
            print(f"Scanning {cat}: Found {len(files)} files.")
    
    if total_count == 0: return print("Error: No files found.")

    structured_data = process_files_to_structure(all_files)
    client_info = get_client_info()
    tehran_tz = pytz.timezone("Asia/Tehran")
    timestamp = datetime.datetime.now(tehran_tz).strftime("%Y-%m-%d %H:%M:%S %Z")

    html_output = generate_html(structured_data, client_info, timestamp)

    try:
        with open(OUTPUT_HTML_FILE, "w", encoding="utf-8") as f:
            f.write(html_output)
        print(f"Success: {OUTPUT_HTML_FILE}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()