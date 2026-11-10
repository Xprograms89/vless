import os
import re
import sys
import time
import socket
import subprocess
import shutil
import requests
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

# --- НАСТРОЙКИ ---
MAX_THREADS = 7          # Количество одновременных потоков для проверки
SPEED_LIMIT_MBPS = 2.0   # Минимальная скорость в Мбит/с для сохранения в Good

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(CURRENT_DIR, "Config")
GOOD_DIR = os.path.join(CURRENT_DIR, "Good")
BASE_CONF = os.path.join(CURRENT_DIR, "VPN.conf")
AMNEZIA_EXE = os.path.join(CURRENT_DIR, "amd64_amneziawg.exe")
OPENVPN_EXE = os.path.join(CURRENT_DIR, "OpenVPN", "bin", "openvpn.exe")

# Очищаем и создаем папку Good перед стартом
if os.path.exists(GOOD_DIR):
    shutil.rmtree(GOOD_DIR)
os.makedirs(GOOD_DIR, exist_ok=True)

# Глобальный список для хранения результатов "на лету" и блокировщик для потоков
active_goods = []
save_lock = Lock()

def resolve_to_ip(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def check_speed_and_google():
    url = "https://google.com"
    speed_test_url = "https://speed.cloudflare.com/__down?bytes=2500000"
    try:
        res = requests.get(url, timeout=3)
        if res.status_code != 200:
            return False, 0
        
        start_time = time.time()
        response = requests.get(speed_test_url, timeout=4, stream=True)
        
        downloaded = 0
        for chunk in response.iter_content(chunk_size=4096):
            downloaded += len(chunk)
            
        duration = time.time() - start_time
        if duration <= 0: duration = 0.001
        
        speed_mbps = (downloaded * 8) / (duration * 1024 * 1024)
        return True, speed_mbps
    except requests.RequestException:
        return False, 0

def extract_info(file_name):
    file_path = os.path.join(CONFIG_DIR, file_name)
    server_target = None
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = re.match(r"^\s*remote\s+(\S+)", line)
            if match:
                server_target = match.group(1)
                break
    if not server_target: return None
    server_ip = resolve_to_ip(server_target)
    if not server_ip: return None
    return server_ip, file_path, file_name

def save_and_resort_on_the_fly(new_item):
    """Добавляет новый рабочий конфиг, сортирует список и мгновенно обновляет файлы в папке Good"""
    with save_lock:
        # 1. Добавляем новый результат в общий список
        active_goods.append(new_item)
        
        # 2. Сортируем весь текущий список по скорости (от максимума к минимуму)
        active_goods.sort(key=lambda x: x['speed'], reverse=True)
        
        # 3. Удаляем старые файлы из папки (чтобы избежать дубликатов при изменении индексов)
        for f in os.listdir(GOOD_DIR):
            try:
                os.remove(os.path.join(GOOD_DIR, f))
            except OSError:
                pass
                
        # 4. Записываем файлы заново с актуальными порядковыми номерами
        for idx, item in enumerate(active_goods, start=1):
            new_name = f"{idx:02d}_[{item['speed']:.1f}_Mbps]_{item['name']}"
            shutil.copy(item['path'], os.path.join(GOOD_DIR, new_name))
        
        print(f"[СОХРАНЕНО НА ЛЕТУ] Добавлен {new_item['name']} ({new_item['speed']:.1f} Mbps). Всего в Good: {len(active_goods)}")

def main():
    if not os.path.exists(CONFIG_DIR):
        print(f"[-] Папка Config не найдена!")
        sys.exit(1)

    ovpn_files = [f for f in os.listdir(CONFIG_DIR) if f.endswith('.ovpn')]
    if not ovpn_files:
        print("[-] Нет файлов .ovpn")
        sys.exit(0)

    print(f"[+] Анализ {len(ovpn_files)} файлов и сбор серверных IP...")
    valid_targets = []
    all_ips = []
    
    for f_name in ovpn_files:
        res = extract_info(f_name)
        if res:
            valid_targets.append(res)
            all_ips.append(f"{res[0]}/32")
    
    if not all_ips:
        print("[-] Не удалось найти корректные IP серверов.")
        sys.exit(0)

    print("[*] Запуск базового туннеля AmneziaWG...")
    with open(BASE_CONF, 'r', encoding='utf-8') as f:
        content = f.read()
    
    allowed_ips_str = ", ".join(all_ips)
    new_content = re.sub(r"AllowedIPs\s*=.*", f"AllowedIPs = {allowed_ips_str}", content)
    
    with open(BASE_CONF, 'w', encoding='utf-8') as f:
        f.write(new_content)

    subprocess.run([AMNEZIA_EXE, "/uninstalltunnelservice", "VPN"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    subprocess.run([AMNEZIA_EXE, "/installtunnelservice", BASE_CONF], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    print(f"[+] Старт проверки в {MAX_THREADS} потоков...")

    def worker(target_info):
        ip, file_path, name = target_info
        
        openvpn_proc = subprocess.Popen(
            [OPENVPN_EXE, "--config", file_path, "--nobind"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        time.sleep(6)
        is_ok, speed = check_speed_and_google()
        
        openvpn_proc.terminate()
        openvpn_proc.wait()
        
        if is_ok and speed >= SPEED_LIMIT_MBPS:
            # Отправляем на немедленное сохранение и пересортировку
            save_and_resort_on_the_fly({'name': name, 'path': file_path, 'speed': speed})
        elif is_ok:
            print(f"[-] {name} | Медленный ({speed:.2f} Мбит/с)")
        else:
            print(f"[-] {name} | Ошибка / Недоступен")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        executor.map(worker, valid_targets)

    print("\n[*] Отключение туннеля AmneziaWG...")
    subprocess.run([AMNEZIA_EXE, "/uninstalltunnelservice", "VPN"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] Готово! Проверка завершена. Все лучшие файлы сохранены в: {GOOD_DIR}")

if __name__ == "__main__":
    main()
