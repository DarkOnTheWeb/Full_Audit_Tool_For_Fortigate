#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import paramiko
import time
import sys

def get_fortigate_config(host, username, password, port=22):
    """
    Получает полный конфиг FortiGate даже с read-only доступом
    """
    print(f"[*] Подключаемся к {host}...")
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Подключаемся с таймаутами
        client.connect(
            hostname=host,
            username=username,
            password=password,
            port=port,
            timeout=30,
            banner_timeout=30,
            auth_timeout=30
        )
        
        print(f"[✓] Подключение успешно")
        
        # Создаем интерактивную сессию
        shell = client.invoke_shell()
        shell.settimeout(5)
        
        # Ждем приветствие
        time.sleep(2)
        # Чистим буфер
        while shell.recv_ready():
            shell.recv(4096)
        
        print(f"[*] Отправляем команду...")
        
        # Ключевой момент: отправляем команду ПОСТРОЧНО
        shell.send('show full-configuration\n')
        time.sleep(3)
        
        # Буфер для конфига
        config_data = ""
        page_count = 0
        max_pages = 2000  # Защита от вечного цикла
        last_data_size = 0
        
        print(f"[*] Читаем вывод (это может занять 2-5 минут)...")
        
        while page_count < max_pages:
            # Проверяем, есть ли данные
            if shell.recv_ready():
                chunk = shell.recv(65536).decode('utf-8', errors='ignore')
                config_data += chunk
                
                # Счетчик прогресса
                if len(config_data) - last_data_size > 10000:
                    print(f"[*] Получено {len(config_data)//1024} KB...")
                    last_data_size = len(config_data)
                
                # Проверяем, не закончился ли вывод
                if 'FortiGate-60F' in chunk and '$' in chunk:
                    # Возможно, это промпт после завершения
                    time.sleep(2)
                    # Проверяем, не было ли --More--
                    shell.send(' ')
                    time.sleep(1)
                    
            else:
                # Нет данных - возможно ждет --More-- или конец
                time.sleep(1)
                
                # Пробуем нажать пробел (для --More--)
                shell.send(' ')
                time.sleep(2)
                
                # Проверяем, не завершилась ли сессия
                try:
                    shell.send('\n')
                    time.sleep(1)
                except:
                    break
                
                page_count += 1
                
                # Прогресс
                if page_count % 20 == 0:
                    print(f"[*] Обработано {page_count} страниц...")
        
        print(f"[✓] Получено {len(config_data)} символов")
        
        # Сохраняем ВСЕ что получили
        with open(f'fortigate_{host}_full_raw.txt', 'w', encoding='utf-8') as f:
            f.write(config_data)
        
        print(f"[✓] Сырые данные сохранены в fortigate_{host}_full_raw.txt")
        
        # Очищаем от мусора
        clean_config = clean_fortigate_output(config_data)
        
        with open(f'fortigate_{host}_clean.conf', 'w', encoding='utf-8') as f:
            f.write(clean_config)
        
        print(f"[✓] Очищенный конфиг сохранен в fortigate_{host}_clean.conf")
        
        # Анализ что получили
        analyze_config(clean_config)
        
        return clean_config
        
    except Exception as e:
        print(f"[!] Ошибка: {e}")
        return None
        
    finally:
        client.close()

def clean_fortigate_output(raw_data):
    """
    Очищает вывод FortiGate от промптов и мусора
    """
    lines = raw_data.split('\n')
    clean_lines = []
    in_config = False
    
    for line in lines:
        # Убираем escape-последовательности
        line = line.replace('\x1b[K', '').replace('\r', '')
        
        # Пропускаем промпты и служебные строки
        if any(x in line for x in [
            '--More--', 
            'Press any', 
            'FortiGate-60F', 
            'show full-configuration',
            '^C'
        ]):
            continue
        
        # Начинаем собирать когда видим config
        if line.strip().startswith('config '):
            in_config = True
        
        if in_config:
            clean_lines.append(line)
    
    return '\n'.join(clean_lines)

def analyze_config(config_text):
    """
    Анализирует, что получили
    """
    print(f"\n[Анализ конфига]:")
    print(f"Общий размер: {len(config_text)} символов")
    
    sections = [
        ('config system', 'system'),
        ('config firewall policy', 'firewall policies'),
        ('config webfilter', 'webfilter'),
        ('config dnsfilter', 'dnsfilter'),
        ('config system dns', 'DNS'),
        ('config router', 'routing'),
        ('config vpn', 'VPN'),
    ]
    
    for keyword, name in sections:
        count = config_text.count(keyword)
        if count > 0:
            print(f"✓ {name}: {count} секций")
        else:
            print(f"✗ {name}: НЕ НАЙДЕНО")

# ===== ЗАПУСК =====
if __name__ == "__main__":
    # ТВОИ ДАННЫЕ
    HOST = "10.10.14.1"
    USERNAME = "audit.cavid"  # или другой пользователь
    PASSWORD = "audit.cavid"
    
    print("=" * 50)
    print("FortiGate Config Extractor v2.0")
    print("=" * 50)
    
    config = get_fortigate_config(HOST, USERNAME, PASSWORD)
    
    if config:
        print(f"\n[✓] УСПЕХ! Конфиг получен")
        print(f"[!] Если что-то не скачалось, попробуй второй метод ниже")
    else:
        print(f"\n[!] Не удалось получить конфиг")
