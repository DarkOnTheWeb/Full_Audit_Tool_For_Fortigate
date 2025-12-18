from netmiko import ConnectHandler
from datetime import datetime
import os


def collect_fortigate_config(host, username, password, device_name="fortigate"):

    print(f"[+] Подключаюсь к FortiGate {host}...")

    conn = ConnectHandler(
        device_type="fortinet",
        host=host,
        username=username,
        password=password,
        fast_cli=False,
    )

    # Отключаем постраничный вывод
    print("[+] Отключаю пагинацию (execute pager 0)...")
    conn.send_command_timing("execute pager 0")

    # Проверка на наличие промпта
    prompt = conn.find_prompt()
    print(f"[+] Промпт устройства: {repr(prompt)}")

    print("[+] Забираю полный конфиг (show full-configuration)...")

    output = conn.send_command_timing(
        "show full-configuration",
        delay_factor=5,
        strip_command=False,
        strip_prompt=False
    )

    conn.disconnect()

    # Сохраняем файл
    date = datetime.now().strftime("%Y-%m-%d")
    folder = f"backups/{date}"
    os.makedirs(folder, exist_ok=True)

    filename = f"{folder}/{device_name}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"[✓] Конфиг сохранен: {filename}")
    return filename


if __name__ == "__main__":
    collect_fortigate_config(
        host="10.10.14.1",
        username="audit.cavid",
        password="audit.cavid",
        device_name="fortigate-60f"
    )
