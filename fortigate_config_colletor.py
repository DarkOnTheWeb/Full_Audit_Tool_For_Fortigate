from netmiko import ConnectHandler
from datetime import datetime
import os


def collect_fortigate_config(host, username, password, device_name="fortigate"):
    """
    Сбор полного конфига FortiGate по SSH.
    Используем send_command_timing, чтобы не ловить ошибку 'Pattern not detected'.
    """

    print(f"[+] Подключаюсь к FortiGate {host}...")

    conn = ConnectHandler(
        device_type="fortinet",
        host=host,
        username=username,
        password=password,
        fast_cli=False,   # не спешим, пусть спокойно всё вычитает
    )

    # Чисто для дебага — посмотреть промпт (можно потом убрать)
    prompt = conn.find_prompt()
    print(f"[+] Промпт устройства: {repr(prompt)}")

    print("[+] Получаю полный конфиг (show full-configuration)...")

    # send_command_timing НЕ ждёт промпт, просто читает поток
    output = conn.send_command_timing(
        "show full-configuration",
        delay_factor=5,   # увеличиваем задержку на большие выводы
        strip_command=True,
        strip_prompt=False,
    )

    conn.disconnect()

    # Сохраняем в файл
    date = datetime.now().strftime("%Y-%m-%d")
    folder = os.path.join("backups", date)
    os.makedirs(folder, exist_ok=True)

    filename = os.path.join(folder, f"{device_name}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"[✓] Конфиг сохранен: {filename}")
    return filename


if __name__ == "__main__":
    collect_fortigate_config(
        host="10.10.14.1",
        username="audit.cavid",      # твой логин
        password="audit.cavid", # не забудь поменять
        device_name="fortigate-60f"
    )
