
import json
from pathlib import Path


def load_config():
    config_path = Path(__file__).parent / "config.json"

    with config_path.open("r", encoding="utf-8") as file:
        return json.load(file)


if __name__ == "__main__":
    config = load_config()

    print("Attack-Surface Monitor")
    print("======================")
    print("Configured domains:", config["domains"])
    print("Configured hosts:", config["hosts"])
    print("Scan interval:", config["scan_interval_minutes"], "minutes")
