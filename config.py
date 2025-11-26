import json
import os

CONFIG_PATH = "config.json"

def load_config():
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)

    # Load pepper from environment if configured
    if config.get("pepper") == "__ENV__":
        env_pepper = os.getenv("PEPPER")
        if env_pepper:
            config["pepper"] = env_pepper
        else:
            raise RuntimeError("PEPPER not found in environment variables.")

    return config

CONFIG = load_config()
