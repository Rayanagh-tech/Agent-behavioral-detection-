"""Chargement des fichiers de configuration JSON."""
import copy
import json
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def config_dir():
    return Path(os.environ.get("SECRES_CONFIG_DIR", PROJECT_ROOT / "config"))


def load_json(name, directory=None):
    path = Path(directory or config_dir()) / name
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_detection_config(directory=None):
    return load_json("detection.json", directory)


def load_access_control(directory=None):
    return load_json("access_control.json", directory)["resources"]


def with_overrides(config, **sections):
    """Copie profonde d'une configuration avec fusion récursive de sections (utile aux tests)."""
    result = copy.deepcopy(config)

    def merge(target, source):
        for key, value in source.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                merge(target[key], value)
            else:
                target[key] = copy.deepcopy(value)

    merge(result, sections)
    return result
