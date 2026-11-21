import json
from pathlib import Path
from typing import Any

from sca_reachability.errors import InputError


def load_json_file(path: Path, label: str) -> Any:
    try:
        with path.open(encoding="utf-8") as input_file:
            return json.load(input_file)
    except OSError as error:
        detail = error.strerror or str(error)
        raise InputError(f"cannot read {label} file {path}: {detail}") from error
    except json.JSONDecodeError as error:
        raise InputError(
            f"{label} file {path} is not valid JSON "
            f"(line {error.lineno}, column {error.colno}): {error.msg}"
        ) from error
    except UnicodeError as error:
        raise InputError(f"{label} file {path} is not valid UTF-8") from error
