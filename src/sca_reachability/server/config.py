from dataclasses import dataclass
import os
import re
from pathlib import Path
from typing import Mapping


DEMO_TOKEN = "local-demo"
DEMO_WEBHOOK_SECRET = "local-demo-webhook-secret"


@dataclass(frozen=True)
class Settings:
    mode: str
    database_path: Path
    dashboard_token: str | None
    allowed_installation_ids: frozenset[int]
    github_app_id: str | None
    github_private_key_path: Path | None
    github_webhook_secret: str | None
    public_origin: str | None
    ai_enabled: bool
    ai_api_key: str | None
    ai_model: str | None
    allow_loopback_origins: bool = False
    public_repositories: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if len(self.public_repositories) > 10 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}", name)
            or name.split('/')[1] in {'.', '..'}
            for name in self.public_repositories
        ):
            raise ValueError("SCA_PUBLIC_REPOSITORIES requires at most 10 owner/name entries")
        if self.allow_loopback_origins and self.mode not in {"demo", "public"}:
            raise ValueError("SCA_ALLOW_LOOPBACK_ORIGINS requires SCA_MODE=demo or public")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        values = os.environ if environ is None else environ
        mode = values.get("SCA_MODE", "live").strip().lower()
        if mode not in {"live", "demo", "public"}:
            raise ValueError("SCA_MODE must be 'live', 'demo' or 'public'")
        allow_loopback = values.get("SCA_ALLOW_LOOPBACK_ORIGINS", "0").strip()
        if allow_loopback not in {"0", "1"}:
            raise ValueError("SCA_ALLOW_LOOPBACK_ORIGINS must be '0' or '1'")

        installation_ids = set()
        for raw_id in values.get("SCA_ALLOWED_INSTALLATION_IDS", "").split(","):
            raw_id = raw_id.strip()
            if not raw_id:
                continue
            try:
                installation_id = int(raw_id)
            except ValueError as error:
                raise ValueError(
                    "SCA_ALLOWED_INSTALLATION_IDS must contain positive integers"
                ) from error
            if installation_id <= 0:
                raise ValueError(
                    "SCA_ALLOWED_INSTALLATION_IDS must contain positive integers"
                )
            installation_ids.add(installation_id)

        database_path = Path(
            values.get(
                "SCA_DATABASE_PATH",
                str(Path.home() / ".local/share/sca-reachability/server.sqlite3"),
            )
        ).expanduser()
        key_path_value = values.get("SCA_GITHUB_PRIVATE_KEY_PATH", "").strip()
        return cls(
            mode=mode,
            database_path=database_path,
            dashboard_token=values.get("SCA_DASHBOARD_TOKEN"),
            allowed_installation_ids=frozenset(installation_ids),
            github_app_id=values.get("SCA_GITHUB_APP_ID"),
            github_private_key_path=Path(key_path_value).expanduser()
            if key_path_value
            else None,
            github_webhook_secret=values.get("SCA_GITHUB_WEBHOOK_SECRET"),
            public_origin=values.get("SCA_PUBLIC_ORIGIN") or None,
            ai_enabled=values.get("SCA_AI_ENABLED", "").strip().lower() == "true",
            ai_api_key=values.get("SCA_AI_API_KEY"),
            ai_model=values.get("SCA_AI_MODEL"),
            allow_loopback_origins=allow_loopback == "1",
            public_repositories=tuple(dict.fromkeys(name.strip().lower() for name in values.get("SCA_PUBLIC_REPOSITORIES", "").split(",") if name.strip())),
        )

    @property
    def operator_token(self) -> str | None:
        if self.mode == "demo":
            return DEMO_TOKEN
        if self.dashboard_token and len(self.dashboard_token) >= 32:
            return self.dashboard_token
        return None

    @property
    def webhook_secret(self) -> str | None:
        if self.mode == "public":
            return None
        if self.mode == "demo":
            return DEMO_WEBHOOK_SECRET
        return self.github_webhook_secret or None

    @property
    def github_configured(self) -> bool:
        if self.mode == "public":
            return True
        if self.mode == "demo":
            return True
        return bool(
            self.allowed_installation_ids
            and self.github_app_id
            and self.github_private_key_path
            and self.github_private_key_path.is_file()
            and self.github_webhook_secret
        )

    @property
    def ai_configured(self) -> bool:
        return bool(self.ai_enabled and self.ai_api_key and self.ai_model)
