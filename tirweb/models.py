import json

from enum import Enum
from pathlib import Path
from typing import Literal
import yaml
from pydantic import BaseModel, Field, field_validator


class AppProfile(str, Enum):
    CORE = "core"
    BFSI_FINTECH = "bfsi_fintech"
    SAAS_MULTITENANT = "saas_multitenant"
    HEALTHCARE_PII = "healthcare_pii"
    ECOMMERCE = "ecommerce"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ExecutionMode(str, Enum):
    AUTOMATED = "automated"
    HYBRID = "hybrid"
    MANUAL = "manual"


class ComplianceMapping(BaseModel):
    india: list[str] = Field(..., min_length=1)
    global_: list[str] = Field(..., alias="global", min_length=1)


class ChecklistItem(BaseModel):
    id: str = Field(..., pattern=r"^WEB-[A-Z]{3}-\d{3}$")
    title: str
    category: str
    severity: Severity
    execution_mode: ExecutionMode
    tool_binding: list[str] = Field(default_factory=list)
    profiles: list[AppProfile] = Field(..., min_length=1)
    test_procedures: list[str] = Field(..., min_length=1)
    compliance: ComplianceMapping


class ChecklistModule(BaseModel):
    module_id: str = Field(..., pattern=r"^TIR-[A-Z]+$")
    name: str
    checks: list[ChecklistItem] = Field(..., min_length=1)


class ChecklistMetadata(BaseModel):
    description: str
    supported_profiles: list[AppProfile]


class TIRWebChecklist(BaseModel):
    schema_version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    tool_suite: Literal["TIRweb"]
    metadata: ChecklistMetadata
    modules: list[ChecklistModule] = Field(..., min_length=1)

    @field_validator("modules")
    @classmethod
    def ensure_unique_check_ids(cls, modules: list[ChecklistModule]) -> list[ChecklistModule]:
        seen: set[str] = set()
        for mod in modules:
            for check in mod.checks:
                if check.id in seen:
                    raise ValueError(f"Duplicate check ID detected: {check.id}")
                seen.add(check.id)
        return modules

    @classmethod
    def from_yaml(cls, path: Path) -> "TIRWebChecklist":
        raw_data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls.model_validate(raw_data)

    def filter_checks(
        self,
        profile: AppProfile,
        include_core: bool = True,
        modes: set[ExecutionMode] | None = None,
    ) -> list[tuple[ChecklistModule, ChecklistItem]]:
        """Return (module, check) pairs matching the requested profile and execution modes."""
        allowed_profiles = {profile}
        if include_core:
            allowed_profiles.add(AppProfile.CORE)

        matched: list[tuple[ChecklistModule, ChecklistItem]] = []
        for module in self.modules:
            for check in module.checks:
                if not allowed_profiles.intersection(check.profiles):
                    continue
                if modes and check.execution_mode not in modes:
                    continue
                matched.append((module, check))
        return matched



class AuthContext(BaseModel):
    headers: dict[str, str] = Field(default_factory=dict)
    bearer_token: str | None = None
    cookies: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_inputs(
        cls,
        raw_headers: list[str] | None = None,
        bearer_token: str | None = None,
        raw_cookies: list[str] | None = None,
        auth_file: Path | None = None,
    ) -> "AuthContext":
        merged_headers: dict[str, str] = {}
        merged_cookies: dict[str, str] = {}
        token: str | None = None

        # 1. Load optional auth config file first (CLI flags override file values)
        if auth_file:
            content = auth_file.read_text(encoding="utf-8")
            parsed = (
                json.loads(content)
                if auth_file.suffix.lower() == ".json"
                else yaml.safe_load(content)
            ) or {}
            merged_headers.update(parsed.get("headers", {}))
            merged_cookies.update(parsed.get("cookies", {}))
            token = parsed.get("bearer_token")

        # 2. Parse repeatable --header "Key: Value" flags
        for item in raw_headers or []:
            if ":" not in item:
                raise ValueError(f"Invalid header format '{item}'. Expected 'Name: Value'.")
            key, val = item.split(":", 1)
            merged_headers[key.strip()] = val.strip()

        # 3. Parse repeatable --cookie "name=value" or "a=1; b=2" flags
        for item in raw_cookies or []:
            for pair in item.split(";"):
                pair = pair.strip()
                if not pair:
                    continue
                if "=" not in pair:
                    raise ValueError(f"Invalid cookie format '{pair}'. Expected 'name=value'.")
                c_key, c_val = pair.split("=", 1)
                merged_cookies[c_key.strip()] = c_val.strip()

        # 4. Explicit --bearer-token takes precedence
        if bearer_token:
            token = bearer_token.strip()

        return cls(headers=merged_headers, bearer_token=token, cookies=merged_cookies)

    def to_http_headers(self) -> dict[str, str]:
        """Compile all credentials into standard HTTP header key-value pairs."""
        compiled = dict(self.headers)
        if self.bearer_token:
            compiled["Authorization"] = f"Bearer {self.bearer_token}"
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            existing_cookie = compiled.get("Cookie")
            compiled["Cookie"] = f"{existing_cookie}; {cookie_str}" if existing_cookie else cookie_str
        return compiled

    def to_cli_header_strings(self) -> list[str]:
        """Format headers as ['Name: Value', ...] for CLI scanners like nuclei -H."""
        return [f"{k}: {v}" for k, v in self.to_http_headers().items()]

    @property
    def is_authenticated(self) -> bool:
        return bool(self.headers or self.bearer_token or self.cookies)

    def redacted_summary(self) -> dict[str, object]:
        """Safe metadata representation for JSON/PDF reports without leaking secrets."""
        return {
            "authenticated": self.is_authenticated,
            "header_names": list(self.headers.keys()),
            "has_bearer_token": bool(self.bearer_token),
            "cookie_names": list(self.cookies.keys()),
        }