from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class ActionType(str, Enum):
    DATA_EXPORT = "data_export"
    DATA_ACCESS = "data_access"
    DATA_DELETE = "data_delete"
    DATA_MODIFY = "data_modify"
    EXTERNAL_EMAIL = "external_email"
    EXTERNAL_MESSAGE = "external_message"
    WEBHOOK_CALL = "webhook_call"
    PRODUCTION_DEPLOY = "production_deploy"
    CODE_EXECUTION = "code_execution"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    PERMISSION_CHANGE = "permission_change"
    AUTH_CHANGE = "auth_change"
    API_KEY_CREATE = "api_key_create"
    PAYMENT = "payment"
    VENDOR_ACTION = "vendor_action"
    EXTERNAL_API_CALL = "external_api_call"
    WEB_BROWSE = "web_browse"
    WEB_SCRAPE = "web_scrape"
    DATABASE_QUERY = "database_query"
    DATABASE_WRITE = "database_write"
    DATABASE_DELETE = "database_delete"
    MODEL_CALL = "model_call"
    PROMPT_INJECTION = "prompt_injection"
    CUSTOM = "custom"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Decision(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    ESCALATE = "escalate"
    BLOCK = "block"


@dataclass
class AgentAction:
    agent_id: str
    org_id: str
    action_type: ActionType
    data_classification: DataClassification = DataClassification.INTERNAL
    environment: str = "production"
    record_count: int = 0
    destination: Optional[str] = None
    description: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class PolicyDecision:
    action_id: str
    agent_id: str
    org_id: str
    action_type: str
    decision: Decision
    policy_matched: Optional[str]
    would_have_blocked: bool
    message: str

    @property
    def is_allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    @property
    def is_blocked(self) -> bool:
        return self.decision == Decision.BLOCK

    @property
    def is_flagged(self) -> bool:
        return self.decision == Decision.FLAG

    @property
    def is_escalated(self) -> bool:
        return self.decision == Decision.ESCALATE
