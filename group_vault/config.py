import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError, model_validator

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]
Token = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


def _base64(value: str) -> str:
    if not base64.b64decode(value, validate=True):
        raise ValueError("empty encoded value")
    return value


Encoded = Annotated[str, Field(max_length=131072), AfterValidator(_base64)]


class PublicVault(ConfigModel):
    vault_id: Identifier
    threshold: int = Field(ge=2, le=255)
    total: int = Field(ge=2, le=255)
    public_key_package: Encoded
    verifying_key: Encoded

    @model_validator(mode="after")
    def check_threshold(self) -> "PublicVault":
        if self.threshold > self.total:
            raise ValueError("threshold exceeds total nodes")
        if len(base64.b64decode(self.verifying_key)) != 32:
            raise ValueError("Ed25519 verifying key must contain 32 bytes")
        return self


class CoordinatorConfig(ConfigModel):
    vault: PublicVault
    requester_token_hash: Token
    node_token_hashes: dict[str, Token]

    @model_validator(mode="after")
    def check_nodes(self) -> "CoordinatorConfig":
        if set(self.node_token_hashes) != {str(i) for i in range(1, self.vault.total + 1)}:
            raise ValueError("one credential is required for every node")
        hashes = [self.requester_token_hash, *self.node_token_hashes.values()]
        if len(hashes) != len(set(hashes)):
            raise ValueError("each participant must have a different credential")
        return self


class NodeConfig(ConfigModel):
    vault: PublicVault
    node_id: Identifier
    token: Token
    share_store: str = "share.json"

    @model_validator(mode="after")
    def check_node(self) -> "NodeConfig":
        if self.node_id not in {str(i) for i in range(1, self.vault.total + 1)}:
            raise ValueError("node is not a member of this vault")
        if Path(self.share_store).name != self.share_store or self.share_store in ("", ".", ".."):
            raise ValueError("share_store must be a filename beside the node configuration")
        return self


class RequesterConfig(ConfigModel):
    vault: PublicVault
    token: Token


def load_config[Config: BaseModel](path: Path, model: type[Config]) -> Config:
    try:
        return model.model_validate_json(path.read_text())
    except ValidationError as exc:
        raise ValueError(f"invalid {model.__name__} configuration") from exc


def write_config(path: Path, value: BaseModel) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value.model_dump(), output, indent=2)
        output.write("\n")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
