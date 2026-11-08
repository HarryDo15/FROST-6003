import base64
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

MAX_MESSAGE_BYTES = 65_536
Status = Literal["pending", "signing", "completed", "expired", "failed"]


def _identifier(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    return value


def _check_base64(value: str) -> str:
    decoded = base64.b64decode(value, validate=True)
    if not decoded:
        raise ValueError("must not be empty")
    return base64.b64encode(decoded).decode("ascii")


def _check_message(value: str) -> str:
    if len(base64.b64decode(value)) > MAX_MESSAGE_BYTES:
        raise ValueError("message exceeds 65536 bytes")
    return value


def _check_share(value: str) -> str:
    if len(base64.b64decode(value)) != 32:
        raise ValueError("signature share must contain 32 bytes")
    return value


Identifier = Annotated[str, Field(min_length=1, max_length=128), AfterValidator(_identifier)]
Base64Str = Annotated[str, Field(max_length=87_384), AfterValidator(_check_base64)]
Message = Annotated[Base64Str, AfterValidator(_check_message)]


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SignatureRequest(APIModel):
    vault_id: Identifier
    payload_to_sign_base64: Message
    requested_by: Identifier


class SignatureResponse(APIModel):
    request_id: Identifier
    status: Status


class SignatureResult(SignatureResponse):
    vault_id: Identifier
    payload_to_sign_base64: Message
    signature_base64: Base64Str | None = None
    verified: bool = False


class PendingRequest(SignatureRequest):
    request_id: Identifier
    status: Status
    expires_at: float
    commitments: dict[str, str] = Field(default_factory=dict)


class PendingRequestsResponse(APIModel):
    requests: list[PendingRequest]


class CommitmentSubmission(APIModel):
    request_id: Identifier
    node_id: Identifier
    commitment_base64: Annotated[Base64Str, Field(max_length=4096)]


class ShareSubmission(APIModel):
    request_id: Identifier
    node_id: Identifier
    partial_signature_base64: Annotated[
        Base64Str, Field(max_length=44), AfterValidator(_check_share)
    ]
