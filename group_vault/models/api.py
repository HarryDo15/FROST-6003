import base64
from typing import Annotated

from pydantic import AfterValidator, BaseModel


def _check_base64(value: str) -> str:
    if not base64.b64decode(value, validate=True):
        raise ValueError("must not be empty")
    return value


Base64Str = Annotated[str, AfterValidator(_check_base64)]


class SignatureRequest(BaseModel):
    vault_id: str
    payload_to_sign_base64: Base64Str
    requested_by: str


class SignatureResponse(BaseModel):
    request_id: str
    status: str


class PendingRequest(SignatureRequest):
    request_id: str


class PendingRequestsResponse(BaseModel):
    requests: list[PendingRequest]


class ShareSubmission(BaseModel):
    request_id: str
    node_id: str
    partial_signature_base64: Base64Str
