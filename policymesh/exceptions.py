class PolicyMeshError(Exception):
    """Base exception for PolicyMesh SDK errors."""

    def __init__(self, message, status_code=None, response=None, request_id=None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response
        self.request_id = request_id


class PolicyBlockedError(PolicyMeshError):
    """Raised when an action is blocked by policy."""

    def __init__(self, message, action_id=None, policy_matched=None, **kwargs):
        super().__init__(message, **kwargs)
        self.action_id = action_id
        self.policy_matched = policy_matched


class PolicyEscalateError(PolicyMeshError):
    """Raised when an action requires human approval."""

    def __init__(self, message, action_id=None, policy_matched=None, **kwargs):
        super().__init__(message, **kwargs)
        self.action_id = action_id
        self.policy_matched = policy_matched


class PolicyMeshAuthError(PolicyMeshError):
    """Raised when authentication fails."""


class PolicyMeshForbiddenError(PolicyMeshError):
    """Raised when the caller is authenticated but not authorized."""


class PolicyMeshValidationError(PolicyMeshError):
    """Raised when the API rejects the request payload."""


class PolicyMeshRateLimitError(PolicyMeshError):
    """Raised when the API rate limit is exceeded."""


class PolicyMeshServerError(PolicyMeshError):
    """Raised when the PolicyMesh API returns a server-side error."""


class PolicyMeshTimeoutError(PolicyMeshError):
    """Raised when the PolicyMesh API times out."""


class PolicyMeshConnectionError(PolicyMeshError):
    """Raised when the PolicyMesh API cannot be reached."""


class PolicyMeshUnexpectedResponseError(PolicyMeshError):
    """Raised when the API returns an unexpected status or body."""
