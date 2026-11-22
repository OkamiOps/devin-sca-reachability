class ServiceError(Exception):
    def __init__(self, status_code: int, public_message: str):
        super().__init__(public_message)
        self.status_code = status_code
        self.public_message = public_message


class RetryableError(Exception):
    """An upstream or transient error that may be retried with bounded backoff."""


class ScanError(Exception):
    """A permanent analysis error; the scan must not be presented as complete."""


class PublicError(ScanError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


class PublicRetryableError(PublicError, RetryableError):
    """A public API error that retains the worker's bounded retry behavior."""
