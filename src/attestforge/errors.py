"""Public, stable failure codes used by the CLI and API."""


class AttestForgeError(ValueError):
    """A fail-closed validation or verification failure."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)
