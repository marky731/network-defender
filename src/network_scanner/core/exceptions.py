"""Custom exception hierarchy for the network scanner."""


class ScannerError(Exception):
    """Base exception for all scanner errors."""

    def __init__(self, message: str, scanner_name: str = ""):
        self.scanner_name = scanner_name
        super().__init__(f"[{scanner_name}] {message}" if scanner_name else message)


class ScanTimeoutError(ScannerError):
    """Raised when a scan operation times out."""

    def __init__(self, target: str, timeout: float, scanner_name: str = ""):
        self.target = target
        self.timeout = timeout
        super().__init__(
            f"Scan timed out for {target} after {timeout}s",
            scanner_name=scanner_name,
        )


class HostUnreachableError(ScannerError):
    """Raised when a target host is unreachable."""

    def __init__(self, host: str, scanner_name: str = ""):
        self.host = host
        super().__init__(f"Host unreachable: {host}", scanner_name=scanner_name)


class ConfigurationError(ScannerError):
    """Raised when there is a configuration problem."""

    pass


class CapabilityError(ScannerError):
    """Raised when a required capability (root, scapy) is not available."""

    def __init__(self, capability: str, scanner_name: str = ""):
        self.capability = capability
        super().__init__(
            f"Required capability not available: {capability}",
            scanner_name=scanner_name,
        )
