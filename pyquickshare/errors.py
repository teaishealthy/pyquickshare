class NonCriticalMissingServiceError(Exception):
    """Exception raised when a non-critical service is missing."""
    service_name: str
    feature: str | None
    resolution: str | None

    def __init__(self, service_name: str, feature: str | None = None, resolution: str | None = None) -> None:
        self.service_name = service_name
        self.feature = feature
        message = f"Non-critical service '{service_name}' is missing."
        if feature:
            message = f"Non-critical feature '{feature}' of service '{service_name}' is missing."
        if resolution:
            message += f"\nPossible resolution: {resolution}"

        super().__init__(message)
