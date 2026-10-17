"""Exception hierarchy. Each class carries the process exit code it maps to."""

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_PREFLIGHT = 3
EXIT_PERMISSION = 4
EXIT_UPDATE_FAILED = 5
EXIT_NOT_READY = 6
EXIT_BUSY = 75


class RuGeoblockError(Exception):
    exit_code = EXIT_FAILURE


class ConfigError(RuGeoblockError):
    exit_code = EXIT_USAGE


class PreflightError(RuGeoblockError):
    exit_code = EXIT_PREFLIGHT


class PrivilegeError(RuGeoblockError):
    exit_code = EXIT_PERMISSION


class DataError(RuGeoblockError):
    """Downloaded or staged data failed validation or could not be fetched."""

    exit_code = EXIT_UPDATE_FAILED


class FirewallError(RuGeoblockError):
    """nft refused a ruleset or the installed rules do not match expectations."""

    exit_code = EXIT_UPDATE_FAILED


class NotReadyError(RuGeoblockError):
    """No dataset or no previous generation is available."""

    exit_code = EXIT_NOT_READY


class BusyError(RuGeoblockError):
    exit_code = EXIT_BUSY
