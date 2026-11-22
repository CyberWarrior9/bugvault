"""Command/argument sink taxonomy for offline RCE source-qualified review.

Names identify candidate consumers. This module cannot construct or send commands.
"""

FAMILY = "command-injection"
SINKS = frozenset({"subprocess-argv", "shell-construction", "process-wrapper"})


def validate_sink(value):
    if not isinstance(value, str) or value not in SINKS:
        raise ValueError("command-injection sink must be a supported process/argument kind")
    return value
