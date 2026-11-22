"""Deserialization consumer taxonomy, not a gadget library or format scanner.

A serialized-looking value is only a lead. Qualification needs a source-qualified
entry-to-consumer path and an existing exact in-scope endpoint asset.
"""

FAMILY = "deserialization"
SINKS = frozenset({"java", "dotnet", "php", "python", "node", "ruby", "other"})


def validate_sink(value):
    if not isinstance(value, str) or value not in SINKS:
        raise ValueError("deserialization sink needs an identified runtime kind")
    return value
