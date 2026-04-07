#!/usr/bin/env python3
"""
Schema-Driven Validation for MCP Tool Inputs and Outputs

Enforces JSON Schema validation on tool parameters and outputs,
plus size limits to prevent resource abuse.
"""

import json
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class ValidationResult:
    """Result of schema validation"""
    valid: bool
    errors: List[str] = field(default_factory=list)
    tool_name: str = ""


class SchemaValidator:
    """
    JSON Schema-based validation for MCP tool inputs and outputs.

    Maintains a schema registry mapping tool names to their expected
    input/output schemas. Enforces type checking, required fields,
    and size limits.
    """

    DEFAULT_MAX_SIZE_BYTES = 1024 * 1024  # 1MB
    DEFAULT_SCHEMAS: Dict[str, Dict[str, Any]] = {
        "read_file": {
            "input": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": {"type": "string", "maxLength": 4096},
                },
                "additionalProperties": False,
            }
        },
        "file_reader": {
            "input": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": {"type": "string", "maxLength": 4096},
                },
                "additionalProperties": False,
            }
        },
        "execute_command": {
            "input": {
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {"type": "string", "maxLength": 4096},
                },
                "additionalProperties": False,
            }
        },
        "database_query": {
            "input": {
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "maxLength": 12000},
                },
                "additionalProperties": False,
            }
        },
        "sql_executor": {
            "input": {
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "maxLength": 12000},
                },
                "additionalProperties": False,
            }
        },
        "send_email": {
            "input": {
                "type": "object",
                "required": ["to", "subject", "body"],
                "properties": {
                    "to": {"type": "string", "maxLength": 512},
                    "subject": {"type": "string", "maxLength": 512},
                    "body": {"type": "string", "maxLength": 20000},
                },
                "additionalProperties": False,
            }
        },
        "email_sender": {
            "input": {
                "type": "object",
                "required": ["to", "subject", "body"],
                "properties": {
                    "to": {"type": "string", "maxLength": 512},
                    "subject": {"type": "string", "maxLength": 512},
                    "body": {"type": "string", "maxLength": 20000},
                },
                "additionalProperties": False,
            }
        },
        "web_search": {
            "input": {
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "maxLength": 2048},
                },
                "additionalProperties": False,
            }
        },
    }

    def __init__(self):
        self._schemas: Dict[str, Dict[str, Any]] = {}
        self._max_size = self.DEFAULT_MAX_SIZE_BYTES
        self._bootstrap_default_schemas()

    def register_schema(
        self, tool_name: str, input_schema: Dict[str, Any], output_schema: Optional[Dict[str, Any]] = None
    ):
        """Register a JSON Schema for a tool."""
        self._schemas[tool_name] = {
            "input": input_schema,
            "output": output_schema,
        }

    def get_schema(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Return the registered schema bundle for a tool, if available."""
        return self._schemas.get(tool_name)

    def get_input_contract(self, tool_name: str) -> Dict[str, Any]:
        """Return contract-style input metadata for protocol integrity checks."""
        bundle = self._schemas.get(tool_name) or {}
        schema = bundle.get("input") or {}
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        return {
            "required_argument_fields": list(schema.get("required", [])) if isinstance(schema, dict) else [],
            "allowed_argument_fields": list(props.keys()),
            "additional_properties": schema.get("additionalProperties", True) if isinstance(schema, dict) else True,
        }

    def validate_input(
        self, tool_name: str, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate tool input parameters against registered schema.

        Returns:
            {"valid": bool, "errors": List[str]}
        """
        errors = []

        # Size check
        try:
            param_json = json.dumps(parameters)
            if len(param_json.encode("utf-8")) > self._max_size:
                errors.append(
                    f"Input size {len(param_json)} bytes exceeds limit {self._max_size}"
                )
        except (TypeError, ValueError) as e:
            errors.append(f"Parameters not JSON-serializable: {e}")

        # Schema check
        schema_entry = self._schemas.get(tool_name)
        if schema_entry and schema_entry.get("input"):
            schema = schema_entry["input"]
            schema_errors = self._validate_against_schema(parameters, schema)
            errors.extend(schema_errors)

        return {"valid": len(errors) == 0, "errors": errors, "tool_name": tool_name}

    def validate_output(
        self, tool_name: str, output: Any
    ) -> Dict[str, Any]:
        """Validate tool output against registered schema."""
        errors = []

        schema_entry = self._schemas.get(tool_name)
        if schema_entry and schema_entry.get("output"):
            schema = schema_entry["output"]
            if isinstance(output, dict):
                schema_errors = self._validate_against_schema(output, schema)
                errors.extend(schema_errors)

        return {"valid": len(errors) == 0, "errors": errors, "tool_name": tool_name}

    def enforce_size_limits(self, data: Any, max_size_bytes: Optional[int] = None) -> bool:
        """Check if data is within size limits."""
        limit = max_size_bytes or self._max_size
        try:
            size = len(json.dumps(data).encode("utf-8"))
            return size <= limit
        except (TypeError, ValueError):
            return False

    def _validate_against_schema(
        self, data: Dict[str, Any], schema: Dict[str, Any]
    ) -> List[str]:
        """Simple JSON Schema validation (subset of JSON Schema spec)."""
        errors = []

        # Check required fields
        required = schema.get("required", [])
        for field_name in required:
            if field_name not in data:
                errors.append(f"Missing required field: {field_name}")

        # Check property types
        properties = schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            if prop_name in data:
                value = data[prop_name]
                expected_type = prop_schema.get("type")

                if expected_type and not self._check_type(value, expected_type):
                    errors.append(
                        f"Field '{prop_name}': expected type '{expected_type}', "
                        f"got '{type(value).__name__}'"
                    )

                # Check string constraints
                if expected_type == "string" and isinstance(value, str):
                    max_len = prop_schema.get("maxLength")
                    if max_len and len(value) > max_len:
                        errors.append(
                            f"Field '{prop_name}': length {len(value)} exceeds maxLength {max_len}"
                        )

                # Check enum
                enum_values = prop_schema.get("enum")
                if enum_values and value not in enum_values:
                    errors.append(
                        f"Field '{prop_name}': value '{value}' not in enum {enum_values}"
                    )

        # Check for additional properties
        if schema.get("additionalProperties") is False:
            allowed = set(properties.keys())
            extra = set(data.keys()) - allowed
            if extra:
                errors.append(f"Unexpected fields: {list(extra)}")

        return errors

    def _check_type(self, value: Any, expected_type: str) -> bool:
        """Check if value matches expected JSON Schema type."""
        type_map = {
            "string": str,
            "number": (int, float),
            "integer": int,
            "boolean": bool,
            "array": list,
            "object": dict,
        }
        expected = type_map.get(expected_type)
        if expected is None:
            return True  # Unknown type, pass
        return isinstance(value, expected)

    def get_registered_tools(self) -> List[str]:
        return list(self._schemas.keys())

    def _bootstrap_default_schemas(self) -> None:
        for tool_name, bundle in self.DEFAULT_SCHEMAS.items():
            if tool_name in self._schemas:
                continue
            self.register_schema(tool_name, bundle.get("input", {}), bundle.get("output"))


__all__ = ["SchemaValidator", "ValidationResult"]
