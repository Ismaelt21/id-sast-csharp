# =============================================================================
#  csharp-sast / core / rules / sinks / reflection_sinks.py
# =============================================================================

from __future__ import annotations


def get_reflection_sink_rules() -> list[dict]:
    """Reglas de sink para Reflection Abuse (CWE-470)."""
    return [
        {
            "id": "SINK-REFLECT-001",
            "rule_type": "sink",
            "symbol": "System.Reflection.Assembly.Load",
            "name": "Assembly.Load con input del usuario",
            "vulnerability": "REFLECTION_ABUSE",
            "tainted_args": [0],
            "always_vulnerable": False,
            "confidence": "high",
            "severity": "CRITICAL",
            "cwe": "CWE-470",
            "cvss_base": 9.8,
            "description": "Assembly.Load con nombre controlado por el usuario permite cargar assemblies arbitrarios.",
            "remediation": "Usar una whitelist de assemblies permitidos. Nunca pasar input del usuario directamente.",
            "frameworks": ["generic"],
            "tags": ["reflection", "rce"],
        },
        {
            "id": "SINK-REFLECT-002",
            "rule_type": "sink",
            "symbol": "System.Reflection.Assembly.LoadFrom",
            "name": "Assembly.LoadFrom con ruta del usuario",
            "vulnerability": "REFLECTION_ABUSE",
            "tainted_args": [0],
            "always_vulnerable": False,
            "confidence": "high",
            "severity": "CRITICAL",
            "cwe": "CWE-470",
            "cvss_base": 9.8,
            "description": "Assembly.LoadFrom con ruta controlada por el usuario permite cargar código arbitrario.",
            "remediation": "Validar la ruta contra una whitelist de directorios permitidos.",
            "frameworks": ["generic"],
            "tags": ["reflection", "rce", "path"],
        },
        {
            "id": "SINK-REFLECT-003",
            "rule_type": "sink",
            "symbol": "System.Activator.CreateInstance",
            "name": "Activator.CreateInstance con tipo del usuario",
            "vulnerability": "REFLECTION_ABUSE",
            "tainted_args": [0],
            "always_vulnerable": False,
            "confidence": "medium",
            "severity": "HIGH",
            "cwe": "CWE-470",
            "cvss_base": 8.1,
            "description": "CreateInstance con nombre de tipo controlado por el usuario permite instanciar tipos arbitrarios.",
            "remediation": "Usar una whitelist de tipos permitidos. Validar con Type.IsAssignableTo() antes de instanciar.",
            "frameworks": ["generic"],
            "tags": ["reflection"],
        },
        {
            "id": "SINK-REFLECT-004",
            "rule_type": "sink",
            "symbol": "System.Type.GetType",
            "name": "Type.GetType con nombre del usuario",
            "vulnerability": "REFLECTION_ABUSE",
            "tainted_args": [0],
            "always_vulnerable": False,
            "confidence": "medium",
            "severity": "HIGH",
            "cwe": "CWE-470",
            "cvss_base": 7.5,
            "description": "Type.GetType con nombre controlado por el usuario puede revelar información de tipos internos.",
            "remediation": "Validar el nombre del tipo contra una whitelist antes de llamar a GetType().",
            "frameworks": ["generic"],
            "tags": ["reflection", "information-disclosure"],
        },
    ]