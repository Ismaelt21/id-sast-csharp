# =============================================================================
#  csharp-sast / core / rules / sinks / command_sinks.py
# =============================================================================
#
#  CATÁLOGO DE SINKS DE COMMAND INJECTION PARA C#
#  ─────────────────────────────────────────────────
#  Cubre: System.Diagnostics.Process, ProcessStartInfo,
#  SSH.NET, PowerShell remoting y shell helpers.
#
# =============================================================================

from __future__ import annotations

COMMAND_INJECTION_SINKS: list[dict] = [

    # =========================================================================
    #  System.Diagnostics — Process y ProcessStartInfo
    # =========================================================================
    {
        "id": "CMD-001", "rule_type": "sink",
        "symbol": "System.Diagnostics.Process.Start",
        "name": "Process.Start con argumentos dinámicos",
        "vulnerability": "COMMAND_INJECTION", "tainted_args": [0, 1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-78", "cvss_base": 9.8,
        "description": (
            "Process.Start con FileName o Arguments controlados por el usuario "
            "permite ejecutar comandos del sistema operativo arbitrarios. "
            "En servidores web puede derivar en toma de control completa."
        ),
        "remediation": (
            "Nunca pasar input del usuario como FileName ni como parte de Arguments. "
            "Usar una whitelist estricta de comandos permitidos. "
            "Separar argumentos con ProcessStartInfo.ArgumentList (no una sola cadena). "
            "Considerar API .NET nativa en lugar de shell commands."
        ),
        "safe_alternative": "API de .NET nativa (System.IO, System.Net.Http, etc.)",
        "frameworks": ["generic", "aspnetcore", "aspnet_mvc"],
        "tags": ["command", "injection", "os", "process"],
    },
    {
        "id": "CMD-002", "rule_type": "sink",
        "symbol": "System.Diagnostics.ProcessStartInfo..ctor",
        "name": "ProcessStartInfo con FileName dinámico",
        "vulnerability": "COMMAND_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-78", "cvss_base": 9.8,
        "description": (
            "ProcessStartInfo construido con FileName controlado por el usuario. "
            "Incluso si Arguments es fijo, un FileName arbitrario permite "
            "ejecutar cualquier binario del sistema."
        ),
        "remediation": (
            "Hardcodear el FileName del ejecutable. "
            "Solo parametrizar Arguments con validación estricta de whitelist."
        ),
        "safe_alternative": "ProcessStartInfo con FileName hardcodeado",
        "frameworks": ["generic", "aspnetcore"],
        "tags": ["command", "injection", "process"],
    },
    {
        "id": "CMD-003", "rule_type": "sink",
        "symbol": "System.Diagnostics.ProcessStartInfo.FileName",
        "name": "ProcessStartInfo.FileName asignado dinámicamente",
        "vulnerability": "COMMAND_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-78", "cvss_base": 9.8,
        "description": "Asignación de FileName desde datos del usuario — equivalente al constructor.",
        "remediation": "FileName debe ser una constante o valor de configuración confiable.",
        "safe_alternative": "ProcessStartInfo con FileName constante",
        "frameworks": ["generic"],
        "tags": ["command", "injection", "process"],
    },
    {
        "id": "CMD-004", "rule_type": "sink",
        "symbol": "System.Diagnostics.ProcessStartInfo.Arguments",
        "name": "ProcessStartInfo.Arguments con input del usuario",
        "vulnerability": "COMMAND_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "medium", "severity": "HIGH",
        "cwe": "CWE-78", "cvss_base": 8.8,
        "description": (
            "Arguments asignado como string único con datos del usuario. "
            "Permite shell argument injection si el programa los interpreta como comandos."
        ),
        "remediation": (
            "Usar ProcessStartInfo.ArgumentList (IList<string>) para pasar "
            "cada argumento separado, evitando parsing de shell. "
            "Validar cada argumento contra whitelist."
        ),
        "safe_alternative": "ProcessStartInfo.ArgumentList",
        "frameworks": ["generic"],
        "tags": ["command", "injection", "process"],
    },
    {
        "id": "CMD-005", "rule_type": "sink",
        "symbol": "System.Diagnostics.ProcessStartInfo.UseShellExecute",
        "name": "ProcessStartInfo con UseShellExecute=true y args dinámicos",
        "vulnerability": "COMMAND_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "medium", "severity": "HIGH",
        "cwe": "CWE-78", "cvss_base": 8.1,
        "description": (
            "UseShellExecute=true delega la ejecución al shell del SO, "
            "interpretando metacaracteres (|, &, ;, `, $). "
            "Con argumentos dinámicos → command injection via metacaracteres."
        ),
        "remediation": "Usar UseShellExecute=false y ArgumentList para evitar interpretación del shell.",
        "safe_alternative": "ProcessStartInfo con UseShellExecute=false + ArgumentList",
        "frameworks": ["generic"],
        "tags": ["command", "injection", "shell", "process"],
    },

    # =========================================================================
    #  SSH.NET y conexiones remotas
    # =========================================================================
    {
        "id": "CMD-006", "rule_type": "sink",
        "symbol": "Renci.SshNet.SshClient.RunCommand",
        "name": "SSH.NET RunCommand con comando dinámico",
        "vulnerability": "COMMAND_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-78", "cvss_base": 9.8,
        "description": (
            "SSH.NET RunCommand ejecuta comandos en un servidor SSH remoto. "
            "Con input dinámico → Command Injection en el servidor remoto."
        ),
        "remediation": "Usar whitelist estricta de comandos SSH permitidos. Nunca pasar input del usuario directamente.",
        "safe_alternative": "Whitelist de comandos SSH permitidos con parámetros separados",
        "frameworks": ["generic"],
        "tags": ["command", "injection", "ssh", "remote"],
    },
    {
        "id": "CMD-007", "rule_type": "sink",
        "symbol": "Renci.SshNet.SshClient.CreateCommand",
        "name": "SSH.NET CreateCommand con comando dinámico",
        "vulnerability": "COMMAND_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-78", "cvss_base": 9.8,
        "description": "SSH.NET CreateCommand crea un comando SSH. Con input dinámico es igual de peligroso que RunCommand.",
        "remediation": "Whitelist estricta. Los comandos SSH no tienen parametrización nativa — construir manualmente.",
        "safe_alternative": "Whitelist de comandos permitidos",
        "frameworks": ["generic"],
        "tags": ["command", "injection", "ssh"],
    },

    # =========================================================================
    #  PowerShell remoting
    # =========================================================================
    {
        "id": "CMD-008", "rule_type": "sink",
        "symbol": "System.Management.Automation.PowerShell.AddScript",
        "name": "PowerShell.AddScript con script dinámico",
        "vulnerability": "COMMAND_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-78", "cvss_base": 9.8,
        "description": (
            "PowerShell.AddScript agrega un script PowerShell para ejecutar. "
            "Con input del usuario en el script → PowerShell Injection / RCE."
        ),
        "remediation": (
            "Usar AddParameter() para pasar valores, no AddScript() con strings construidos. "
            "Hardcodear el script y usar AddParameter para los valores dinámicos."
        ),
        "safe_alternative": "PowerShell.AddCommand() + AddParameter()",
        "frameworks": ["generic"],
        "tags": ["command", "injection", "powershell", "rce"],
    },
    {
        "id": "CMD-009", "rule_type": "sink",
        "symbol": "System.Management.Automation.PowerShell.AddCommand",
        "name": "PowerShell.AddCommand con comando dinámico",
        "vulnerability": "COMMAND_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "medium", "severity": "HIGH",
        "cwe": "CWE-78", "cvss_base": 8.1,
        "description": "PowerShell.AddCommand con nombre de cmdlet dinámico puede ejecutar comandos no previstos.",
        "remediation": "Hardcodear el nombre del comando. Solo parametrizar los argumentos via AddParameter().",
        "safe_alternative": "PowerShell.AddCommand con nombre constante + AddParameter()",
        "frameworks": ["generic"],
        "tags": ["command", "injection", "powershell"],
    },

    # =========================================================================
    #  WMI
    # =========================================================================
    {
        "id": "CMD-010", "rule_type": "sink",
        "symbol": "System.Management.ManagementObjectSearcher..ctor",
        "name": "WMI ManagementObjectSearcher con query dinámica",
        "vulnerability": "COMMAND_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "medium", "severity": "HIGH",
        "cwe": "CWE-78", "cvss_base": 7.5,
        "description": (
            "ManagementObjectSearcher ejecuta queries WMI. "
            "Con query dinámica puede exponer información del sistema o ejecutar métodos WMI."
        ),
        "remediation": "Usar queries WMI fijas con parámetros validados. Validar contra whitelist de clases WMI permitidas.",
        "safe_alternative": "WMI con queries fijas y valores validados",
        "frameworks": ["generic"],
        "tags": ["command", "wmi", "injection"],
    },
]


def get_command_sink_rules() -> list[dict]:
    """Retorna el catálogo completo de reglas de Command Injection."""
    return COMMAND_INJECTION_SINKS


def get_command_sink_symbols() -> set[str]:
    return {rule["symbol"] for rule in COMMAND_INJECTION_SINKS}


def get_command_sinks_by_framework(framework: str) -> list[dict]:
    return [r for r in COMMAND_INJECTION_SINKS if framework in r.get("frameworks", [])]