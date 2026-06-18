# =============================================================================
#  csharp-sast / core / rules / sinks / razor_sinks.py
# =============================================================================

from __future__ import annotations


def get_razor_sink_rules() -> list[dict]:
    """Reglas de sink para XSS en Razor / ASP.NET (CWE-79)."""
    return [
        {
            "id": "SINK-RAZOR-001",
            "rule_type": "sink",
            "symbol": "Microsoft.AspNetCore.Html.HtmlString",
            "name": "HtmlString con input del usuario",
            "vulnerability": "RAZOR_XSS",
            "tainted_args": [0],
            "always_vulnerable": False,
            "confidence": "high",
            "severity": "HIGH",
            "cwe": "CWE-79",
            "cvss_base": 6.1,
            "description": "HtmlString desactiva el auto-encoding de Razor. Input del usuario sin sanitizar causa XSS.",
            "remediation": "Usar @variable en Razor (encodea automáticamente). Si necesitas HTML, usar HtmlSanitizer primero.",
            "frameworks": ["aspnetcore"],
            "tags": ["xss", "razor"],
        },
        {
            "id": "SINK-RAZOR-002",
            "rule_type": "sink",
            "symbol": "Microsoft.AspNetCore.Mvc.Rendering.HtmlHelperExtensions.Raw",
            "name": "Html.Raw() con input del usuario",
            "vulnerability": "RAZOR_XSS",
            "tainted_args": [0],
            "always_vulnerable": False,
            "confidence": "high",
            "severity": "HIGH",
            "cwe": "CWE-79",
            "cvss_base": 6.1,
            "description": "Html.Raw() emite HTML sin encoding. Con input del usuario es XSS directo.",
            "remediation": "No usar Html.Raw() con input del usuario. Usar @Html.Encode() o simplemente @variable.",
            "frameworks": ["aspnetcore", "aspnet_mvc"],
            "tags": ["xss", "razor"],
        },
        {
            "id": "SINK-RAZOR-003",
            "rule_type": "sink",
            "symbol": "System.Web.HtmlString",
            "name": "System.Web.HtmlString (ASP.NET MVC clásico)",
            "vulnerability": "RAZOR_XSS",
            "tainted_args": [0],
            "always_vulnerable": False,
            "confidence": "high",
            "severity": "HIGH",
            "cwe": "CWE-79",
            "cvss_base": 6.1,
            "description": "System.Web.HtmlString en ASP.NET MVC clásico emite HTML sin encoding.",
            "remediation": "Usar Html.Encode() o reemplazar por Microsoft.AspNetCore.Html.HtmlString con sanitización.",
            "frameworks": ["aspnet_mvc"],
            "tags": ["xss", "razor", "legacy"],
        },
        {
            "id": "SINK-RAZOR-004",
            "rule_type": "sink",
            "symbol": "System.Web.Mvc.HtmlHelper.Raw",
            "name": "Html.Raw() ASP.NET MVC clásico",
            "vulnerability": "RAZOR_XSS",
            "tainted_args": [0],
            "always_vulnerable": False,
            "confidence": "high",
            "severity": "HIGH",
            "cwe": "CWE-79",
            "cvss_base": 6.1,
            "description": "Html.Raw() en ASP.NET MVC clásico emite HTML sin encoding.",
            "remediation": "Usar @Html.Encode(variable) en lugar de @Html.Raw(variable).",
            "frameworks": ["aspnet_mvc"],
            "tags": ["xss", "razor", "legacy"],
        },
    ]