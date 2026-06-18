# =============================================================================
#  csharp-sast / core / rules / sinks / xml_sinks.py
# =============================================================================
#
#  CATÁLOGO DE SINKS DE XML EXTERNAL ENTITY (XXE) PARA C#
#  ─────────────────────────────────────────────────────────
#  Cubre: XmlDocument, XmlTextReader, XmlReader, XDocument,
#  XmlSerializer, XPathDocument y variantes LINQ to XML.
#
#  NOTA SOBRE .NET CORE VS .NET FRAMEWORK:
#    En .NET Core (3.0+) XmlTextReader tiene DtdProcessing=Prohibit por defecto.
#    En .NET Framework tiene DtdProcessing=Parse (INSEGURO por defecto).
#    Se reportan ambos con confianza ajustada según el contexto.
#
# =============================================================================

from __future__ import annotations

XXE_SINKS: list[dict] = [

    # =========================================================================
    #  System.Xml.XmlDocument
    # =========================================================================
    {
        "id": "XXE-001", "rule_type": "sink",
        "symbol": "System.Xml.XmlDocument.Load",
        "name": "XmlDocument.Load sin DtdProcessing=Prohibit",
        "vulnerability": "XXE", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "HIGH",
        "cwe": "CWE-611", "cvss_base": 7.5,
        "description": (
            "XmlDocument.Load procesa DTDs externas por defecto en .NET Framework. "
            "Con XML malicioso que contenga referencias de entidad externa, "
            "el atacante puede leer archivos del servidor (file:///etc/passwd) "
            "o hacer peticiones a servicios internos (SSRF via XXE)."
        ),
        "remediation": (
            "Antes de cargar: xmlDoc.XmlResolver = null; "
            "O usar XmlReader con XmlReaderSettings { "
            "DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }."
        ),
        "safe_alternative": "XmlReader con XmlReaderSettings.DtdProcessing=Prohibit",
        "frameworks": ["generic", "aspnetcore", "wcf"],
        "tags": ["xxe", "xml", "injection", "lfi", "ssrf"],
    },
    {
        "id": "XXE-002", "rule_type": "sink",
        "symbol": "System.Xml.XmlDocument.LoadXml",
        "name": "XmlDocument.LoadXml con datos externos",
        "vulnerability": "XXE", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "HIGH",
        "cwe": "CWE-611", "cvss_base": 7.5,
        "description": (
            "XmlDocument.LoadXml parsea XML desde string. "
            "Mismo riesgo de XXE si el XML viene del usuario "
            "y el XmlResolver no está deshabilitado."
        ),
        "remediation": "Configurar xmlDoc.XmlResolver = null antes de llamar LoadXml.",
        "safe_alternative": "XmlReader con settings seguras",
        "frameworks": ["generic", "aspnetcore"],
        "tags": ["xxe", "xml"],
    },

    # =========================================================================
    #  System.Xml.XmlTextReader
    # =========================================================================
    {
        "id": "XXE-003", "rule_type": "sink",
        "symbol": "System.Xml.XmlTextReader..ctor",
        "name": "XmlTextReader sin DtdProcessing=Prohibit",
        "vulnerability": "XXE", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "HIGH",
        "cwe": "CWE-611", "cvss_base": 7.5,
        "description": (
            "XmlTextReader en .NET Framework habilita DTD processing por defecto. "
            "En .NET Core está deshabilitado por defecto, pero el código "
            "que lo configura explícitamente puede ser vulnerable."
        ),
        "remediation": (
            "Inmediatamente después de crear: reader.DtdProcessing = DtdProcessing.Prohibit; "
            "O migrar a XmlReader.Create con XmlReaderSettings seguras."
        ),
        "safe_alternative": "XmlReader.Create con XmlReaderSettings seguras",
        "frameworks": ["generic"],
        "tags": ["xxe", "xml"],
    },

    # =========================================================================
    #  System.Xml.XmlReader
    # =========================================================================
    {
        "id": "XXE-004", "rule_type": "sink",
        "symbol": "System.Xml.XmlReader.Create",
        "name": "XmlReader.Create sin XmlReaderSettings seguras",
        "vulnerability": "XXE", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "medium", "severity": "HIGH",
        "cwe": "CWE-611", "cvss_base": 7.5,
        "description": (
            "XmlReader.Create puede ser seguro (con settings adecuadas) o inseguro "
            "(sin settings, o con DtdProcessing != Prohibit). "
            "Se reporta como potencial si procesa datos externos sin settings explícitas."
        ),
        "remediation": (
            "Siempre pasar settings: "
            "XmlReader.Create(stream, new XmlReaderSettings { "
            "DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null })."
        ),
        "safe_alternative": "XmlReader.Create con XmlReaderSettings seguras explícitas",
        "frameworks": ["generic", "aspnetcore"],
        "tags": ["xxe", "xml"],
    },

    # =========================================================================
    #  System.Xml.Linq (LINQ to XML)
    # =========================================================================
    {
        "id": "XXE-005", "rule_type": "sink",
        "symbol": "System.Xml.Linq.XDocument.Load",
        "name": "XDocument.Load con datos externos",
        "vulnerability": "XXE", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "medium", "severity": "MEDIUM",
        "cwe": "CWE-611", "cvss_base": 5.9,
        "description": (
            "XDocument.Load (LINQ to XML) puede procesar DTDs si el lector "
            "no está configurado correctamente. "
            "Menor riesgo que XmlDocument en .NET Core, pero no nulo en .NET Framework."
        ),
        "remediation": "Usar XDocument.Load(XmlReader.Create(stream, safeSettings)) en lugar de XDocument.Load(path).",
        "safe_alternative": "XDocument.Load con XmlReader seguro",
        "frameworks": ["generic"],
        "tags": ["xxe", "xml", "linq"],
    },
    {
        "id": "XXE-006", "rule_type": "sink",
        "symbol": "System.Xml.Linq.XElement.Load",
        "name": "XElement.Load con datos externos",
        "vulnerability": "XXE", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "medium", "severity": "MEDIUM",
        "cwe": "CWE-611", "cvss_base": 5.9,
        "description": "XElement.Load — mismo riesgo que XDocument.Load con DTD processing.",
        "remediation": "Usar XmlReader con settings seguras antes de cargar.",
        "safe_alternative": "XElement.Load con XmlReader seguro",
        "frameworks": ["generic"],
        "tags": ["xxe", "xml", "linq"],
    },
    {
        "id": "XXE-007", "rule_type": "sink",
        "symbol": "System.Xml.Linq.XDocument.Parse",
        "name": "XDocument.Parse con datos externos",
        "vulnerability": "XXE", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "medium", "severity": "MEDIUM",
        "cwe": "CWE-611", "cvss_base": 5.9,
        "description": "XDocument.Parse parsea XML desde string con los mismos riesgos de XXE.",
        "remediation": "Parsear via XmlReader con settings seguras.",
        "safe_alternative": "XmlReader con DtdProcessing=Prohibit + XDocument.Load",
        "frameworks": ["generic"],
        "tags": ["xxe", "xml", "linq"],
    },

    # =========================================================================
    #  XmlSerializer y XPathDocument
    # =========================================================================
    {
        "id": "XXE-008", "rule_type": "sink",
        "symbol": "System.Xml.Serialization.XmlSerializer.Deserialize",
        "name": "XmlSerializer.Deserialize con datos externos",
        "vulnerability": "XXE", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "medium", "severity": "MEDIUM",
        "cwe": "CWE-611", "cvss_base": 5.9,
        "description": (
            "XmlSerializer.Deserialize puede ser vulnerable a XXE si el reader "
            "subyacente permite DTD processing. "
            "Menor riesgo que XmlDocument pero no nulo."
        ),
        "remediation": "Pasar un XmlReader configurado con DtdProcessing=Prohibit a Deserialize().",
        "safe_alternative": "XmlSerializer.Deserialize(XmlReader con settings seguras)",
        "frameworks": ["generic", "wcf"],
        "tags": ["xxe", "xml", "deserialization"],
    },
    {
        "id": "XXE-009", "rule_type": "sink",
        "symbol": "System.Xml.XPath.XPathDocument..ctor",
        "name": "XPathDocument con datos externos",
        "vulnerability": "XXE", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "medium", "severity": "HIGH",
        "cwe": "CWE-611", "cvss_base": 6.5,
        "description": "XPathDocument para evaluación XPath. Si carga XML externo sin restricciones → XXE.",
        "remediation": "Usar XmlReader con DtdProcessing=Prohibit como argumento del constructor.",
        "safe_alternative": "XPathDocument(XmlReader con settings seguras)",
        "frameworks": ["generic"],
        "tags": ["xxe", "xml", "xpath"],
    },

    # =========================================================================
    #  XmlSchema y validación
    # =========================================================================
    {
        "id": "XXE-010", "rule_type": "sink",
        "symbol": "System.Xml.Schema.XmlSchema.Read",
        "name": "XmlSchema.Read con datos externos",
        "vulnerability": "XXE", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "low", "severity": "MEDIUM",
        "cwe": "CWE-611", "cvss_base": 5.3,
        "description": "XmlSchema.Read carga un schema XML — puede ser explotado con XXE si el schema viene de una fuente no confiable.",
        "remediation": "Nunca cargar XSD schemas desde fuentes controladas por el usuario.",
        "safe_alternative": "Schemas XSD precompilados y embebidos en el proyecto",
        "frameworks": ["generic"],
        "tags": ["xxe", "xml", "schema"],
    },
]


def get_xml_sink_rules() -> list[dict]:
    """Retorna el catálogo completo de reglas de XXE."""
    return XXE_SINKS


def get_xml_sink_symbols() -> set[str]:
    return {rule["symbol"] for rule in XXE_SINKS}


def get_xml_sinks_by_framework(framework: str) -> list[dict]:
    return [r for r in XXE_SINKS if framework in r.get("frameworks", [])]