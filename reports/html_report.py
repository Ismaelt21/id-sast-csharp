# =============================================================================
#  csharp-sast / reports / html_report.py
# =============================================================================
#
#  GENERADOR DE REPORTE HTML PARA CSHARP-SAST
#  ────────────────────────────────────────────
#  Convierte los resultados del análisis en un reporte HTML interactivo,
#  visual y seguro para revisión manual, auditoría y entrega ejecutiva.
#
#  CARACTERÍSTICAS:
#    • HTML autocontenido, sin dependencias externas
#    • Resumen ejecutivo con nivel de riesgo y métricas clave
#    • Filtros por severidad y búsqueda de texto
#    • Tarjetas detalladas por vulnerabilidad
#    • Path de taint, snippets de código y remediación
#    • Referencias OWASP/CWE enlazadas
#    • Diseño responsivo y seguro frente a inyección HTML
#
#  USO:
#    report = HTMLReport()
#    html_str = report.generate(...)
#    report.save(html_str, Path("reports/output/report.html"))
#
# =============================================================================

from __future__ import annotations

import html as html_lib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.parsers.ast_importer import ParsedCSharpModel
from core.parsers.framework_detector import FrameworkProfile
from reports.json_report import JsonReport, ReportMetrics

logger = logging.getLogger(__name__)


@dataclass
class HTMLReportConfig:
    """Configuración del generador HTML."""

    output_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "output")
    title: str = "csharp-sast Security Report"
    filename_prefix: str = "csharp_sast_report"
    max_vulns: int = 120
    max_path_steps: int = 10
    max_code_lines: int = 8
    show_code: bool = True
    show_path: bool = True


class HTMLReport:
    """Generador de reporte HTML para csharp-sast."""

    def __init__(self, config: HTMLReportConfig | None = None) -> None:
        self.config = config or HTMLReportConfig()
        self.config.output_dir = Path(self.config.output_dir)

    def generate(
        self,
        vulnerabilities: list[Any],
        model: ParsedCSharpModel,
        profile: FrameworkProfile,
        scan_id: str | None = None,
        project_name: str = "csharp-project",
        project_path: str = "",
        metrics: ReportMetrics | None = None,
        false_positives_removed: int = 0,
    ) -> str:
        """Genera el HTML completo como string."""
        report_data = JsonReport().generate_dict(
            vulnerabilities=vulnerabilities,
            model=model,
            profile=profile,
            scan_id=scan_id,
            project_name=project_name,
            project_path=project_path,
            metrics=metrics,
            false_positives_removed=false_positives_removed,
        )
        return self._build_html(report_data)

    def save(self, html_content: str, output_path: Path) -> Path:
        """Guarda el reporte HTML en disco."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding="utf-8")
        logger.info("HTMLReport: guardado en '%s'", output_path)
        return output_path

    def generate_and_save(
        self,
        vulnerabilities: list[Any],
        model: ParsedCSharpModel,
        profile: FrameworkProfile,
        scan_id: str | None = None,
        project_name: str = "csharp-project",
        project_path: str = "",
        metrics: ReportMetrics | None = None,
        false_positives_removed: int = 0,
        output_path: Path | None = None,
    ) -> Path:
        """Genera y guarda el reporte HTML en un solo paso."""
        html_content = self.generate(
            vulnerabilities=vulnerabilities,
            model=model,
            profile=profile,
            scan_id=scan_id,
            project_name=project_name,
            project_path=project_path,
            metrics=metrics,
            false_positives_removed=false_positives_removed,
        )

        if output_path is None:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_path = self.config.output_dir / f"{self.config.filename_prefix}_{stamp}.html"

        return self.save(html_content, output_path)

    def _build_html(self, report_data: dict[str, Any]) -> str:
        summary = report_data.get("summary", {})
        project = report_data.get("project", {})
        metrics = report_data.get("metrics", {})
        framework_info = report_data.get("framework_info", {})
        fp_info = report_data.get("false_positives_info", {})
        remediation_summary = report_data.get("remediation_summary", {})
        vulns = report_data.get("vulnerabilities", []) or []

        sev = _normalize_severity_counts(summary.get("by_severity", {}))
        total_vulns = int(summary.get("total_vulnerabilities", summary.get("total", len(vulns))))
        risk_level = _text(summary.get("risk_level", "CLEAN"))
        visible_vulns = vulns[: self.config.max_vulns]
        hidden_count = max(0, len(vulns) - len(visible_vulns))

        parts = [
            "<!DOCTYPE html>",
            '<html lang="es">',
            "<head>",
            '<meta charset="UTF-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
            f"<title>{self._esc(self.config.title)}</title>",
            "<style>",
            self._styles(),
            "</style>",
            "</head>",
            '<body data-theme="dark">',
            '<div class="shell">',
            self._hero(project, summary, sev, risk_level, total_vulns, fp_info, report_data),
            self._overview(project, sev, fp_info, framework_info, total_vulns),
            self._toolbar(),
            self._filters(),
            self._findings(visible_vulns, hidden_count),
            self._metrics(metrics),
            self._context(summary, remediation_summary, project, framework_info),
            "</div>",
            self._script(),
            "</body>",
            "</html>",
        ]
        return "".join(parts)

    def _hero(
        self,
        project: dict[str, Any],
        summary: dict[str, Any],
        sev: dict[str, int],
        risk_level: str,
        total_vulns: int,
        fp_info: dict[str, Any],
        report_data: dict[str, Any],
    ) -> str:
        project_name = _text(project.get("name", "Unknown project"))
        project_path = _text(project.get("path", ""))
        framework = _text(project.get("framework", ""))
        language_version = _text(project.get("language_version", ""))
        generated_at = _text(report_data.get("generated_at", _now_iso()))
        scan_id = _text(report_data.get("scan_id", ""))
        schema_version = _text(report_data.get("schema_version", ""))
        false_positives_removed = int(fp_info.get("total_removed", 0))

        chip_parts = []
        if framework:
            chip_parts.append(f'<span class="chip">Framework: {self._esc(framework)}</span>')
        if language_version:
            chip_parts.append(f'<span class="chip">{self._esc(language_version)}</span>')
        if false_positives_removed:
            chip_parts.append(f'<span class="chip chip-soft">FP removidos: {false_positives_removed}</span>')

        severity_html = "".join(
            f'<div class="severity-card severity-{name.lower()}"><span>{name}</span><strong>{count}</strong></div>'
            for name, count in sev.items()
        )

        return f"""
<section class="hero">
  <div class="hero__copy">
    <span class="eyebrow">csharp-sast</span>
    <h1>{self._esc(project_name)}</h1>
    <p class="hero__subtitle">{self._esc(project_path or 'Proyecto analizado')} · Riesgo {self._esc(risk_level)}</p>
    <div class="chip-row">{''.join(chip_parts)}</div>
  </div>
  <div class="hero__grid">
    <div class="risk-card risk-{self._esc(risk_level.lower())}">
      <span>Nivel de riesgo</span>
      <strong>{self._esc(risk_level)}</strong>
    </div>
    <div class="metric-card">
      <span>Total findings</span>
      <strong>{total_vulns}</strong>
      <small>Schema {self._esc(schema_version)} · Scan {self._esc(scan_id[:12] or '-')}</small>
    </div>
  </div>
  <div class="severity-strip" aria-label="severity summary">{severity_html}</div>
  <div class="hero__footer">Generado: {self._esc(generated_at)}</div>
</section>
<div class="top-controls">
  <button class="control-btn" id="theme-toggle" type="button" aria-label="Cambiar tema">Toggle theme</button>
  <button class="control-btn control-btn--ghost" id="print-report" type="button" aria-label="Exportar a PDF">Print / PDF</button>
</div>
"""

    def _toolbar(self) -> str:
        return ""

    def _overview(
        self,
        project: dict[str, Any],
        sev: dict[str, int],
        fp_info: dict[str, Any],
        framework_info: dict[str, Any],
        total_vulns: int,
    ) -> str:
        target_frameworks = framework_info.get("detected_frameworks", []) or []
        frameworks = ", ".join(self._esc(str(item)) for item in target_frameworks[:5]) or "No disponible"
        return f"""
<section class="panel">
  <div class="panel__header">
    <div>
      <h2>Resumen ejecutivo</h2>
      <p>Visión rápida del alcance, el riesgo y la reducción de falsos positivos.</p>
    </div>
  </div>
  <div class="stats-grid">
    <div class="stat"><span>Vulnerabilidades</span><strong>{total_vulns}</strong></div>
    <div class="stat"><span>Archivos</span><strong>{self._esc(str(project.get('files_analyzed', 0)))}</strong></div>
    <div class="stat"><span>Métodos</span><strong>{self._esc(str(project.get('methods_analyzed', 0)))}</strong></div>
    <div class="stat"><span>Clases</span><strong>{self._esc(str(project.get('classes_analyzed', 0)))}</strong></div>
    <div class="stat"><span>FP removidos</span><strong>{self._esc(str(fp_info.get('total_removed', 0)))}</strong><small>{float(fp_info.get('reduction_percentage', 0.0)):.1f}%</small></div>
    <div class="stat"><span>Frameworks</span><strong>{frameworks}</strong></div>
  </div>
  <div class="severity-summary">{''.join(f'<div class="sev-line"><span>{name}</span><strong>{count}</strong></div>' for name, count in sev.items())}</div>
</section>
"""

    def _filters(self) -> str:
        return """
<section class="panel panel--filters">
  <div class="panel__header">
    <div>
      <h2>Findings</h2>
      <p>Filtra por severidad o busca texto dentro del reporte.</p>
    </div>
  </div>
  <div class="filter-bar">
    <input id="finding-search" type="search" placeholder="Buscar por archivo, tipo, CWE, método o texto...">
    <div class="filter-buttons">
      <button class="filter-btn is-active" data-filter="ALL">All</button>
      <button class="filter-btn" data-filter="CRITICAL">Critical</button>
      <button class="filter-btn" data-filter="HIGH">High</button>
      <button class="filter-btn" data-filter="MEDIUM">Medium</button>
      <button class="filter-btn" data-filter="LOW">Low</button>
      <button class="filter-btn" data-filter="INFO">Info</button>
    </div>
  </div>
</section>
"""

    def _findings(self, vulns: list[dict[str, Any]], hidden_count: int) -> str:
        if not vulns:
            return "<section class=\"panel\"><p class=\"empty\">No se detectaron vulnerabilidades.</p></section>"

        cards = [self._finding_card(vuln, index + 1) for index, vuln in enumerate(vulns)]
        hidden_html = f'<p class="hidden-note">Se muestran {len(vulns)} findings de un total de {len(vulns) + hidden_count}.</p>' if hidden_count else ""
        return f"""
<section class="findings-wrap">
  {hidden_html}
  <div class="findings-grid">
    {''.join(cards)}
  </div>
</section>
"""

    def _finding_card(self, vuln: dict[str, Any], index: int) -> str:
        severity = _text(vuln.get("severity", "INFO")).upper()
        kind = _text(vuln.get("vulnerability_kind", "UNKNOWN"))
        confidence = _text(vuln.get("confidence", "UNKNOWN"))
        source = _text(vuln.get("finding_source", "unknown"))
        vuln_id = _text(vuln.get("vuln_id", ""))
        cwe = _text(vuln.get("cwe", ""))
        cwe_name = _text(vuln.get("cwe_name", ""))
        location = vuln.get("location", {}) or {}
        file_path = _text(location.get("file", ""))
        file_short = _basename(file_path) or file_path or "unknown"
        source_line = int(location.get("source_line", 0) or 0)
        sink_line = int(location.get("sink_line", 0) or 0)
        method = _text(location.get("method", ""))
        cls = _text(location.get("class", ""))
        framework = _text(location.get("framework", ""))
        description = _text(vuln.get("description", ""))
        remediation = _text(vuln.get("remediation", ""))
        title = _text(vuln.get("title", kind))
        source_label = _text(vuln.get("taint_flow", {}).get("source_label", ""))
        sink_label = _text(vuln.get("taint_flow", {}).get("sink_label", ""))
        path_summary = vuln.get("taint_flow", {}).get("path_summary", []) or []
        references = vuln.get("references", []) or []
        context = vuln.get("context", {}) or {}
        code_snippet = _text(vuln.get("code_snippet", ""))
        code_context = vuln.get("code_context", []) or []

        context_bits = []
        if context.get("is_entry_point"):
            context_bits.append("Endpoint público")
        if context.get("is_in_loop"):
            context_bits.append("Sink en loop")
        if context.get("has_partial_sanitizer"):
            context_bits.append("Sanitizador parcial")

        path_html = ""
        if self.config.show_path and path_summary:
            path_html = (
                "<div class=\"finding-section\"><h4>Path de taint</h4><ol>"
                + "".join(f"<li>{self._esc(step)}</li>" for step in path_summary[: self.config.max_path_steps])
                + "</ol></div>"
            )

        code_html = ""
        if self.config.show_code:
            code_html = self._code_context_html(code_context, code_snippet)

        refs_html = ""
        if references:
            refs_html = "<div class=\"finding-section\"><h4>Referencias</h4><ul class=\"ref-list\">"
            refs_html += "".join(
                f'<li><a href="{self._esc(str(ref))}" target="_blank" rel="noreferrer noopener">{self._esc(str(ref))}</a></li>'
                for ref in references[:5]
            )
            refs_html += "</ul></div>"

        context_html = ""
        if context_bits:
            context_html = (
                "<div class=\"finding-section\"><h4>Contexto</h4><div class=\"chip-row\">"
                + "".join(f'<span class="chip chip-soft">{self._esc(bit)}</span>' for bit in context_bits)
                + "</div></div>"
            )

        return f"""
<article class="finding-card severity-{severity.lower()}" data-severity="{self._esc(severity)}" data-kind="{self._esc(kind)}" data-file="{self._esc(file_short)}" data-source="{self._esc(source)}">
  <header class="finding-card__header">
    <div>
      <span class="finding-index">#{index}</span>
      <h3>{self._esc(title)}</h3>
      <p>{self._esc(kind)} · {self._esc(cwe)} {self._esc(cwe_name)}</p>
    </div>
    <div class="finding-badges">
      <span class="badge badge-{severity.lower()}">{self._esc(severity)}</span>
      <span class="badge">{self._esc(confidence)}</span>
      <span class="badge">{self._esc(source)}</span>
    </div>
  </header>
  <div class="finding-meta">
    <span><strong>Archivo:</strong> {self._esc(file_short)}</span>
    <span><strong>Líneas:</strong> L{source_line} → L{sink_line}</span>
    <span><strong>Método:</strong> {self._esc(cls)}.{self._esc(method)}()</span>
    <span><strong>Framework:</strong> {self._esc(framework)}</span>
    <span><strong>Vuln ID:</strong> {self._esc(vuln_id[:16])}</span>
  </div>
  <div class="finding-section">
    <h4>Descripción</h4>
    <p>{self._esc(description) if description else 'Sin descripción disponible.'}</p>
  </div>
  {path_html}
  {context_html}
  {code_html}
  <div class="finding-section finding-section--grid">
    <div>
      <h4>Fuente</h4>
      <p>{self._esc(source_label) if source_label else 'No especificada'}</p>
    </div>
    <div>
      <h4>Sink</h4>
      <p>{self._esc(sink_label) if sink_label else 'No especificado'}</p>
    </div>
  </div>
  <div class="finding-section">
    <h4>Remediación</h4>
    <p>{self._esc(remediation) if remediation else 'Sin recomendación disponible.'}</p>
  </div>
  {refs_html}
</article>
"""

    def _code_context_html(self, code_context: list[dict[str, Any]], code_snippet: str) -> str:
        """Renderiza un bloque contextual con líneas numeradas."""
        if code_context:
            rows = []
            for item in code_context[: self.config.max_code_lines]:
                line_no = int(item.get("line", 0) or 0)
                text = self._esc(str(item.get("text", "")))
                is_sink = bool(item.get("is_sink", False))
                sink_class = " finding-code__line--sink" if is_sink else ""
                line_label = f"L{line_no}" if line_no > 0 else "..."
                rows.append(
                    f'<div class="finding-code__line{sink_class}"><span class="finding-code__ln">{line_label}</span><span class="finding-code__text">{text}</span></div>'
                )
            return (
                '<div class="finding-section"><h4>Contexto de código</h4>'
                '<div class="finding-code">'
                + "".join(rows)
                + "</div></div>"
            )

        if code_snippet:
            code_lines = code_snippet.splitlines()[: self.config.max_code_lines]
            return (
                '<div class="finding-section"><h4>Code snippet</h4><pre><code>'
                + self._esc("\n".join(code_lines))
                + "</code></pre></div>"
            )

        return ""

    def _metrics(self, metrics: dict[str, Any]) -> str:
        timing = metrics.get("timing", {}) if isinstance(metrics, dict) else {}
        total_sec = timing.get("total_sec", metrics.get("analysis_duration_sec", 0.0)) if isinstance(metrics, dict) else 0.0
        metric_items = [
            ("Archivos", metrics.get("files_analyzed", 0)),
            ("Métodos", metrics.get("methods_analyzed", 0)),
            ("Nodos", metrics.get("nodes_analyzed", 0)),
            ("Sources", metrics.get("sources_found", 0)),
            ("Sinks", metrics.get("sinks_found", 0)),
            ("Sanitizers", metrics.get("sanitizers_found", 0)),
            ("Taint paths", metrics.get("taint_paths_analyzed", 0)),
            ("Reglas", metrics.get("rules_loaded", 0)),
        ]
        cards = "".join(
            f'<div class="metric-box"><span>{self._esc(label)}</span><strong>{self._esc(str(value))}</strong></div>'
            for label, value in metric_items
        )
        return f"""
<section class="panel">
  <div class="panel__header">
    <div>
      <h2>Métricas del análisis</h2>
      <p>Indicadores de ejecución y cobertura del pipeline.</p>
    </div>
  </div>
  <div class="metric-grid">{cards}</div>
  <div class="timing-line">Duración total: {self._esc(f'{total_sec:.2f}')} s</div>
</section>
"""

    def _context(
        self,
        summary: dict[str, Any],
        remediation_summary: dict[str, Any],
        project: dict[str, Any],
        framework_info: dict[str, Any],
    ) -> str:
        top_files = summary.get("top_affected_files", []) or []
        top_types = summary.get("top_vulnerability_types", []) or []
        target_frameworks = project.get("target_frameworks", []) or []
        frameworks = ", ".join(self._esc(str(item)) for item in target_frameworks[:5]) or "No disponible"

        top_files_html = "".join(
            f"<li><span>{self._esc(str(item.get('file', '?')))}</span><strong>{self._esc(str(item.get('count', 0)))}</strong></li>"
            for item in top_files[:5]
        ) or '<li><span>No hay datos</span><strong>-</strong></li>'
        top_types_visible = top_types[:8] if len(top_types) > 8 else top_types
        top_types_html = "".join(
            f"<li><span>{self._esc(str(item.get('kind', '?')))}</span><strong>{self._esc(str(item.get('count', 0)))}</strong></li>"
            for item in top_types_visible
        ) or '<li><span>No hay datos</span><strong>-</strong></li>'

        remediation_blocks = []
        for kind, data in list(remediation_summary.items())[:8]:
            remediation_blocks.append(
                f"<div class=\"remediation-item\"><strong>{self._esc(kind)}</strong><p>{self._esc(str(data.get('primary_remediation', '')))}</p><small>{self._esc(str(data.get('count', 0)))} findings</small></div>"
            )

        detected_frameworks = framework_info.get("detected_frameworks", []) or []
        detected_html = ", ".join(self._esc(str(item)) for item in detected_frameworks[:5]) or "No disponible"

        return f"""
<section class="panel panel--wide">
  <div class="panel__header">
    <div>
      <h2>Contexto y remediación</h2>
      <p>Arquitectura observada, archivos más afectados y sugerencias base.</p>
    </div>
  </div>
  <div class="two-col">
    <div class="mini-panel">
      <h3>Top archivos</h3>
      <ul class="compact-list">{top_files_html}</ul>
    </div>
    <div class="mini-panel">
      <h3>Top tipos</h3>
      <ul class="compact-list">{top_types_html}</ul>
    </div>
  </div>
  <div class="mini-panel">
    <h3>Frameworks detectados</h3>
    <p>{frameworks}</p>
    <p>{detected_html}</p>
  </div>
  <div class="remediation-grid">
    {''.join(remediation_blocks) or '<p class="empty">No hay remediaciones agregadas.</p>'}
  </div>
</section>
"""

    def _script(self) -> str:
        return """
<script>
(function () {
  const buttons = document.querySelectorAll('.filter-btn');
  const search = document.getElementById('finding-search');
  const cards = Array.from(document.querySelectorAll('.finding-card'));
  const themeToggle = document.getElementById('theme-toggle');
  const printButton = document.getElementById('print-report');
  let activeSeverity = 'ALL';
  const themeStorageKey = 'csharp-sast-theme';

  function applyTheme(theme) {
    const nextTheme = theme === 'light' ? 'light' : 'dark';
    document.body.dataset.theme = nextTheme;
    if (themeToggle) {
      themeToggle.textContent = 'Toggle theme';
    }
    try {
      window.localStorage.setItem(themeStorageKey, nextTheme);
    } catch (error) {
      // Ignore storage failures.
    }
  }

  function applyFilters() {
    const query = (search.value || '').trim().toLowerCase();
    cards.forEach((card) => {
      const severity = (card.dataset.severity || 'INFO').toUpperCase();
      const text = card.textContent.toLowerCase();
      const matchesSeverity = activeSeverity === 'ALL' || severity === activeSeverity;
      const matchesQuery = !query || text.includes(query);
      card.style.display = matchesSeverity && matchesQuery ? '' : 'none';
    });
  }

  try {
    const storedTheme = window.localStorage.getItem(themeStorageKey);
    if (storedTheme) {
      applyTheme(storedTheme);
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      applyTheme('light');
    } else {
      applyTheme('dark');
    }
  } catch (error) {
    applyTheme('dark');
  }

  buttons.forEach((button) => {
    button.addEventListener('click', () => {
      buttons.forEach((btn) => btn.classList.remove('is-active'));
      button.classList.add('is-active');
      activeSeverity = button.dataset.filter || 'ALL';
      applyFilters();
    });
  });

  if (search) {
    search.addEventListener('input', applyFilters);
  }

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const currentTheme = document.body.dataset.theme === 'light' ? 'light' : 'dark';
      applyTheme(currentTheme === 'dark' ? 'light' : 'dark');
    });
  }

  if (printButton) {
    printButton.addEventListener('click', () => window.print());
  }
})();
</script>
"""

    def _code_context_html(self, code_context: list[dict[str, Any]], code_snippet: str) -> str:
        """
        Renderiza un bloque de contexto con líneas numeradas.

        Prioriza code_context ya estructurado y cae al snippet plano si hace falta.
        """
        if code_context:
            rows = []
            for item in code_context[: self.config.max_code_lines]:
                line_no = int(item.get("line", 0) or 0)
                text = self._esc(str(item.get("text", "")))
                is_sink = bool(item.get("is_sink", False))
                marker = " finding-code__line--sink" if is_sink else ""
                label = f"L{line_no}" if line_no > 0 else "..."
                rows.append(
                    f'<div class="finding-code__line{marker}"><span class="finding-code__ln">{label}</span><span class="finding-code__text">{text}</span></div>'
                )
            return (
                '<div class="finding-section"><h4>Contexto de código</h4>'
                '<div class="finding-code">'
                + "".join(rows)
                + "</div></div>"
            )

        if code_snippet:
            code_lines = code_snippet.splitlines()[: self.config.max_code_lines]
            return (
                '<div class="finding-section"><h4>Code snippet</h4><pre><code>'
                + self._esc("\n".join(code_lines))
                + "</code></pre></div>"
            )

        return ""

    def _styles(self) -> str:
        return """
:root {
  color-scheme: dark;
  --bg: #07111d;
  --bg-soft: #0d1728;
  --panel: rgba(14, 22, 38, 0.92);
  --panel-strong: rgba(17, 27, 46, 0.98);
  --line: rgba(159, 176, 204, 0.16);
  --line-strong: rgba(159, 176, 204, 0.26);
  --text: #edf4ff;
  --muted: #a8b7cd;
  --accent: #8be0ff;
  --critical: #ef4444;
  --high: #f97316;
  --medium: #f59e0b;
  --low: #22c55e;
  --info: #38bdf8;
}
body[data-theme="light"] {
  color-scheme: light;
  --bg: #eef4fb;
  --bg-soft: #ffffff;
  --panel: rgba(255, 255, 255, 0.92);
  --panel-strong: rgba(255, 255, 255, 0.98);
  --line: rgba(15, 23, 42, 0.10);
  --line-strong: rgba(15, 23, 42, 0.16);
  --text: #0f172a;
  --muted: #516176;
  --accent: #0369a1;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  font-family: "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
  background:
    radial-gradient(circle at top left, rgba(139, 224, 255, 0.16), transparent 30%),
    radial-gradient(circle at top right, rgba(249, 115, 22, 0.10), transparent 28%),
    linear-gradient(180deg, var(--bg) 0%, #0b1627 42%, #09111d 100%);
  color: var(--text);
  line-height: 1.5;
}
body[data-theme="light"] {
  background:
    radial-gradient(circle at top left, rgba(14, 165, 233, 0.10), transparent 30%),
    radial-gradient(circle at top right, rgba(251, 146, 60, 0.08), transparent 28%),
    linear-gradient(180deg, #f9fbff 0%, #edf3fb 42%, #f6f8fc 100%);
}
a { color: var(--accent); }
.shell {
  width: min(1360px, calc(100% - 32px));
  margin: 28px auto 64px;
  display: grid;
  gap: 18px;
}
.hero, .panel, .finding-card {
  border: 1px solid var(--line);
  background: linear-gradient(180deg, var(--panel-strong), var(--panel));
  border-radius: 24px;
  box-shadow:
    0 18px 42px rgba(0, 0, 0, 0.22),
    inset 0 1px 0 rgba(255, 255, 255, 0.03);
  backdrop-filter: blur(16px);
}
.hero { padding: 30px; position: relative; overflow: hidden; }
.hero::after {
  content: "";
  position: absolute;
  inset: auto -10% -35% auto;
  width: 320px;
  height: 320px;
  background: radial-gradient(circle, rgba(139, 224, 255, 0.16), transparent 60%);
  pointer-events: none;
}
.hero__copy h1 { margin: 8px 0 10px; font-size: clamp(2rem, 4vw, 3.6rem); line-height: 1.02; letter-spacing: -0.03em; }
.hero__subtitle, .panel__header p, .timing-line, .hero__footer, .finding-card__header p, .finding-meta, .mini-panel p, .compact-list, .remediation-item p { color: var(--muted); }
.hero__footer { margin-top: 18px; display: flex; flex-wrap: wrap; gap: 14px; font-size: 0.92rem; }
.eyebrow { text-transform: uppercase; letter-spacing: 0.18em; font-size: 0.76rem; color: var(--accent); }
.chip-row, .filter-buttons, .severity-summary, .finding-badges, .finding-section--grid, .hero__grid, .stats-grid, .metric-grid, .two-col, .remediation-grid { display: flex; flex-wrap: wrap; gap: 12px; }
.chip, .badge, .filter-btn, .severity-card, .risk-card, .metric-card, .stat, .metric-box, .mini-panel, .remediation-item { border: 1px solid var(--line); background: rgba(255, 255, 255, 0.03); border-radius: 16px; }
.chip { padding: 8px 12px; font-size: 0.88rem; color: var(--text); }
.chip-soft { background: rgba(139, 224, 255, 0.08); }
.hero__grid { margin-top: 20px; }
.risk-card, .metric-card { flex: 1 1 220px; padding: 18px; background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02)); }
.risk-card span, .metric-card span, .stat span, .metric-box span { display: block; color: var(--muted); font-size: 0.88rem; }
.risk-card strong, .metric-card strong, .stat strong, .metric-box strong { display: block; font-size: 2rem; line-height: 1.1; margin-top: 8px; }
.risk-clean { color: #86efac; }
.risk-low { color: #86efac; }
.risk-medium { color: #fde68a; }
.risk-high { color: #fdba74; }
.risk-critical { color: #fca5a5; }
.severity-card { padding: 14px 16px; backdrop-filter: blur(8px); }
.severity-card span { display: block; font-size: 0.78rem; letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
.severity-card strong { display: block; font-size: 1.55rem; line-height: 1; }
.severity-critical strong { color: #fecaca; }
.severity-high strong { color: #fed7aa; }
.severity-medium strong { color: #fde68a; }
.severity-low strong { color: #bbf7d0; }
.severity-info strong { color: #bae6fd; }
.severity-strip { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-top: 16px; }
.panel { padding: 22px; }
.panel__header { display: flex; justify-content: space-between; gap: 14px; align-items: end; margin-bottom: 18px; }
.panel__header h2 { margin: 0; font-size: 1.38rem; letter-spacing: -0.02em; }
.top-controls { display: flex; justify-content: flex-end; margin: 0 0 16px; gap: 10px; flex-wrap: wrap; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
.stat, .metric-box { padding: 16px; background: rgba(255,255,255,0.03); }
.stat small { display: block; margin-top: 6px; color: var(--accent); }
.severity-summary { margin-top: 16px; display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); }
.sev-line { display: flex; justify-content: space-between; padding: 12px 14px; border: 1px solid var(--line); border-radius: 14px; background: rgba(255,255,255,0.02); }
.filter-bar { display: grid; gap: 14px; }
#finding-search { width: 100%; border: 1px solid var(--line); border-radius: 14px; padding: 14px 16px; background: rgba(255,255,255,0.04); color: var(--text); font-size: 1rem; outline: none; transition: border-color .18s ease, box-shadow .18s ease, transform .18s ease; }
#finding-search:focus { border-color: rgba(139, 224, 255, 0.55); box-shadow: 0 0 0 4px rgba(139, 224, 255, 0.10); }
.filter-btn { padding: 10px 14px; color: var(--text); cursor: pointer; font: inherit; transition: transform .15s ease, background .15s ease, border-color .15s ease, box-shadow .15s ease; }
.filter-btn:hover, .control-btn:hover { transform: translateY(-1px); }
.filter-btn.is-active { background: rgba(139, 224, 255, 0.16); border-color: rgba(139, 224, 255, 0.42); box-shadow: 0 10px 24px rgba(0, 0, 0, 0.12); }
.control-btn {
  border: 1px solid var(--line);
  border-radius: 14px;
  background: linear-gradient(180deg, rgba(56, 189, 248, 0.18), rgba(56, 189, 248, 0.08));
  color: var(--text);
  padding: 12px 16px;
  cursor: pointer;
  font: inherit;
  font-weight: 700;
  letter-spacing: 0.01em;
  transition: transform .12s ease, border-color .12s ease, background .12s ease;
}
.control-btn:hover { transform: translateY(-1px); border-color: rgba(56, 189, 248, 0.35); }
.control-btn--ghost { background: transparent; }
.findings-wrap { display: grid; gap: 12px; }
.hidden-note { color: var(--muted); margin: 0; }
.findings-grid { display: grid; gap: 16px; }
.finding-card { padding: 20px; transition: transform .18s ease, border-color .18s ease, box-shadow .18s ease; }
.finding-card:hover { transform: translateY(-2px); border-color: var(--line-strong); box-shadow: 0 22px 40px rgba(0, 0, 0, 0.20); }
.finding-card__header { display: flex; justify-content: space-between; gap: 16px; align-items: start; }
.finding-card__header h3 { margin: 4px 0 6px; font-size: 1.15rem; }
.finding-index { display: inline-flex; padding: 4px 9px; border-radius: 999px; background: rgba(139, 224, 255, 0.15); color: var(--accent); font-size: 0.82rem; }
.badge { display: inline-flex; align-items: center; padding: 7px 10px; font-size: 0.82rem; }
.badge-critical { background: rgba(239, 68, 68, 0.15); color: #fecaca; }
.badge-high { background: rgba(249, 115, 22, 0.15); color: #fed7aa; }
.badge-medium { background: rgba(245, 158, 11, 0.15); color: #fde68a; }
.badge-low { background: rgba(34, 197, 94, 0.15); color: #bbf7d0; }
.badge-info { background: rgba(56, 189, 248, 0.15); color: #bae6fd; }
.finding-meta { margin: 16px 0 12px; display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px 14px; font-size: 0.93rem; }
.finding-section { margin-top: 14px; }
.finding-section h4, .mini-panel h3 { margin: 0 0 10px; font-size: 0.96rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--accent); }
.finding-section p { margin: 0; }
.finding-section ol, .ref-list, .compact-list { margin: 0; padding-left: 20px; }
pre { margin: 0; padding: 14px; overflow-x: auto; border-radius: 14px; background: rgba(10, 16, 32, 0.88); border: 1px solid var(--line); }
body[data-theme="light"] pre { background: #f7fafc; }
code { color: #d1e9ff; font-family: Consolas, "SFMono-Regular", monospace; }
body[data-theme="light"] code { color: #0f172a; }
.finding-code { border: 1px solid var(--line); border-radius: 14px; overflow: hidden; background: rgba(10, 16, 32, 0.88); }
body[data-theme="light"] .finding-code { background: #f7fafc; }
.finding-code__line { display: grid; grid-template-columns: 72px 1fr; gap: 12px; padding: 8px 14px; border-top: 1px solid rgba(255,255,255,0.04); font-family: Consolas, "SFMono-Regular", monospace; font-size: 0.92rem; line-height: 1.45; }
body[data-theme="light"] .finding-code__line { border-top-color: rgba(15,23,42,0.06); }
.finding-code__line:first-child { border-top: 0; }
.finding-code__line--sink { background: rgba(139, 224, 255, 0.12); }
.finding-code__ln { color: var(--muted); user-select: none; }
.finding-code__text { white-space: pre-wrap; word-break: break-word; color: var(--text); }
.finding-section--grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
.metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); }
.timing-line { margin-top: 14px; }
.two-col { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }
.mini-panel { padding: 16px; background: rgba(255,255,255,0.02); }
.compact-list { list-style: none; padding-left: 0; display: grid; gap: 8px; }
.compact-list li { display: flex; justify-content: space-between; gap: 10px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 8px; }
.remediation-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); margin-top: 14px; }
.remediation-item { padding: 14px; background: rgba(255,255,255,0.03); }
.empty { color: var(--muted); text-align: center; padding: 16px; }
@media (max-width: 720px) {
  .shell { width: min(100% - 20px, 1280px); margin-top: 10px; }
  .hero, .panel, .finding-card { border-radius: 18px; }
  .finding-card__header, .panel__header { flex-direction: column; align-items: start; }
  .hero { padding: 22px; }
  .top-controls { width: 100%; }
  .control-btn, .filter-btn { width: 100%; justify-content: center; }
  .top-controls { flex-direction: column; align-items: stretch; }
  .severity-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media print {
  :root, body, body[data-theme="light"], body[data-theme="dark"] {
    color-scheme: light;
    --bg: #ffffff;
    --bg-soft: #ffffff;
    --panel: #ffffff;
    --panel-strong: #ffffff;
    --line: rgba(15, 23, 42, 0.12);
    --line-strong: rgba(15, 23, 42, 0.18);
    --text: #0f172a;
    --muted: #516176;
    --accent: #0369a1;
  }
  body {
    background: #ffffff !important;
    color: #0f172a !important;
  }
  .shell {
    width: 100%;
    margin: 0;
    gap: 14px;
  }
  .top-controls,
  .filter-bar,
  .hidden-note {
    display: none !important;
  }
  .hero, .panel, .finding-card, .mini-panel, .metric-box, .stat, .severity-card, .risk-card, .metric-card {
    box-shadow: none !important;
    background: #ffffff !important;
  }
  a {
    color: #0f172a !important;
    text-decoration: underline;
  }
  .finding-card, .mini-panel, .metric-box, .stat, .severity-card, .risk-card, .metric-card {
    break-inside: avoid;
    page-break-inside: avoid;
  }
  .severity-strip {
    grid-template-columns: repeat(5, minmax(0, 1fr));
  }
}
"""

    @staticmethod
    def _esc(value: Any) -> str:
        return html_lib.escape(_text(value))


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_severity_counts(raw: dict[str, Any]) -> dict[str, int]:
    normalized = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for key, value in raw.items():
        upper = str(key).upper()
        if upper in normalized:
            normalized[upper] = int(value or 0)
    return normalized


