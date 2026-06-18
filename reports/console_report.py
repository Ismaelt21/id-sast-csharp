# =============================================================================
#  csharp-sast / reports / console_report.py
# =============================================================================
#
#  REPORTE DE CONSOLA PARA CSHARP-SAST
#  ──────────────────────────────────────
#  Genera la salida formateada en terminal durante y al final del análisis.
#  Es el reporte más inmediato — el desarrollador lo ve en tiempo real.
#
#  CARACTERÍSTICAS:
#    • Colores ANSI con detección automática de soporte (TTY check)
#    • Banner de inicio y resumen ejecutivo de cierre
#    • Tabla de vulnerabilidades ordenada por severidad
#    • Detalle expandible de cada vulnerabilidad (modo verbose)
#    • Barra de progreso durante el análisis
#    • Resultado de CI/CD gate (PASS / FAIL con exit code)
#    • Modo quiet (solo resumen) y verbose (detalle completo)
#    • Compatible con piping y redirección a archivo
#
#  NIVELES DE SALIDA:
#    quiet   → Solo el resumen final (PASS/FAIL + conteo)
#    normal  → Banner + tabla de vulnerabilidades + resumen
#    verbose → Normal + detalle completo de cada vuln + taint path
#
#  COLORES ANSI:
#    Solo se emiten si stdout es un TTY real.
#    Con --no-color o CI=true → salida sin colores.
#
#  USO:
#    report = ConsoleReport()
#    report.print_banner(project_name, profile)
#    report.print_progress(file, files_done, files_total)
#    report.print_results(vulnerabilities, model, profile, metrics)
#    # → retorna exit_code (0=clean, 1=vulns found, 2=error)
#
# =============================================================================

from __future__ import annotations

import os
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from core.parsers.ast_importer import ParsedCSharpModel
from core.parsers.framework_detector import FrameworkProfile
from reports.json_report import ReportMetrics


# ─────────────────────────────────────────────────────────────────────────────
#  ANSI COLOR CODES
# ─────────────────────────────────────────────────────────────────────────────

def _supports_color() -> bool:
    """True si el terminal soporta colores ANSI."""
    if os.getenv("NO_COLOR") or os.getenv("CI"):
        return False
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty()


class _C:
    """Códigos ANSI. Se vacían si no hay soporte de color."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[31m"
    ORANGE  = "\033[33m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[32m"
    BLUE    = "\033[34m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    BRED    = "\033[41m"
    BGREEN  = "\033[42m"
    BG_DARK = "\033[40m"

    @classmethod
    def disable(cls) -> None:
        """Vacía todos los códigos ANSI."""
        for attr in list(vars(cls)):
            if not attr.startswith("_") and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, "")


# ─────────────────────────────────────────────────────────────────────────────
#  ESTILOS POR SEVERIDAD
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_STYLE: dict[str, dict[str, str]] = {
    "CRITICAL": {"color": _C.RED,    "emoji": "🔴", "label": "CRITICAL", "bg": _C.BRED},
    "HIGH":     {"color": _C.ORANGE, "emoji": "🟠", "label": "HIGH    ", "bg": _C.ORANGE},
    "MEDIUM":   {"color": _C.YELLOW, "emoji": "🟡", "label": "MEDIUM  ", "bg": _C.YELLOW},
    "LOW":      {"color": _C.GREEN,  "emoji": "🟢", "label": "LOW     ", "bg": _C.GREEN},
    "INFO":     {"color": _C.BLUE,   "emoji": "🔵", "label": "INFO    ", "bg": _C.BLUE},
}

_FINDING_SOURCE_ICON: dict[str, str] = {
    "taint_analysis":     "🔍",
    "pattern_match":      "🎯",
    "framework_analysis": "🏗️",
    "ai_detected":        "🤖",
}

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTES DE FORMATO
# ─────────────────────────────────────────────────────────────────────────────

_TERM_WIDTH       = 100
_SEPARATOR        = "─" * _TERM_WIDTH
_DOUBLE_SEP       = "═" * _TERM_WIDTH
_EXIT_CODE_CLEAN  = 0
_EXIT_CODE_VULNS  = 1
_EXIT_CODE_ERROR  = 2


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURACIÓN DEL REPORTE
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ConsoleReportConfig:
    """Configuración de comportamiento del reporte de consola."""
    verbose:      bool = False    # Mostrar detalle completo de cada vuln
    quiet:        bool = False    # Solo mostrar resumen final
    colors:       bool = True     # Usar colores ANSI (auto-detectado si None)
    max_vulns:    int  = 50       # Máximo de vulns a mostrar en tabla
    show_code:    bool = True     # Mostrar code snippet en modo verbose
    show_path:    bool = True     # Mostrar taint path en modo verbose
    fail_on:      str  = "HIGH"   # Severidad mínima para exit code 1


# ─────────────────────────────────────────────────────────────────────────────
#  REPORTE DE CONSOLA PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class ConsoleReport:
    """
    Generador de reporte de consola para csharp-sast.

    Maneja la salida formateada en terminal durante y al final del análisis.
    Soporta colores ANSI, modo verbose/quiet y detección automática de TTY.

    Uso:
        config = ConsoleReportConfig(verbose=True, fail_on="HIGH")
        report = ConsoleReport(config)

        report.print_banner("MyProject", profile)

        # Durante el análisis:
        report.print_progress("Controllers/UserController.cs", 3, 42)

        # Al finalizar:
        exit_code = report.print_results(
            vulnerabilities=classified_vulns,
            model=model,
            profile=profile,
            scan_id="uuid-...",
            project_name="MyProject",
            metrics=pipeline_metrics,
            false_positives_removed=5,
        )
        sys.exit(exit_code)
    """

    def __init__(self, config: ConsoleReportConfig | None = None) -> None:
        self.config = config or ConsoleReportConfig()

        # Configurar colores
        if not self.config.colors or not _supports_color():
            _C.disable()

        # Mapa de output: escribir a stdout por defecto
        self._out = sys.stdout

    # ─────────────────────────────────────────────────────────────────────────
    #  BANNER DE INICIO
    # ─────────────────────────────────────────────────────────────────────────

    def print_banner(
        self,
        project_name: str,
        profile:      FrameworkProfile | None = None,
    ) -> None:
        """
        Imprime el banner de inicio del análisis.
        Incluye nombre del proyecto, framework detectado y timestamp.
        """
        if self.config.quiet:
            return

        framework = ""
        if profile:
            fw = getattr(profile, "primary_framework", None)
            framework = fw.value if fw and hasattr(fw, "value") else str(fw or "")

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        self._println()
        self._println(f"{_C.BOLD}{_C.CYAN}{_DOUBLE_SEP}{_C.RESET}")
        self._println(
            f"{_C.BOLD}{_C.CYAN}  🔒 csharp-sast — C# SAST Engine{_C.RESET}"
        )
        self._println(f"{_C.BOLD}{_C.CYAN}{_DOUBLE_SEP}{_C.RESET}")
        self._println(
            f"  {_C.BOLD}Proyecto  :{_C.RESET} {project_name}"
        )
        if framework:
            self._println(
                f"  {_C.BOLD}Framework :{_C.RESET} {framework}"
            )
        self._println(
            f"  {_C.BOLD}Inicio    :{_C.RESET} {now}"
        )
        self._println(f"{_C.DIM}{_SEPARATOR}{_C.RESET}")
        self._println()

    # ─────────────────────────────────────────────────────────────────────────
    #  PROGRESO DURANTE EL ANÁLISIS
    # ─────────────────────────────────────────────────────────────────────────

    def print_progress(
        self,
        current_file: str,
        files_done:   int,
        files_total:  int,
        phase:        str = "Analizando",
    ) -> None:
        """
        Imprime una línea de progreso que se sobreescribe en TTY.

        Args:
            current_file: Archivo siendo procesado actualmente.
            files_done:   Archivos completados.
            files_total:  Total de archivos.
            phase:        Fase del análisis ("Analizando", "Taint", "Gemini").
        """
        if self.config.quiet:
            return

        pct = int(files_done / files_total * 100) if files_total > 0 else 0
        bar_len = 20
        filled = int(bar_len * pct / 100)
        bar = "█" * filled + "░" * (bar_len - filled)

        file_short = _basename(current_file)
        file_short = file_short[:35].ljust(35)

        line = (
            f"\r  {_C.CYAN}[{bar}]{_C.RESET} "
            f"{_C.BOLD}{pct:3d}%{_C.RESET} "
            f"{_C.DIM}{phase}:{_C.RESET} "
            f"{file_short} "
            f"{_C.DIM}({files_done}/{files_total}){_C.RESET}"
        )

        # En TTY: sobreescribir línea. Sin TTY: imprimir normal.
        if sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False:
            print(line, end="", flush=True)
        else:
            if files_done % 10 == 0 or files_done == files_total:
                print(line.replace("\r", ""), flush=True)

    def print_phase(self, phase_name: str, detail: str = "") -> None:
        """
        Imprime el inicio de una nueva fase del análisis.
        Ejemplo: "→ Taint Analysis | propagando desde 12 sources"
        """
        if self.config.quiet:
            return
        detail_str = f" {_C.DIM}| {detail}{_C.RESET}" if detail else ""
        self._println(
            f"\n  {_C.CYAN}→{_C.RESET} "
            f"{_C.BOLD}{phase_name}{_C.RESET}"
            f"{detail_str}"
        )

    def print_phase_done(self, phase_name: str, result: str = "") -> None:
        """Imprime el fin de una fase del análisis."""
        if self.config.quiet:
            return
        result_str = f" {_C.DIM}→ {result}{_C.RESET}" if result else ""
        self._println(
            f"  {_C.GREEN}✓{_C.RESET} "
            f"{_C.BOLD}{phase_name}{_C.RESET}"
            f"{result_str}"
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  RESULTADOS FINALES
    # ─────────────────────────────────────────────────────────────────────────

    def print_results(
        self,
        vulnerabilities:         list[Any],   # list[ClassifiedVulnerability]
        model:                   ParsedCSharpModel,
        profile:                 FrameworkProfile,
        scan_id:                 str | None = None,
        project_name:            str = "csharp-project",
        metrics:                 ReportMetrics | None = None,
        false_positives_removed: int = 0,
    ) -> int:
        """
        Imprime el reporte completo de resultados al final del análisis.

        Imprime:
          1. Línea de separación (cierra la barra de progreso)
          2. Resumen ejecutivo (totales por severidad)
          3. Tabla de vulnerabilidades (ordenada por severidad)
          4. Detalle de cada vuln (si verbose=True)
          5. Métricas del análisis
          6. Resultado CI/CD gate (PASS / FAIL)

        Args:
            vulnerabilities:         list[ClassifiedVulnerability].
            model:                   ParsedCSharpModel del análisis.
            profile:                 FrameworkProfile del proyecto.
            scan_id:                 UUID del análisis.
            project_name:            Nombre del proyecto.
            metrics:                 Métricas del pipeline.
            false_positives_removed: FPs removidos por Gemini.

        Returns:
            exit_code: 0 = limpio, 1 = vulnerabilidades encontradas, 2 = error.
        """
        metrics = metrics or ReportMetrics()

        # Terminar la línea de progreso
        if not self.config.quiet:
            self._println()

        # Serializar vulns (igual que json_report para consistencia)
        vulns = _serialize_vulns(vulnerabilities)

        # Ordenar por severidad
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        vulns_sorted = sorted(
            vulns,
            key=lambda v: (
                sev_order.get(v.get("severity", "INFO"), 99),
                v.get("location", {}).get("file", ""),
                v.get("location", {}).get("sink_line", 0),
            ),
        )

        # Calcular resumen
        summary = _build_summary(vulns)

        if not self.config.quiet:
            self._print_separator()
            self._print_executive_summary(
                summary, project_name, metrics, false_positives_removed
            )
            self._print_separator()

            if vulns_sorted:
                self._print_vuln_table(vulns_sorted)

                if self.config.verbose:
                    self._print_verbose_details(vulns_sorted)

            self._print_metrics(metrics)

        # CI/CD Gate y exit code
        exit_code = self._print_ci_gate(summary, scan_id)

        return exit_code

    def print_error(self, error_message: str, exception: Exception | None = None) -> None:
        """Imprime un error crítico del análisis."""
        self._println()
        self._println(
            f"{_C.BOLD}{_C.RED}❌ ERROR CRÍTICO{_C.RESET}"
        )
        self._println(f"{_C.RED}{error_message}{_C.RESET}")
        if exception and self.config.verbose:
            self._println(f"{_C.DIM}{type(exception).__name__}: {exception}{_C.RESET}")
        self._println()

    def print_warning(self, message: str) -> None:
        """Imprime un warning no crítico."""
        if not self.config.quiet:
            self._println(
                f"  {_C.YELLOW}⚠️  {message}{_C.RESET}"
            )

    def print_info(self, message: str) -> None:
        """Imprime un mensaje informativo."""
        if not self.config.quiet:
            self._println(f"  {_C.CYAN}ℹ️  {message}{_C.RESET}")

    # ─────────────────────────────────────────────────────────────────────────
    #  SECCIONES INTERNAS
    # ─────────────────────────────────────────────────────────────────────────

    def _print_executive_summary(
        self,
        summary:                 dict[str, Any],
        project_name:            str,
        metrics:                 ReportMetrics,
        false_positives_removed: int,
    ) -> None:
        """Imprime el resumen ejecutivo con totales por severidad."""
        total     = summary.get("total", 0)
        by_sev    = summary.get("by_severity", {})
        risk      = summary.get("risk_level", "CLEAN")
        risk_style = _SEVERITY_STYLE.get(risk, _SEVERITY_STYLE["INFO"])

        # Cabecera
        self._println(
            f"\n  {_C.BOLD}RESUMEN DE ANÁLISIS{_C.RESET} "
            f"— {project_name}"
        )
        self._println()

        # Risk level
        self._println(
            f"  Nivel de riesgo : "
            f"{risk_style['color']}{_C.BOLD}"
            f"{risk_style['emoji']} {risk}"
            f"{_C.RESET}"
        )

        # Total + FPs
        self._println(
            f"  Vulnerabilidades: {_C.BOLD}{total}{_C.RESET}"
            + (
                f"  {_C.DIM}(+{false_positives_removed} FP removidos por Gemini){_C.RESET}"
                if false_positives_removed
                else ""
            )
        )

        # Desglose por severidad
        self._println()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = by_sev.get(sev, 0)
            if count == 0 and sev == "INFO":
                continue
            style = _SEVERITY_STYLE[sev]
            bar = "■" * min(count, 40)
            self._println(
                f"  {style['emoji']} "
                f"{style['color']}{_C.BOLD}{sev:<8}{_C.RESET}"
                f"  {_C.BOLD}{count:3d}{_C.RESET}  "
                f"{style['color']}{bar}{_C.RESET}"
            )

        # Duration
        if metrics.analysis_duration_sec:
            self._println()
            self._println(
                f"  {_C.DIM}Duración    : "
                f"{metrics.analysis_duration_sec:.1f}s | "
                f"Archivos: {metrics.files_analyzed} | "
                f"Métodos: {metrics.methods_analyzed}{_C.RESET}"
            )

    def _print_vuln_table(self, vulns: list[dict[str, Any]]) -> None:
        """Imprime la tabla de vulnerabilidades ordenada."""
        max_show = self.config.max_vulns
        shown    = vulns[:max_show]
        hidden   = len(vulns) - max_show if len(vulns) > max_show else 0

        self._println(
            f"\n  {_C.BOLD}VULNERABILIDADES DETECTADAS{_C.RESET} "
            f"({len(vulns)} total)"
        )
        self._println(f"  {_C.DIM}{_SEPARATOR}{_C.RESET}")

        # Cabecera de tabla
        self._println(
            f"  {_C.BOLD}"
            f"{'#':<4} {'SEV':<8} {'TIPO':<28} {'ARCHIVO':<30} {'LÍNEA':<6} {'CONF':<10}"
            f"{_C.RESET}"
        )
        self._println(f"  {_C.DIM}{'─'*90}{_C.RESET}")

        for i, v in enumerate(shown, 1):
            sev    = v.get("severity", "INFO")
            kind   = v.get("vulnerability_kind", "?")[:27]
            loc    = v.get("location", {})
            file_s = loc.get("file_short", loc.get("file", "?"))[-28:].ljust(30)
            line   = str(loc.get("sink_line", loc.get("source_line", 0)))
            conf   = v.get("confidence", "?")
            style  = _SEVERITY_STYLE.get(sev, _SEVERITY_STYLE["INFO"])
            source_icon = _FINDING_SOURCE_ICON.get(
                v.get("finding_source", ""), "•"
            )

            self._println(
                f"  {_C.DIM}{i:<4}{_C.RESET}"
                f"{style['color']}{_C.BOLD}{sev:<8}{_C.RESET} "
                f"{source_icon} "
                f"{_C.BOLD}{kind:<28}{_C.RESET} "
                f"{_C.DIM}{file_s}{_C.RESET}"
                f"{_C.DIM}{line:<6}{_C.RESET}"
                f"{_C.DIM}{conf}{_C.RESET}"
            )

        if hidden:
            self._println(
                f"\n  {_C.DIM}... y {hidden} más. "
                f"Usar --verbose para ver todas o revisar el reporte HTML.{_C.RESET}"
            )

    def _print_verbose_details(self, vulns: list[dict[str, Any]]) -> None:
        """Imprime el detalle completo de cada vulnerabilidad (modo verbose)."""
        max_detail = min(len(vulns), self.config.max_vulns)

        self._println(
            f"\n  {_C.BOLD}DETALLE DE VULNERABILIDADES{_C.RESET}"
        )

        for i, v in enumerate(vulns[:max_detail], 1):
            sev   = v.get("severity", "INFO")
            style = _SEVERITY_STYLE.get(sev, _SEVERITY_STYLE["INFO"])
            loc   = v.get("location", {})
            kind  = v.get("vulnerability_kind", "?")
            vuln_id = v.get("vuln_id", "?")[:12]

            self._println()
            self._println(
                f"  {style['color']}{_C.BOLD}"
                f"┌─ [{i}] {kind} — {sev} [{vuln_id}]"
                f"{_C.RESET}"
            )

            # Ubicación
            self._println(
                f"  {style['color']}│{_C.RESET} "
                f"{_C.BOLD}Archivo :{_C.RESET} "
                f"{loc.get('file', '?')} "
                f"(L{loc.get('source_line', 0)} → "
                f"L{loc.get('sink_line', 0)})"
            )
            self._println(
                f"  {style['color']}│{_C.RESET} "
                f"{_C.BOLD}Método  :{_C.RESET} "
                f"{loc.get('class', '?')}.{loc.get('method', '?')}()"
            )

            # CWE + CVSS
            cwe  = v.get("cwe", "")
            cvss = v.get("cvss", {})
            base = cvss.get("base_score", 0.0) if cvss else 0.0
            if cwe or base:
                self._println(
                    f"  {style['color']}│{_C.RESET} "
                    f"{_C.BOLD}CWE/CVSS:{_C.RESET} "
                    f"{cwe}  CVSS: {base:.1f}"
                )

            # Descripción
            desc = v.get("description", "")
            if desc:
                wrapped = textwrap.fill(
                    desc, width=80,
                    initial_indent="     ",
                    subsequent_indent="     ",
                )
                self._println(
                    f"  {style['color']}│{_C.RESET} "
                    f"{_C.BOLD}Descripción:{_C.RESET}"
                )
                self._println(f"{_C.DIM}{wrapped}{_C.RESET}")

            # Flujo de taint
            taint = v.get("taint_flow", {})
            src   = taint.get("source_label", "")
            sink  = taint.get("sink_label", "")
            path  = taint.get("path_summary", [])
            if src or sink:
                self._println(
                    f"  {style['color']}│{_C.RESET} "
                    f"{_C.BOLD}Taint flow:{_C.RESET} "
                    f"{_C.RED}{src}{_C.RESET} → "
                    f"{_C.RED}{sink}{_C.RESET}"
                )

            if self.config.show_path and path:
                for step in path[:6]:
                    self._println(
                        f"  {style['color']}│{_C.RESET}"
                        f"  {_C.DIM}  → {step}{_C.RESET}"
                    )

            # Contexto adicional
            ctx = v.get("context", {})
            ctx_parts = []
            if ctx.get("is_in_loop"):
                ctx_parts.append("🔁 sink en loop")
            if ctx.get("has_partial_sanitizer"):
                ctx_parts.append("⚠️ sanitizador parcial")
            if ctx.get("is_entry_point"):
                ctx_parts.append("🌐 endpoint público")
            if ctx_parts:
                self._println(
                    f"  {style['color']}│{_C.RESET} "
                    f"{_C.DIM}{' | '.join(ctx_parts)}{_C.RESET}"
                )

            # Code snippet
            snippet = v.get("code_snippet", "")
            if self.config.show_code and snippet:
                self._println(
                    f"  {style['color']}│{_C.RESET} "
                    f"{_C.BOLD}Código:{_C.RESET}"
                )
                for code_line in snippet.split("\n")[:6]:
                    self._println(
                        f"  {style['color']}│{_C.RESET}"
                        f"  {_C.DIM}│  {code_line[:80]}{_C.RESET}"
                    )

            # Remediación
            rem = v.get("remediation", "")
            if rem:
                wrapped_rem = textwrap.fill(
                    rem, width=80,
                    initial_indent="     ",
                    subsequent_indent="     ",
                )
                self._println(
                    f"  {style['color']}│{_C.RESET} "
                    f"{_C.BOLD}Remediación:{_C.RESET}"
                )
                self._println(f"{_C.GREEN}{wrapped_rem}{_C.RESET}")

            self._println(
                f"  {style['color']}└{'─'*60}{_C.RESET}"
            )

    def _print_metrics(self, metrics: ReportMetrics) -> None:
        """Imprime métricas del pipeline de análisis."""
        if not self.config.verbose:
            return

        self._println()
        self._println(
            f"  {_C.BOLD}MÉTRICAS DEL ANÁLISIS{_C.RESET}"
        )
        self._println(f"  {_C.DIM}{_SEPARATOR}{_C.RESET}")

        def _metric(label: str, value: Any, unit: str = "") -> None:
            self._println(
                f"  {_C.DIM}{label:<32}{_C.RESET} "
                f"{_C.BOLD}{value}{_C.RESET}"
                f"{_C.DIM}{unit}{_C.RESET}"
            )

        _metric("Archivos analizados",    metrics.files_analyzed)
        _metric("Métodos analizados",     metrics.methods_analyzed)
        _metric("Nodos del grafo",        metrics.nodes_analyzed)
        _metric("Sources detectadas",     metrics.sources_found)
        _metric("Sinks detectados",       metrics.sinks_found)
        _metric("Sanitizadores",          metrics.sanitizers_found)
        _metric("Caminos de taint",       metrics.taint_paths_analyzed)
        _metric("Reglas cargadas",        metrics.rules_loaded)
        if metrics.gemini_analyzed:
            _metric("Gemini analizados",  metrics.gemini_analyzed)
            _metric("FPs removidos (AI)", metrics.gemini_fp_removed)

        if metrics.analysis_duration_sec:
            self._println()
            _metric("Duración total",     f"{metrics.analysis_duration_sec:.2f}", "s")
            if metrics.roslyn_bridge_ms:
                _metric("Roslyn bridge",  f"{metrics.roslyn_bridge_ms:.0f}", " ms")
            if metrics.taint_analysis_ms:
                _metric("Taint analysis", f"{metrics.taint_analysis_ms:.0f}", " ms")
            if metrics.gemini_analysis_ms:
                _metric("Gemini",         f"{metrics.gemini_analysis_ms:.0f}", " ms")

    def _print_ci_gate(
        self,
        summary: dict[str, Any],
        scan_id: str | None,
    ) -> int:
        """
        Imprime el resultado del CI/CD gate y retorna el exit code.

        Lógica:
          - 0 (CLEAN) : No hay vulnerabilidades con severidad >= fail_on
          - 1 (VULNS) : Hay vulnerabilidades que superan el umbral
          - 2 (ERROR) : Error durante el análisis

        Returns:
            exit_code int.
        """
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        fail_idx  = sev_order.get(self.config.fail_on, 1)
        by_sev    = summary.get("by_severity", {})

        # Contar vulns bloqueantes
        blocking = sum(
            by_sev.get(sev, 0)
            for sev, idx in sev_order.items()
            if idx <= fail_idx
        )

        total = summary.get("total", 0)

        self._println()
        self._println(f"  {_C.DIM}{_DOUBLE_SEP}{_C.RESET}")

        if blocking == 0 and total == 0:
            # CLEAN
            self._println(
                f"  {_C.GREEN}{_C.BOLD}✅ ANÁLISIS LIMPIO{_C.RESET} "
                f"— No se encontraron vulnerabilidades."
            )
            exit_code = _EXIT_CODE_CLEAN

        elif blocking == 0:
            # Hay vulns pero por debajo del umbral
            self._println(
                f"  {_C.YELLOW}{_C.BOLD}⚠️  GATE PASSED{_C.RESET} "
                f"— {total} vuln(s) encontradas, "
                f"ninguna supera el umbral de {self.config.fail_on}."
            )
            exit_code = _EXIT_CODE_VULNS

        else:
            # FALLO — vulns críticas/altas
            self._println(
                f"  {_C.RED}{_C.BOLD}❌ GATE FAILED{_C.RESET} "
                f"— {_C.BOLD}{blocking}{_C.RESET} vuln(s) con severidad "
                f"{_C.RED}{self.config.fail_on}+{_C.RESET} detectadas."
            )
            exit_code = _EXIT_CODE_VULNS

        if scan_id:
            self._println(
                f"  {_C.DIM}scan_id: {scan_id}{_C.RESET}"
            )

        self._println(f"  {_C.DIM}{_DOUBLE_SEP}{_C.RESET}")
        self._println()

        return exit_code

    def _print_separator(self) -> None:
        """Imprime una línea separadora."""
        self._println(f"  {_C.DIM}{_SEPARATOR}{_C.RESET}")

    # ─────────────────────────────────────────────────────────────────────────
    #  OUTPUT HELPER
    # ─────────────────────────────────────────────────────────────────────────

    def _println(self, text: str = "") -> None:
        """Escribe una línea al output configurado."""
        safe_text = text.encode("ascii", errors="replace").decode("ascii")
        print(safe_text, file=self._out)

    def set_output(self, stream: Any) -> None:
        """Redirige el output a un stream diferente (p.ej. archivo)."""
        self._out = stream


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS DE MÓDULO (reutilizados por html_report y sarif_report)
# ─────────────────────────────────────────────────────────────────────────────

def _serialize_vulns(vulnerabilities: list[Any]) -> list[dict[str, Any]]:
    """
    Serializa ClassifiedVulnerabilities a dicts.
    Reutiliza el mismo esquema que json_report._serialize_vulnerability
    para consistencia entre reportes.
    """
    results = []
    for vuln in vulnerabilities:
        def _get(attr: str, default: Any = None) -> Any:
            return getattr(vuln, attr, default)

        def _ev(attr: str, default: str = "") -> str:
            val = getattr(vuln, attr, None)
            if val is None:
                return default
            return val.value if hasattr(val, "value") else str(val)

        import hashlib
        vuln_id = _get("vuln_id") or hashlib.sha256(
            f"{_get('file','')}:{_get('sink_line',0)}:{_ev('vulnerability_kind')}".encode()
        ).hexdigest()[:16]

        cvss = _get("cvss")
        cvss_data = {
            "base_score":    getattr(cvss, "base_score", 0.0) if cvss else 0.0,
            "vector_string": getattr(cvss, "vector_string", "") if cvss else "",
        }

        results.append({
            "vuln_id":             vuln_id,
            "vulnerability_kind":  _ev("vulnerability_kind"),
            "severity":            _ev("severity"),
            "confidence":          _ev("confidence"),
            "finding_source":      _ev("finding_source"),
            "cwe":                 _get("cwe", ""),
            "cwe_name":            _get("cwe_name", ""),
            "cvss":                cvss_data,
            "location": {
                "file":            _get("file", ""),
                "file_short":      _basename(_get("file", "") or ""),
                "source_line":     _get("line", 0),
                "sink_line":       _get("sink_line", 0),
                "method":          _get("method_name", ""),
                "class":           _get("class_name", ""),
                "framework":       _get("framework", ""),
            },
            "title":               _get("title", ""),
            "description":         _get("description", ""),
            "remediation":         _get("remediation", ""),
            "references":          _get("references", []) or [],
            "taint_flow": {
                "source_label":    _get("source_label", ""),
                "sink_label":      _get("sink_label", ""),
                "path_summary":    (_get("taint_path_summary", []) or [])[:10],
            },
            "context": {
                "is_in_loop":           _get("is_in_loop", False),
                "has_partial_sanitizer": _get("has_partial_sanitizer", False),
                "is_entry_point":        _get("is_entry_point", False),
            },
            "code_snippet":        (_get("code_snippet", "") or "")[:300],
        })
    return results


def _build_summary(vulns: list[dict[str, Any]]) -> dict[str, Any]:
    """Calcula el resumen de severidades desde la lista serializada."""
    by_sev: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    }
    for v in vulns:
        sev = v.get("severity", "INFO")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    risk = "CLEAN"
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if by_sev.get(s, 0) > 0:
            risk = s
            break

    return {
        "total":       len(vulns),
        "by_severity": by_sev,
        "risk_level":  risk,
    }


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1]
