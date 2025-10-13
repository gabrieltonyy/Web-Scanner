from __future__ import annotations

from typing import Literal, Optional

EngineName = Literal["weasyprint", "wkhtmltopdf", "reportlab"]

# Default report engine for HTML → PDF conversion
DEFAULT_ENGINE: EngineName = "weasyprint"


class PDFRenderer:
    """Render HTML to PDF via a configured engine.

    Engines supported:
      - weasyprint (default): pure-Python, CSS-aware. Requires system libs.
      - wkhtmltopdf: external binary. Requires executable in PATH.
      - reportlab: direct PDF generation (no HTML); not implemented here.
    """

    def __init__(self, engine: Optional[EngineName] = None):
        self.engine: EngineName = engine or DEFAULT_ENGINE

    def render(self, html: str, output_path: str) -> None:
        if self.engine == "weasyprint":
            self._render_weasyprint(html, output_path)
        elif self.engine == "wkhtmltopdf":
            self._render_wkhtmltopdf(html, output_path)
        elif self.engine == "reportlab":
            raise NotImplementedError("ReportLab direct rendering not implemented in this module.")
        else:
            raise ValueError(f"Unknown PDF engine: {self.engine}")

    def _render_weasyprint(self, html: str, output_path: str) -> None:
        # Deferred import to avoid hard dependency at import time
        try:
            from weasyprint import HTML  # type: ignore
        except Exception as e:  # pragma: no cover - environment dependent
            raise RuntimeError("WeasyPrint is not installed or misconfigured") from e

        HTML(string=html).write_pdf(output_path)

    def _render_wkhtmltopdf(self, html: str, output_path: str) -> None:
        # Render via wkhtmltopdf (requires the binary installed). We write
        # the HTML to a temp file to avoid shell quoting issues.
        import os
        import subprocess
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as tmp:
            tmp.write(html)
            tmp_path = tmp.name

        try:
            cmd = ["wkhtmltopdf", tmp_path, output_path]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if proc.returncode != 0:
                raise RuntimeError(
                    f"wkhtmltopdf failed with code {proc.returncode}: {proc.stderr.decode(errors='ignore')}"
                )
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

