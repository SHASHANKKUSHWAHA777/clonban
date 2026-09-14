"""
Structured error types for analyzer stages.

Each error is a small dict so it serializes cleanly into JSON reports:
  {"stage": "certificate", "message": "...", "detail": "..."}

Analyzers return these in an "errors" list alongside whatever partial
results they could still produce.  A failed stage never silently becomes
zero/0.0 — it becomes null with an error entry.
"""
from typing import Optional


class AnalyzerError(Exception):
    def __init__(self, stage: str, message: str, detail: Optional[str] = None):
        self.stage = stage
        self.message = message
        self.detail = detail
        super().__init__(message)

    def to_dict(self) -> dict:
        d = {"stage": self.stage, "message": self.message}
        if self.detail:
            d["detail"] = self.detail
        return d