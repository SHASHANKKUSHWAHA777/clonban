"""
Safe subprocess utilities.

Security rules enforced here:
  - Never use shell=True (argument array form only).
  - Always set a timeout (default 30 s) so a hung external tool cannot
    hold a worker indefinitely.
  - Capture stdout/stderr as bounded text (truncated) — never let a
    binary stream leak unbounded data into logs.
  - Enforce a max output size to avoid OOM on pathological output.
"""
import logging
import subprocess
from typing import Optional

logger = logging.getLogger("clonedetector.subprocess")

DEFAULT_TIMEOUT = 30
MAX_OUTPUT_BYTES = 2 * 1024 * 1024  # 2 MiB


def run_command(
    args: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> dict:
    """
    Run *args* as a subprocess argument array (never shell=True).

    Returns:
        {"returncode": int, "stdout": str, "stderr": str, "timed_out": bool}
    """
    result = {"returncode": -1, "stdout": "", "stderr": "", "timed_out": False}
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
        result["returncode"] = proc.returncode
        stdout = (proc.stdout or "")[:MAX_OUTPUT_BYTES]
        stderr = (proc.stderr or "")[:MAX_OUTPUT_BYTES]
        result["stdout"] = stdout
        result["stderr"] = stderr
        result["timed_out"] = False
    except subprocess.TimeoutExpired as e:
        result["timed_out"] = True
        result["stderr"] = f"Command timed out after {timeout}s"
        stdout = (e.stdout or b"") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = (e.stderr or b"") if isinstance(e.stderr, bytes) else (e.stderr or "")
        if isinstance(stdout, bytes):
            stdout = stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        result["stdout"] = stdout[:MAX_OUTPUT_BYTES]
        result["stderr"] = (f"Command timed out after {timeout}s: {stderr}")[:MAX_OUTPUT_BYTES]
    except FileNotFoundError:
        result["returncode"] = 127
        result["stderr"] = f"Command not found: {args[0]}"
    except Exception as e:
        result["returncode"] = 1
        result["stderr"] = f"Unexpected error: {e}"
        logger.warning("Subprocess error: %s args=%s", e, args, exc_info=True)
    return result


def run_apksigner(apk_path: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[dict]:
    """
    Try to extract signing information via the Android *apksigner* tool.

    Returns None when apksigner is not installed (caller falls back to androguard).
    """
    args = ["apksigner", "verify", "--print-signatures", "--in", apk_path]
    res = run_command(args, timeout=timeout)
    if res["returncode"] == 127:
        logger.warning("apksigner not available, falling back to androguard")
        return None
    return res