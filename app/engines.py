from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO

MAX_SOURCE_BYTES = 200_000
MAX_STDOUT_BYTES = 1_000_000
MAX_STDERR_BYTES = 20_000
WORKER_TIMEOUT_SECONDS = 60
WORKER_IMAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,199}$")


def normalize_slither_findings(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    results = parsed.get("results")
    detectors = results.get("detectors", []) if isinstance(results, dict) else []
    if not isinstance(detectors, list):
        return findings
    for item in detectors:
        if not isinstance(item, dict):
            continue
        locations = []
        elements = item.get("elements", [])
        for element in elements if isinstance(elements, list) else []:
            if not isinstance(element, dict):
                continue
            mapping = element.get("source_mapping", {})
            lines = mapping.get("lines") if isinstance(mapping, dict) else None
            if (
                isinstance(lines, list)
                and lines
                and all(isinstance(line, int) and line > 0 for line in lines)
            ):
                locations.append({
                    "file": Path(mapping.get("filename_relative", "")).name,
                    "lines": lines,
                })
        findings.append({
            "id": item.get("id") or item.get("check", "unknown"),
            "check": item.get("check", "unknown"),
            "severity": str(item.get("impact", "informational")).lower(),
            "confidence": str(item.get("confidence", "unknown")).lower(),
            "description": str(item.get("description", ""))[:4000],
            "locations": locations,
            "source": "slither",
        })
    return findings


def _drain_stream(
    stream: BinaryIO,
    destination: bytearray,
    limit: int,
    overflow: threading.Event,
    name: str,
    truncated: dict[str, bool],
) -> None:
    while chunk := stream.read(8192):
        remaining = limit - len(destination)
        if remaining > 0:
            destination.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated[name] = True
            overflow.set()


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.terminate()
    except OSError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        process.wait()


def _stop_container(cidfile: Path) -> str | None:
    try:
        container_id = cidfile.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None
    except OSError as error:
        return f"Could not read worker container ID ({type(error).__name__})."
    if not container_id:
        return None
    try:
        stopped = subprocess.run(
            ["docker", "kill", container_id],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"Could not stop worker container ({type(error).__name__})."
    if stopped.returncode != 0:
        return f"Could not stop worker container (exit {stopped.returncode})."
    return None


def _run_worker(
    command: list[str],
    cidfile: Path,
) -> tuple[int, bytes, bytes, bool, bool, bool, bool, str | None]:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    truncated = {"stdout": False, "stderr": False}
    readers = [
        threading.Thread(
            target=_drain_stream,
            args=(process.stdout, stdout, MAX_STDOUT_BYTES, overflow, "stdout", truncated),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr, MAX_STDERR_BYTES, overflow, "stderr", truncated),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + WORKER_TIMEOUT_SECONDS
    timed_out = False
    stopped_early = False
    while process.poll() is None:
        if overflow.is_set():
            stopped_early = True
            _stop_process(process)
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            stopped_early = True
            _stop_process(process)
            break
        time.sleep(min(0.025, remaining))
    for reader in readers:
        reader.join()
    process.stdout.close()
    process.stderr.close()

    output_limited = overflow.is_set()
    cleanup_error = _stop_container(cidfile) if stopped_early else None
    return (
        process.returncode if process.returncode is not None else -1,
        bytes(stdout),
        bytes(stderr),
        timed_out,
        output_limited,
        truncated["stdout"],
        truncated["stderr"],
        cleanup_error,
    )


def audit_source(source: str, filename: str) -> dict[str, Any]:
    if Path(filename).suffix.lower() != ".sol":
        return {"status": "failed", "error": "Only .sol files are accepted."}
    if not source.strip() or len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        return {"status": "failed", "error": "Source is empty or exceeds the size limit."}
    if not shutil.which("docker"):
        return {"status": "tool_unavailable", "engine": "slither", "findings": [],
                "message": "Docker is not installed; analysis did not run."}
    image = os.getenv("AEGIS_WORKER_IMAGE", "")
    if not image or not WORKER_IMAGE_PATTERN.fullmatch(image):
        return {"status": "not_configured", "engine": "slither", "findings": [],
                "message": "Set AEGIS_WORKER_IMAGE to a locally built, trusted worker image."}

    with tempfile.TemporaryDirectory(prefix="aegis-input-") as directory:
        source_path = Path(directory) / Path(filename).name
        source_path.write_text(source, encoding="utf-8")
        cidfile = Path(directory) / "worker.cid"
        command = [
            "docker", "run", "--rm", "--pull=never", "--network=none",
            "--cidfile", str(cidfile),
            "--read-only", "--memory=1g", "--cpus=1", "--pids-limit=128",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user=65534:65534", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--mount", f"type=bind,src={source_path},dst=/input/contract.sol,readonly",
            "--env", "HOME=/tmp", image, "/input/contract.sol", "--json", "-", "--fail-none",
        ]
        started = time.monotonic()
        try:
            inspected = subprocess.run(
                [
                    "docker", "image", "inspect", "--format",
                    "{{.Id}} {{index .Config.Labels \"org.aegis.slither-version\"}}",
                    image,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
            image_metadata = inspected.stdout.strip().split()
            if (
                inspected.returncode != 0
                or len(image_metadata) != 2
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_metadata[0])
                or not re.fullmatch(r"\d+\.\d+\.\d+", image_metadata[1])
            ):
                return {
                    "status": "not_configured",
                    "engine": "slither",
                    "findings": [],
                    "message": "Trusted worker image is missing or has no verifiable Aegis tool labels.",
                    "raw_stdout": inspected.stdout[:10_000],
                    "raw_stderr": inspected.stderr[-10_000:],
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }
            image_digest, slither_version = image_metadata
            command[command.index(image)] = image_digest
            (
                exit_code,
                stdout_bytes,
                stderr_bytes,
                timed_out,
                output_limited,
                stdout_truncated,
                stderr_truncated,
                cleanup_error,
            ) = _run_worker(command, cidfile)
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            stdout_sha256 = hashlib.sha256(stdout_bytes).hexdigest()
            stderr_sha256 = hashlib.sha256(stderr_bytes).hexdigest()
            duration_ms = int((time.monotonic() - started) * 1000)
            if timed_out or output_limited:
                limited_result = {
                    "status": "timeout" if timed_out else "output_limit",
                    "engine": "slither",
                    "engine_version": f"slither-analyzer {slither_version}",
                    "worker_image_digest": image_digest,
                    "findings": [],
                    "duration_ms": duration_ms,
                    "message": (
                        "Worker exceeded its time limit; analysis is inconclusive."
                        if timed_out
                        else "Worker exceeded the bounded output limit; analysis is inconclusive."
                    ),
                    "raw_stdout": stdout,
                    "raw_stderr": stderr,
                    "raw_stdout_truncated": stdout_truncated,
                    "raw_stderr_truncated": stderr_truncated,
                    "raw_stdout_sha256": stdout_sha256,
                    "raw_stderr_sha256": stderr_sha256,
                }
                if cleanup_error:
                    limited_result["cleanup_error"] = cleanup_error
                return limited_result
            completed = subprocess.CompletedProcess(
                command, exit_code, stdout=stdout, stderr=stderr
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout", "engine": "slither", "engine_version": None,
                "findings": [], "duration_ms": int((time.monotonic() - started) * 1000),
                "message": "Worker image inspection or analysis exceeded its time limit.",
                "raw_stdout": "", "raw_stderr": "Worker timeout.",
            }
        except OSError as error:
            return {
                "status": "engine_error",
                "engine": "slither",
                "findings": [],
                "duration_ms": int((time.monotonic() - started) * 1000),
                "message": "The isolated worker could not be started.",
                "raw_stdout": "",
                "raw_stderr": type(error).__name__,
            }

    duration_ms = int((time.monotonic() - started) * 1000)
    parsed = None
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError:
        pass
    success = completed.returncode == 0 and isinstance(parsed, dict) and parsed.get("success") is True
    return {
        "status": "completed" if success else "engine_error",
        "engine": "slither",
        "engine_version": f"slither-analyzer {slither_version}",
        "worker_image_digest": image_digest,
        "findings": normalize_slither_findings(parsed) if success else [],
        "duration_ms": duration_ms,
        "exit_code": completed.returncode,
        "message": (
            "Tool output requires human review; no security certification is implied."
            if success else "The isolated analyzer failed; the result is inconclusive."
        ),
        "raw_stdout": completed.stdout,
        "raw_stderr": completed.stderr,
        "raw_stdout_truncated": False,
        "raw_stderr_truncated": False,
        "raw_stdout_sha256": stdout_sha256,
        "raw_stderr_sha256": stderr_sha256,
    }
