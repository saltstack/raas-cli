import shlex
import subprocess

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="salt-config-cli API", version="1.0.0")

SCC_BINARY = "scc"
DEFAULT_TIMEOUT_SECONDS = 60


class CommandRequest(BaseModel):
    command: str = Field(
        ...,
        description='Salt config CLI command to run, e.g. "repo list --json" or "scc repo list --json"',
        min_length=1,
    )
    timeout: int = Field(DEFAULT_TIMEOUT_SECONDS, ge=1, le=600)


class CommandResponse(BaseModel):
    command: str
    returncode: int
    stdout: str
    stderr: str


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/commands", response_model=CommandResponse)
def run_command(request: CommandRequest) -> CommandResponse:
    try:
        args = shlex.split(request.command)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"could not parse command: {exc}") from exc

    if not args:
        raise HTTPException(status_code=400, detail="command must not be empty")

    # Allow the command to optionally be prefixed with the binary name itself.
    if args[0] in (SCC_BINARY, "salt-config", "raas"):
        args = args[1:]

    command = [SCC_BINARY, *args]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=request.timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(
            status_code=504, detail=f"command timed out after {request.timeout}s"
        ) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=f"{SCC_BINARY} binary not found") from exc

    return CommandResponse(
        command=shlex.join(command),
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )
