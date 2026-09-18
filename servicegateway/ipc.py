import json
import socket

MAX_MESSAGE = 2 * 1024 * 1024


class AgentError(RuntimeError):
    pass


class AgentClient:
    def __init__(self, path):
        self.path = path

    def call(self, action, **payload):
        message = json.dumps({"action": action, **payload}).encode() + b"\n"
        if len(message) > MAX_MESSAGE:
            raise AgentError("Agent request too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(90)
                sock.connect(self.path)
                sock.sendall(message)
                with sock.makefile("rb") as stream:
                    raw = stream.readline(MAX_MESSAGE + 1)
                if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
                    raise AgentError("Invalid agent response")
                result = json.loads(raw)
                if not result.get("ok"):
                    raise AgentError(result.get("error", "Agent failed")[:500])
                return result["data"]
        except (OSError, ValueError) as exc:
            raise AgentError(f"Agent unavailable: {type(exc).__name__}") from exc
