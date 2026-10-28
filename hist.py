import argparse
import asyncio
import os
import re
from dataclasses import dataclass
from pathlib import Path

from typesafe_sdk import AsyncTypeSafeClient, Choice


@dataclass
class CommandResult:
    index: int
    command: str
    security: str
    external: str
    error: str | None = None


def resolve_history_file(custom_path: str | None = None) -> Path:
    if custom_path:
        path = Path(custom_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"History file not found: {path}")
        return path

    histfile = os.environ.get("HISTFILE")
    if histfile and Path(histfile).expanduser().is_file():
        return Path(histfile).expanduser()

    # Prioritize based on current shell, then standard locations
    shell = os.environ.get("SHELL", "")
    candidates = []
    if "zsh" in shell:
        candidates.extend([Path("~/.zsh_history"), Path("~/.bash_history")])
    else:
        candidates.extend([Path("~/.bash_history"), Path("~/.zsh_history")])

    for candidate in candidates:
        expanded = candidate.expanduser()
        if expanded.is_file():
            return expanded

    raise FileNotFoundError("Could not find shell history file (.zsh_history or .bash_history)")


def parse_history(file_path: Path, limit: int = 100) -> list[str]:
    raw_content = file_path.read_bytes().decode("utf-8", errors="replace")
    commands: list[str] = []
    current_entry: list[str] = []

    # Regex for zsh extended_history format: ': <timestamp>:<duration>;<cmd>'
    zsh_pattern = re.compile(r"^: \d+:\d+;(.*)$")

    for line in raw_content.splitlines():
        # Bash history timestamp comments (e.g. #1700000000)
        if re.match(r"^#\d+$", line.strip()):
            continue

        match = zsh_pattern.match(line)
        if match:
            if current_entry:
                cmd = "\n".join(current_entry).strip()
                if cmd:
                    commands.append(cmd)
            current_entry = [match.group(1)]
        elif current_entry:
            # Continuation line for multi-line command
            current_entry.append(line)
        else:
            cmd = line.strip()
            if cmd:
                commands.append(cmd)

    if current_entry:
        cmd = "\n".join(current_entry).strip()
        if cmd:
            commands.append(cmd)

    return commands[-limit:] if limit > 0 else commands


async def analyze_command(
    client: AsyncTypeSafeClient,
    semaphore: asyncio.Semaphore,
    index: int,
    command: str,
    cwd: str,
) -> CommandResult:
    async with semaphore:
        try:
            response = await client.system_one(
                state={
                    "command": command,
                    "cwd": cwd,
                },
                questions={
                    "security": Choice(
                        instructions="How dangerous is this command?",
                        criteria={"reads": None, "modifies": None, "deletes": None},
                    ),
                    "external": Choice(
                        instructions="Access outside cwd?",
                        criteria={"yes": None, "no": None},
                    ),
                },
            )
            security = response.choices["security"].choice
            external = response.choices["external"].choice
            return CommandResult(
                index=index,
                command=command,
                security=security,
                external=external,
            )
        except Exception as exc:  # noqa: BLE001
            return CommandResult(
                index=index,
                command=command,
                security="error",
                external="error",
                error=str(exc),
            )


async def analyze_history(
    commands: list[str],
    cwd: str,
    concurrency: int = 10,
) -> list[CommandResult]:
    semaphore = asyncio.Semaphore(concurrency)
    async with AsyncTypeSafeClient() as client:
        tasks = [
            analyze_command(client, semaphore, i + 1, cmd, cwd)
            for i, cmd in enumerate(commands)
        ]
        return await asyncio.gather(*tasks)


def print_report(results: list[CommandResult]) -> None:
    print(f"\n{'#':>4} | {'SECURITY':<10} | {'EXTERNAL':<8} | COMMAND")
    print("-" * 80)

    stats_security: dict[str, int] = {}
    stats_external: dict[str, int] = {}

    for res in results:
        single_line_cmd = " ".join(res.command.split())
        display_cmd = (
            single_line_cmd[:55] + "..." if len(single_line_cmd) > 58 else single_line_cmd
        )

        stats_security[res.security] = stats_security.get(res.security, 0) + 1
        stats_external[res.external] = stats_external.get(res.external, 0) + 1

        print(f"{res.index:>4} | {res.security:<10} | {res.external:<8} | {display_cmd}")

    print("-" * 80)
    print("\nResumen:")
    print(f"Total comandos analizados: {len(results)}")
    print("Seguridad:")
    for k, v in sorted(stats_security.items()):
        print(f"  - {k}: {v}")
    print("Acceso fuera de cwd:")
    for k, v in sorted(stats_external.items()):
        print(f"  - {k}: {v}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verifica los últimos comandos del historial con TypeSafe AI"
    )
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=100,
        help="Número de comandos a verificar (por defecto: 100)",
    )
    parser.add_argument(
        "--history-file",
        type=str,
        default=None,
        help="Ruta al archivo de historial (por defecto: detectado automáticamente)",
    )
    parser.add_argument(
        "--cwd",
        type=str,
        default=os.getcwd(),
        help="Directorio de trabajo actual para la verificación de contexto",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Nivel de concurrencia para las peticiones a la API (por defecto: 10)",
    )

    args = parser.parse_args()

    history_path = resolve_history_file(args.history_file)
    print(f"Leyendo historial de: {history_path}")

    commands = parse_history(history_path, limit=args.limit)
    print(f"Analizando los últimos {len(commands)} comandos con TypeSafe AI (concurrencia: {args.concurrency})...")

    results = asyncio.run(
        analyze_history(commands, cwd=args.cwd, concurrency=args.concurrency)
    )
    print_report(results)


if __name__ == "__main__":
    main()
