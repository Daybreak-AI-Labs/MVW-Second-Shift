"""Command line: ``python -m second_shift_runtime run|serve --definition agent.json``."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from .definition import DefinitionError, load_definition
from .loop import run_agent
from .server import definition_runner, make_server
from .skills_service import DEFAULT_KEY_ENV, SkillRuns, build_openapi, make_skills_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="second_shift_runtime", description="Run an agent governed by Second Shift.")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Run the agent once on a task and print its answer.")
    run.add_argument("--definition", required=True, help="Path to the agent definition (JSON).")
    run.add_argument("--input", required=True, help='The task. Use "-" to read it from standard input.')
    run.add_argument("--output", default="output", help="Folder for files the agent creates (default: ./output).")
    serve = sub.add_parser("serve", help="Serve GET /ping and POST /invocations (AgentCore / container contract).")
    serve.add_argument("--definition", required=True)
    serve.add_argument("--output", default="/tmp/second-shift-output", help="Folder for files the agent creates.")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--inbound-key-env", help="Name of an environment variable holding a bearer key callers must send.")
    skills = sub.add_parser("serve-skills", help="Serve the agent's skills over HTTP, each call checked with Second Shift first "
                                                  "(for an agent that runs on Microsoft Foundry).")
    skills.add_argument("--definition", required=True)
    skills.add_argument("--output", default="/tmp/second-shift-skills", help="Folder for files a skill makes while it runs.")
    skills.add_argument("--host", default="0.0.0.0")
    skills.add_argument("--port", type=int, default=8080)
    skills.add_argument("--inbound-key-env", default=DEFAULT_KEY_ENV,
                        help=f"Name of the environment variable holding the key callers send in x-api-key (default {DEFAULT_KEY_ENV}).")
    skills.add_argument("--server-url", help="The public https address of this service; when given, GET /openapi.json serves the OpenAPI file.")
    skills.add_argument("--run-idle-seconds", type=float, default=120.0, help="A run ends after this many seconds without a call.")
    skills.add_argument("--approval-wait-seconds", type=float, default=60.0, help="How long a call waits for a person to approve it.")
    spec = sub.add_parser("skills-openapi", help="Print the OpenAPI 3.0 file for the skills service.")
    spec.add_argument("--definition", required=True)
    spec.add_argument("--server-url", required=True, help="The public https address of the skills service.")
    args = parser.parse_args(argv)
    logging.basicConfig(level=os.environ.get("SECOND_SHIFT_LOG_LEVEL", "WARNING"), format="%(asctime)s %(name)s %(message)s")
    try:
        definition = load_definition(args.definition)
    except DefinitionError as exc:
        print(f"The agent definition cannot be used. {exc}", file=sys.stderr)
        return 2

    if args.command == "run":
        task = sys.stdin.read() if args.input == "-" else args.input
        result = run_agent(definition, task, Path(args.output))
        if result.outcome == "success":
            print(result.answer)
        else:
            print(f"The run did not finish: {result.reason}", file=sys.stderr)
        for info in result.files:
            print(f"file: {info.path} ({info.size} bytes, sha256 {info.sha256})", file=sys.stderr)
        if result.report_error:
            print(f"Warning: the run report could not be sent to Second Shift. {result.report_error}", file=sys.stderr)
        return 0 if result.outcome == "success" else 1

    if args.command == "skills-openapi":
        try:
            print(json.dumps(build_openapi(definition, args.server_url), indent=2))
        except ValueError as exc:
            print(f"The OpenAPI file cannot be made. {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "serve-skills":
        if not definition.skills:
            print("The agent has no skills, so there is nothing to serve.", file=sys.stderr)
            return 2
        key = os.environ.get(args.inbound_key_env, "")
        if not key:
            print(f"The environment variable {args.inbound_key_env} is empty, so there is no key to check callers against.", file=sys.stderr)
            return 2
        runs = SkillRuns(definition, Path(args.output), idle_seconds=args.run_idle_seconds, approval_wait=args.approval_wait_seconds)
        skills_server = make_skills_server(runs, args.host, args.port, key, server_url=args.server_url)
        skills_server.start_reaper()
        print(f"Serving the skills of {definition.name} on {args.host}:{args.port}", file=sys.stderr)
        try:
            skills_server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            skills_server.shutdown_runs()
            skills_server.server_close()
        return 0

    inbound = None
    if args.inbound_key_env:
        inbound = os.environ.get(args.inbound_key_env, "")
        if not inbound:
            print(f"The environment variable {args.inbound_key_env} is empty, so there is no inbound key to check.", file=sys.stderr)
            return 2
    server = make_server(definition_runner(definition), args.host, args.port, Path(args.output), inbound_key=inbound)
    print(f"Serving {definition.name} on {args.host}:{args.port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
