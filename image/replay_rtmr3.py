"""Replay a retained dstack RTMR3 event log and emit its canonical result."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from measurement_allowlist import MeasurementAllowlistError, _load_json, replay_rtmr3


def _error(message: str) -> None:
    payload = {"error": {"code": "rtmr3_replay_failed", "message": message}}
    print(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event_log", type=Path)
    args = parser.parse_args(argv)
    try:
        event_log: Any = _load_json(args.event_log, "retained RTMR3 event log")
        if not isinstance(event_log, list):
            raise MeasurementAllowlistError("retained RTMR3 event log must be a list")
        replay = replay_rtmr3(event_log)
        compose_hash = replay["compose_hash"]
        if not isinstance(compose_hash, str):
            raise MeasurementAllowlistError("replayed compose hash is missing")
        result = {
            "compose_hash": compose_hash,
            "rtmr3": replay["rtmr3"],
        }
        print(
            json.dumps(
                result,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
        )
        return 0
    except (OSError, MeasurementAllowlistError, TypeError, ValueError) as error:
        _error(str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
