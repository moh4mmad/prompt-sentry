import json
from pathlib import Path

from app.models.schemas import Action, AttackType, Source
from app.redteam.runner import RedTeamCase

_LIBRARY_DIR = Path(__file__).parent.parent.parent / "attack_library"

_SOURCE_MAP: dict[str, Source] = {s.value: s for s in Source}
_ACTION_MAP: dict[str, Action] = {a.value: a for a in Action}
_ATTACK_MAP: dict[str, AttackType] = {a.value: a for a in AttackType}


def load_library_cases() -> list[RedTeamCase]:
    cases: list[RedTeamCase] = []
    if not _LIBRARY_DIR.exists():
        return cases
    for path in sorted(_LIBRARY_DIR.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                cases.append(
                    RedTeamCase(
                        test_id=obj["id"],
                        name=obj.get("name", obj["id"]),
                        category=_ATTACK_MAP[obj["category"]],
                        source=_SOURCE_MAP[obj["source"]],
                        prompt=obj["text"],
                        expected_action=_ACTION_MAP[obj["expected_action"]],
                    )
                )
            except (KeyError, json.JSONDecodeError):
                continue
    return cases
