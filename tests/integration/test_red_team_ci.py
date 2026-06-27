"""Red-team smoke test that runs on every PR via CI."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_red_team_passes_full_default_suite() -> None:
    response = client.post("/v1/red-team/run", json={"suite": "default", "mode": "offline"})
    body = response.json()
    assert response.status_code == 200
    assert body["failed"] == 0, f"Red-team failures: {body['failures']}"
    assert body["pass_rate"] == 1.0
