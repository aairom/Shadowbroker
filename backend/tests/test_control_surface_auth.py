"""Regression coverage for operator-only control surfaces."""

import pytest


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("get", "/api/wormhole/identity", None),
        ("post", "/api/wormhole/identity/bootstrap", {}),
        ("post", "/api/wormhole/gate/enter", {"gate_id": "general-talk"}),
        ("post", "/api/wormhole/gate/leave", {"gate_id": "general-talk"}),
        ("post", "/api/wormhole/sign", {"event_type": "gate_event", "payload": {"ok": True}}),
        ("post", "/api/wormhole/gate/key/rotate", {"gate_id": "general-talk", "reason": "test"}),
        (
            "post",
            "/api/wormhole/gate/key/grant",
            {
                "gate_id": "general-talk",
                "recipient_node_id": "node-test",
                "recipient_dh_pub": "dh-test",
            },
        ),
        ("post", "/api/wormhole/gate/persona/create", {"gate_id": "general-talk", "label": "test"}),
        (
            "post",
            "/api/wormhole/gate/persona/activate",
            {"gate_id": "general-talk", "persona_id": "persona-test"},
        ),
        ("post", "/api/wormhole/gate/persona/clear", {"gate_id": "general-talk"}),
        (
            "post",
            "/api/wormhole/gate/persona/retire",
            {"gate_id": "general-talk", "persona_id": "persona-test"},
        ),
        (
            "post",
            "/api/wormhole/gate/message/sign-encrypted",
            {
                "gate_id": "general-talk",
                "epoch": 1,
                "ciphertext": "ciphertext",
                "nonce": "nonce",
                "format": "mls1",
                "envelope_hash": "hash",
            },
        ),
        ("post", "/api/wormhole/gate/message/compose", {"gate_id": "general-talk", "plaintext": "hello"}),
        ("post", "/api/wormhole/sign-raw", {"message": "raw"}),
        ("post", "/api/wormhole/gate/state/export", {"gate_id": "general-talk"}),
        ("post", "/api/wormhole/gate/proof", {"gate_id": "general-talk"}),
        ("post", "/api/wormhole/connect", {}),
        ("post", "/api/layers", {"layers": {"viirs_nightlights": True}}),
        ("post", "/api/ais/feed", {"msgs": []}),
    ],
)
def test_remote_control_surface_rejects_without_local_operator_or_admin(
    remote_client, method, path, payload
):
    request = getattr(remote_client, method)
    response = request(path, json=payload) if payload is not None else request(path)

    assert response.status_code == 403


def test_remote_agent_actions_poll_rejects_without_local_operator_or_admin(remote_client):
    response = remote_client.get("/api/ai/agent-actions")

    assert response.status_code == 403
