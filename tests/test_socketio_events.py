"""
Tests for Socket.IO event handlers.

Regression coverage for the AttributeError raised by Flask-SocketIO 5.3.4 on
Flask >= 3.1: RequestContext.session became a read-only property, so the
library's `ctx.session = session_obj` assignment blew up and every Socket.IO
event handler failed. This broke the dashboard's live stats feed.
"""

import importlib.metadata

from app import socketio


class TestSocketIOEventHandlers:
    def test_request_stats_emits_stats_update(self, db_cleanup):
        client = socketio.test_client(_socketio_app())
        try:
            assert client.is_connected()
            client.emit("request_stats")
            received = client.get_received()
            events = [e["name"] for e in received]
            assert "stats_update" in events
        finally:
            if client.is_connected():
                client.disconnect()

    def test_request_stats_payload_shape(self, db_cleanup):
        client = socketio.test_client(_socketio_app())
        try:
            client.emit("request_stats")
            payload = next(
                e["args"][0] for e in client.get_received() if e["name"] == "stats_update"
            )
            for key in ("employees", "vehicles", "visitors", "pending_approvals", "timestamp"):
                assert key in payload
        finally:
            if client.is_connected():
                client.disconnect()

    def test_flask_socketio_supports_installed_flask(self):
        """Flask >= 3.1 made RequestContext.session read-only.

        Flask-SocketIO only works there from 5.5.0 onward, so an older pin
        fails on every event dispatch.
        """
        flask_version = importlib.metadata.version("Flask")
        flask_socketio_version = importlib.metadata.version("Flask-SocketIO")
        major, minor = (int(part) for part in flask_version.split(".")[:2])
        if (major, minor) < (3, 1):
            return  # read-only session property was introduced in Flask 3.1
        parts = tuple(int(p) for p in flask_socketio_version.split(".")[:3])
        assert parts >= (5, 5, 0), (
            f"Flask {flask_version} requires Flask-SocketIO >= 5.5.0, "
            f"but {flask_socketio_version} is pinned"
        )


def _socketio_app():
    from app import app

    return app
