"""Unit tests for the Agent Gate policy checks and tool list.

They import gate.py with a temporary data folder and a small options file, so
nothing touches /data, the Supervisor or MQTT. main() is never called.

Run from the repository root:
    python -m unittest discover -s agent_gate/tests
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON = os.path.dirname(HERE)

_TMP = tempfile.mkdtemp(prefix="agent_gate_test_")
_OPTIONS = os.path.join(_TMP, "options.json")
with open(_OPTIONS, "w", encoding="utf-8") as f:
    json.dump({
        "upstream_mcp_url": "http://127.0.0.1:9583/private_upstream_path_123456",
        "protected_patterns": ["agent_gate"],
        "destructive_patterns": [r"\brm\b", r"\bmv\b", r"\bdocker\b", r">\s*/"],
        "redact_secrets": True,
    }, f)
os.environ["GATE_OPTIONS"] = _OPTIONS
os.environ["GATE_DATA"] = _TMP
os.environ.setdefault("SUPERVISOR_TOKEN", "")
sys.path.insert(0, ADDON)

import gate  # noqa: E402


class ToolListTests(unittest.TestCase):
    def test_tool_names_match(self):
        self.assertEqual(tuple(t["name"] for t in gate.GATE_TOOLS), gate.GATE_TOOL_NAMES)

    def test_every_tool_has_annotations(self):
        keys = {"title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}
        for tool in gate.GATE_TOOLS:
            with self.subTest(tool=tool["name"]):
                self.assertTrue(keys.issubset(tool.get("annotations", {})))
                self.assertEqual(tool["inputSchema"]["type"], "object")

    def test_annotation_values(self):
        ann = {t["name"]: t["annotations"] for t in gate.GATE_TOOLS}
        self.assertTrue(ann["gate_status"]["readOnlyHint"])
        self.assertFalse(ann["gate_status"]["destructiveHint"])
        self.assertTrue(ann["gate_run_command"]["destructiveHint"])
        self.assertFalse(ann["gate_run_command"]["readOnlyHint"])
        self.assertTrue(ann["gate_agent_files"]["destructiveHint"])

    def test_inject_replaces_upstream_tools_with_same_name(self):
        msg = {"result": {"tools": [{"name": "ha_get_state"},
                                    {"name": "gate_run_command", "description": "fake"}]}}
        out = gate.inject_gate_tools(msg)
        names = [t["name"] for t in out["result"]["tools"]]
        self.assertEqual(names.count("gate_run_command"), 1)
        self.assertIn("ha_get_state", names)
        fake = [t for t in out["result"]["tools"] if t.get("description") == "fake"]
        self.assertEqual(fake, [])

    def test_rewrite_tools_list_sse(self):
        body = 'event: message\ndata: {"result": {"tools": []}}\n\n'.encode()
        out = gate.rewrite_tools_list_body("text/event-stream", body).decode()
        self.assertIn("gate_status", out)
        self.assertIn("readOnlyHint", out)


class ProtectedTests(unittest.TestCase):
    def test_plain_name(self):
        self.assertTrue(gate.touches_protected({"slug": "local_agent_gate"}))

    def test_split_with_quotes(self):
        self.assertTrue(gate.touches_protected({"cmd": 'agent_g""ate'}))

    def test_unicode_escape(self):
        self.assertTrue(gate.touches_protected({"x": "agent\\u005fgate"}))

    def test_hassio_template(self):
        self.assertTrue(gate.touches_protected(
            {"action": "hassio.addon_stop", "data": {"addon": "{{ 'x' }}"}}))

    def test_unrelated_call(self):
        self.assertFalse(gate.touches_protected({"entity_id": "light.kitchen"}))


class GateControlTests(unittest.TestCase):
    def test_mqtt_with_template(self):
        self.assertTrue(gate.reaches_gate_controls(
            "ha_call_service", {"domain": "mqtt", "topic": "{{ 'agent' ~ '_gate' }}"}))

    def test_mqtt_discovery_prefix(self):
        self.assertTrue(gate.reaches_gate_controls(
            "ha_call_service", {"domain": "mqtt", "topic": "homeassistant/switch/x/config"}))

    def test_firing_phone_action(self):
        self.assertTrue(gate.reaches_gate_controls(
            "ha_call_event", {"event_type": "mobile_app_notification_action"}))

    def test_plain_mqtt_is_allowed(self):
        self.assertEqual(gate.reaches_gate_controls(
            "ha_call_service", {"domain": "mqtt", "topic": "lights/kitchen/set"}), "")


class ReadToolTests(unittest.TestCase):
    def test_read_patterns(self):
        self.assertTrue(gate.is_read_tool("ha_get_state"))
        self.assertTrue(gate.is_read_tool("ha_config_get_automation"))

    def test_camera_excluded(self):
        self.assertFalse(gate.is_read_tool("ha_get_camera_image"))

    def test_write_tool(self):
        self.assertFalse(gate.is_read_tool("ha_call_service"))


class DestructiveTests(unittest.TestCase):
    def test_destructive(self):
        for cmd in ("rm -rf /addons/x", "mv a b", "docker ps", "echo hi > /homeassistant/x"):
            with self.subTest(cmd=cmd):
                self.assertTrue(gate.is_destructive(cmd))

    def test_harmless(self):
        for cmd in ("ls -la /addons", "cat README.md", "grep -r foo ."):
            with self.subTest(cmd=cmd):
                self.assertFalse(gate.is_destructive(cmd))


class RedactionTests(unittest.TestCase):
    def test_key_value(self):
        text, n = gate.redact_text("password: hunter2secret")
        self.assertNotIn("hunter2secret", text)
        self.assertGreaterEqual(n, 1)

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
        text, _ = gate.redact_text("token " + jwt)
        self.assertNotIn(jwt, text)

    def test_upstream_path_is_hidden(self):
        text, _ = gate.redact_text("url is http://x/private_upstream_path_123456/mcp")
        self.assertNotIn("private_upstream_path_123456", text)

    def test_plain_text_unchanged(self):
        self.assertEqual(gate.redact_text("hello world"), ("hello world", 0))


if __name__ == "__main__":
    unittest.main()
