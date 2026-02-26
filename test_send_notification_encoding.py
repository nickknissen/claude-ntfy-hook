import importlib.util
import pathlib
import unittest
from unittest import mock


def _load_module():
    module_path = pathlib.Path(__file__).resolve().parent / "claude-notify.py"
    spec = importlib.util.spec_from_file_location("claude_notify", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


claude_notify = _load_module()


class SendNotificationEncodingTests(unittest.TestCase):
    def test_send_notification_sets_utf8_content_type(self):
        message = "SingleOrDefault \u2192 FirstOrDefault"
        with mock.patch.object(claude_notify.requests, "post") as mock_post:
            mock_post.return_value = mock.Mock(status_code=200)

            claude_notify.send_notification("Title", message)

        sent = mock_post.call_args.kwargs
        headers = sent["headers"]
        self.assertEqual(headers.get("Content-Type"), "text/plain; charset=utf-8")
        self.assertEqual(sent["data"], message.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
