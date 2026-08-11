import tempfile
import unittest
from pathlib import Path

from udp_analyzer.channels import (
    ChannelCatalog,
    channel_target_from_url,
    extract_urls_from_unit,
    load_channel_targets,
)


class ChannelTargetTests(unittest.TestCase):
    def test_extracts_url_from_systemd_environment(self):
        text = """
        [Service]
        Environment="CHANNEL_URL=https://api.example.com/foo?token=redacted"
        ExecStart=/usr/bin/my-app
        """

        self.assertEqual(
            extract_urls_from_unit(text),
            ["https://api.example.com/foo?token=redacted"],
        )

    def test_one_unit_must_not_define_multiple_urls(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            path = Path(raw_dir) / "channel-a.service"
            path.write_text(
                """
                [Service]
                Environment=URL=https://api.example.com/foo
                Environment=OTHER_URL=https://api.example.com/bar
                """,
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "expected one URL per unit"):
                load_channel_targets([path])

    def test_same_host_port_is_separated_by_unit(self):
        first = channel_target_from_url(
            "channel-a.service",
            "https://api.example.com/foo",
        )
        second = channel_target_from_url(
            "channel-b.service",
            "https://api.example.com/bar",
        )
        catalog = ChannelCatalog([first, second]).resolve(
            resolver=lambda host, port: [
                (2, 1, 6, "", ("203.0.113.10", port)),
            ]
        )

        first_match = catalog.match("channel-a.service", "203.0.113.10", 443)
        second_match = catalog.match("channel-b.service", "203.0.113.10", 443)

        self.assertEqual(first_match.status, "matched")
        self.assertEqual(first_match.target.url, "https://api.example.com/foo")
        self.assertEqual(second_match.status, "matched")
        self.assertEqual(second_match.target.url, "https://api.example.com/bar")

    def test_unexpected_endpoint_is_visible(self):
        target = channel_target_from_url(
            "channel-a.service",
            "https://api.example.com/foo",
        )
        catalog = ChannelCatalog([target]).resolve(
            resolver=lambda host, port: [
                (2, 1, 6, "", ("203.0.113.10", port)),
            ]
        )

        match = catalog.match("channel-a.service", "198.51.100.20", 443)

        self.assertEqual(match.status, "unexpected_flow")
        self.assertEqual(match.target.url, "https://api.example.com/foo")


if __name__ == "__main__":
    unittest.main()
