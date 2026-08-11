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

    def test_multi_url_unit_is_skipped_with_warning_not_fatal(self):
        # A stray package unit with Documentation=https://... plus another URL
        # must not take the whole monitor down at startup — it is not a channel.
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
            good = Path(raw_dir) / "channel-b.service"
            good.write_text(
                "[Service]\nEnvironment=URL=https://api.example.com/ok\n",
                encoding="utf-8",
            )

            with self.assertWarnsRegex(RuntimeWarning, "expected one URL per unit"):
                targets = load_channel_targets([path, good])
            self.assertEqual([t.unit for t in targets], ["channel-b.service"])

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


#: The REAL recorder deployment contract: a template unit whose URL lives in an
#: EnvironmentFile, one env file per instance. This is the exact layout of the
#: ffmpeg@ template on ELA recorders (${INPUT_URL} + EnvironmentFile=<dir>/%i.env).
RECORDER_TEMPLATE = """
[Service]
ExecStartPre=-/usr/local/bin/analyzer refresh %i
EnvironmentFile={env_dir}/%i.env
ExecStart=/usr/bin/ffmpeg -hide_banner -nostdin -i ${{INPUT_URL}} \\
    -c copy -f segment -segment_time ${{SEGMENT_SECONDS}} ${{OUTPUT_PATTERN}}
"""


class TemplateUnitTests(unittest.TestCase):
    def _mk(self, raw_dir, name, body):
        p = Path(raw_dir) / name
        p.write_text(body, encoding="utf-8")
        return p

    def test_template_instances_come_from_environment_files(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            env_dir = Path(raw_dir) / "env"
            env_dir.mkdir()
            self._mk(env_dir, "radio-a.env",
                     "INPUT_URL=http://radiostream.example/tuba145-1.mp3\n"
                     "SEGMENT_SECONDS=900\nOUTPUT_PATTERN=/rec/%Y/radio-a/R.aac\n")
            self._mk(env_dir, "radio-b.env",
                     "INPUT_URL=http://radiostream.example/tuba9.mp3\n")
            # a TV instance with a udp:// input is NOT an http channel: skipped
            self._mk(env_dir, "tv-a.env",
                     "INPUT_URL=udp://239.1.2.3:1234?fifo_size=5\n")
            template = self._mk(raw_dir, "ffmpeg@.service",
                                RECORDER_TEMPLATE.format(env_dir=env_dir))

            targets = load_channel_targets([template])

            self.assertEqual(
                [(t.unit, t.channel) for t in targets],
                [("ffmpeg@radio-a.service", "radio-a"),
                 ("ffmpeg@radio-b.service", "radio-b")],
            )
            self.assertEqual(targets[0].url,
                             "http://radiostream.example/tuba145-1.mp3")
            self.assertEqual(targets[0].port, 80)

    def test_template_instance_match_uses_full_instance_unit_name(self):
        # cgroup reports the INSTANCE name (ffmpeg@radio-a.service) — the catalog
        # must be keyed by it, or every row degrades to unknown_unit.
        with tempfile.TemporaryDirectory() as raw_dir:
            env_dir = Path(raw_dir) / "env"
            env_dir.mkdir()
            self._mk(env_dir, "radio-a.env",
                     "INPUT_URL=http://radiostream.example/x.mp3\n")
            template = self._mk(raw_dir, "ffmpeg@.service",
                                RECORDER_TEMPLATE.format(env_dir=env_dir))
            catalog = ChannelCatalog(load_channel_targets([template])).resolve(
                resolver=lambda host, port: [(2, 1, 6, "", ("203.0.113.10", port))])

            self.assertEqual(
                catalog.match("ffmpeg@radio-a.service", "203.0.113.10", 80).status,
                "matched")
            self.assertEqual(
                catalog.match("ffmpeg@radio-zz.service", "203.0.113.10", 80).status,
                "unknown_unit")

    def test_plain_unit_reads_environment_file_too(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            env = self._mk(Path(raw_dir), "one.env",
                           "URL=https://api.example.com/stream\n")
            unit = self._mk(raw_dir, "single.service",
                            f"[Service]\nEnvironmentFile=-{env}\n"
                            "ExecStart=/usr/bin/app ${URL}\n")

            targets = load_channel_targets([unit])

            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0].url, "https://api.example.com/stream")

    def test_percent_h_expands_to_unit_owner_home(self):
        from udp_analyzer.channels import expand_home_specifier

        unit_path = Path("/home/tv/.config/systemd/user/ffmpeg@.service")
        self.assertEqual(
            expand_home_specifier("%h/ELA-system/env/%i.env", unit_path),
            "/home/tv/ELA-system/env/%i.env")


if __name__ == "__main__":
    unittest.main()
