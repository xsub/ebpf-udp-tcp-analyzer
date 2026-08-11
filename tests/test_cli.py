import unittest
import tempfile
from pathlib import Path
from unittest import mock

from udp_analyzer.cli import build_parser, create_channel_collector, create_collector
from udp_analyzer.models import SampleFilter
from udp_analyzer.tcp_channel import ChannelSampleFilter, TcpChannelDryRunCollector


class CliAttributionTests(unittest.TestCase):
    def setUp(self):
        self.parser = build_parser()

    def test_enrich_processes_uses_auto_cookie_first_mode(self):
        args = self.parser.parse_args(
            ["run", "--collector", "ebpf", "--no-attach", "--enrich-processes"]
        )

        with mock.patch("udp_analyzer.cli.EbpfCollector") as collector_class:
            create_collector(args, SampleFilter())

        self.assertEqual(
            collector_class.call_args.kwargs["delivery_attribution"], "auto"
        )

    def test_legacy_mode_is_explicitly_selectable(self):
        args = self.parser.parse_args(
            [
                "run",
                "--collector",
                "ebpf",
                "--no-attach",
                "--delivery-attribution",
                "legacy",
            ]
        )

        with mock.patch("udp_analyzer.cli.EbpfCollector") as collector_class:
            create_collector(args, SampleFilter())

        self.assertEqual(
            collector_class.call_args.kwargs["delivery_attribution"], "legacy"
        )

    def test_process_filter_rejects_disabled_attribution(self):
        args = self.parser.parse_args(
            [
                "run",
                "--collector",
                "ebpf",
                "--process-name",
                "ffmpeg",
                "--delivery-attribution",
                "none",
            ]
        )

        with self.assertRaisesRegex(RuntimeError, "cannot be combined"):
            create_collector(args, SampleFilter())

    def test_channel_dry_run_loads_one_url_per_unit(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            unit = Path(raw_dir) / "channel-a.service"
            unit.write_text(
                "[Service]\nEnvironment=URL=https://api.example.com/foo\n",
                encoding="utf-8",
            )
            args = self.parser.parse_args(
                [
                    "run-channels",
                    "--collector",
                    "dry-run",
                    "--no-default-unit-dirs",
                    "--no-resolve-dns",
                    "--unit-file",
                    str(unit),
                ]
            )

            collector = create_channel_collector(args, ChannelSampleFilter())

        self.assertIsInstance(collector, TcpChannelDryRunCollector)
        self.assertEqual(collector.catalog.targets[0].unit, "channel-a.service")
        self.assertEqual(
            collector.catalog.targets[0].url,
            "https://api.example.com/foo",
        )


if __name__ == "__main__":
    unittest.main()
