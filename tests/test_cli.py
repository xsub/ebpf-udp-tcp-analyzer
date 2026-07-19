import unittest
from unittest import mock

from udp_analyzer.cli import build_parser, create_collector
from udp_analyzer.models import SampleFilter


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


if __name__ == "__main__":
    unittest.main()
