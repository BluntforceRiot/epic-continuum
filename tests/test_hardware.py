from __future__ import annotations

import unittest
from unittest.mock import patch

from continuum.core import hardware


class EpicContinuumHardwareTest(unittest.TestCase):
    def test_vram_detection_falls_back_after_nvidia_probe(self) -> None:
        with (
            patch("continuum.core.hardware._detect_nvidia_vram_bytes", return_value=(None, "nvidia unavailable")),
            patch("continuum.core.hardware._detect_amd_vram_bytes", return_value=(16 * hardware.GB, "rocm-smi max_gpu_memory")),
            patch("continuum.core.hardware._detect_macos_vram_bytes", return_value=(None, "not macOS")),
            patch.dict("os.environ", {}, clear=True),
        ):
            value, source = hardware.detect_vram_bytes()

        self.assertEqual(value, 16 * hardware.GB)
        self.assertEqual(source, "rocm-smi max_gpu_memory")

    def test_macos_unified_memory_probe_uses_system_ram_on_apple_silicon(self) -> None:
        with (
            patch("continuum.core.hardware.platform.system", return_value="Darwin"),
            patch("continuum.core.hardware.platform.machine", return_value="arm64"),
            patch("continuum.core.hardware.subprocess.run", side_effect=FileNotFoundError),
            patch("continuum.core.hardware.detect_system_ram_bytes", return_value=(32 * hardware.GB, "sysctl hw.memsize")),
        ):
            value, source = hardware._detect_macos_vram_bytes()

        self.assertEqual(value, 32 * hardware.GB)
        self.assertIn("apple_unified_memory", source)

    def test_rocm_memory_parser_accepts_units_and_bytes(self) -> None:
        values = hardware._parse_memory_tokens(
            "VRAM Total Memory (B): 17179869184\nGPU[0] VRAM Total Memory: 16 GiB\n"
        )

        self.assertIn(17179869184, values)
        self.assertIn(16 * hardware.GB, values)


if __name__ == "__main__":
    unittest.main()
