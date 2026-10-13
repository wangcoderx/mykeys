#!/usr/bin/env python3
"""Build a macOS .icns with platform-appropriate optical padding."""

from pathlib import Path
import shutil
import subprocess
import tempfile

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "设计方案/icons/mykeys-logo-v2.png"
MASTER = ROOT / "设计方案/icons/icon-macos-1024.png"
OUTPUT = ROOT / "设计方案/icons/icon-macos.icns"

CANVAS_SIZE = 1024
ARTWORK_SIZE = 824
ALPHA_CROP_THRESHOLD = 64


def crop_transparent_margin(source: Image.Image) -> Image.Image:
    """Crop faint export padding while keeping the artwork centered and square."""
    alpha = source.getchannel("A")
    solid_alpha = alpha.point(
        lambda value: 255 if value >= ALPHA_CROP_THRESHOLD else 0
    )
    bounds = solid_alpha.getbbox()
    if bounds is None:
        raise ValueError("Icon source contains no visible artwork")

    left, top, right, bottom = bounds
    side = max(right - left, bottom - top)
    center_x = (left + right) / 2
    center_y = (top + bottom) / 2
    crop_left = round(center_x - side / 2)
    crop_top = round(center_y - side / 2)
    return source.crop((crop_left, crop_top, crop_left + side, crop_top + side))


def main() -> None:
    source = Image.open(SOURCE).convert("RGBA")
    cropped_source = crop_transparent_margin(source)
    artwork = cropped_source.resize(
        (ARTWORK_SIZE, ARTWORK_SIZE), Image.Resampling.LANCZOS
    )
    master = Image.new("RGBA", (CANVAS_SIZE, CANVAS_SIZE), (0, 0, 0, 0))
    inset = (CANVAS_SIZE - ARTWORK_SIZE) // 2
    master.alpha_composite(artwork, (inset, inset))
    master.save(MASTER, optimize=True)

    with tempfile.TemporaryDirectory(prefix="mykeys-icon-") as temp_dir:
        generated = Path(temp_dir) / "generated"
        subprocess.run(
            [
                "cargo",
                "tauri",
                "icon",
                str(MASTER),
                "--output",
                str(generated),
            ],
            cwd=ROOT,
            check=True,
        )
        shutil.copyfile(generated / "icon.icns", OUTPUT)

    print(f"Created {MASTER}")
    print(f"Created {OUTPUT}")


if __name__ == "__main__":
    main()
