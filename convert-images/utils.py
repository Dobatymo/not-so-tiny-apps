import logging
from pathlib import Path

from PIL import Image
from PIL.Image import registered_extensions

logger = logging.getLogger(__name__)

IMAGE_EXTENSIONS = [
    ".jpg",
    ".jpeg",
    ".png",
    ".bmp",
    ".gif",
    ".tiff",
    ".tif",
    ".webp",
    ".heic",
    ".avif",
    ".dds",
    ".icns",
    ".ico",
    ".jp2",
    ".jpx",
    ".tga",
]
IMAGE_EXTENSIONS_READ = IMAGE_EXTENSIONS + [".psd"]
IMAGE_EXTENSIONS_WRITE = IMAGE_EXTENSIONS + [".pdf"]

unsupported_modes_format = {
    "JPEG": ("RGBA",),
}


def convert_image(src: Path, dest: Path) -> bool:
    extensions = registered_extensions()
    dest_format = extensions[dest.suffix]
    unsupported_modes = unsupported_modes_format.get(dest_format, ())
    fallback = "RGB"
    assert fallback not in unsupported_modes

    with Image.open(src) as img:
        if img.mode in unsupported_modes:
            img = img.convert(fallback)
            logger.warning("Format %s doesn't support mode %s, converting to %s", dest_format, img.mode, fallback)
        img.save(dest)
