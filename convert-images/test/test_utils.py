import logging
import shutil
import tempfile
import unittest
from pathlib import Path

from pillow_heif import register_heif_opener

from utils import IMAGE_EXTENSIONS_READ, IMAGE_EXTENSIONS_WRITE, convert_image

logger = logging.getLogger(__name__)

register_heif_opener()


class TestImageConversion(unittest.TestCase):
    def setUp(self):
        self.tmp_files = Path(tempfile.mkdtemp())
        self.test_files = Path("testfiles")

    def tearDown(self):
        shutil.rmtree(self.tmp_files)

    def test_convert_png_to_all_writable_formats(self):
        src = self.test_files / "dobatymo.png"
        for ext in IMAGE_EXTENSIONS_WRITE:
            dest = self.tmp_files / f"converted{ext}"
            convert_image(src, dest)

            self.assertTrue(dest.exists())

    def test_convert_folder_to_jpg(self):
        for ext in IMAGE_EXTENSIONS_READ:
            src = self.test_files / f"dobatymo{ext}"

            if not src.exists():
                logger.warning("Skipping %s", src)
                continue

            dest = self.tmp_files / src.with_suffix(".jpg").name
            convert_image(src, dest)

            self.assertTrue(dest.exists())
