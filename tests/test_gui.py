import unittest
from pathlib import Path


class TestGUIAssetsAndPackaging(unittest.TestCase):
    def test_gui_theme_and_packaging_assets_exist(self):
        root = Path(__file__).resolve().parent.parent
        self.assertTrue((root / "gui" / "styles" / "dark.qss").exists())
        self.assertTrue((root / "gui" / "styles" / "icons" / "anonx.svg").exists())
        self.assertTrue((root / "packaging" / "anonx.desktop").exists())
        self.assertTrue((root / "packaging" / "anonx.svg").exists())

        desktop = (root / "packaging" / "anonx.desktop").read_text(encoding="utf-8")
        self.assertIn("Exec=/usr/local/bin/anonx-gui", desktop)
        self.assertIn("Terminal=false", desktop)


if __name__ == "__main__":
    unittest.main()
