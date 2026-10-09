from pathlib import Path
import json
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import build_chatgpt_plugin as package


class PackageTests(unittest.TestCase):
    def test_archive_is_self_contained_and_has_no_local_credentials_or_runtimes(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'plugin.zip'
            package.build(target)
            with zipfile.ZipFile(target) as archive:
                self.assertIsNone(archive.testzip())
                names = set(archive.namelist())
                manifest = json.loads(archive.read('plugin.json'))
                self.assertIn(manifest['extensions']['com.openai']['onboardingSkill'][2:], names)
                self.assertIn('skills/instagram-content-editor/references/evaluation.md', names)
                self.assertFalse(any(name.endswith('.py') or '.env' in name or '.git/' in name for name in names))
                self.assertNotIn('mcp.json', names)
                self.assertNotIn('mcpServers', manifest)
                # Every local Markdown reference and manifest asset is checked by package_files.
                self.assertEqual(names, set(package.package_files()))

    def test_build_is_reproducible(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b = Path(temp) / 'a.zip', Path(temp) / 'b.zip'
            package.build(a)
            package.build(b)
            self.assertEqual(a.read_bytes(), b.read_bytes())


if __name__ == '__main__':
    unittest.main()
