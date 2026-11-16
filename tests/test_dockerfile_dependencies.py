import pathlib
import re
import unittest


class DockerfileDependencyTests(unittest.TestCase):
    def test_panel_image_contains_acme_runtime_dependencies(self):
        dockerfile = (pathlib.Path(__file__).resolve().parents[1] / 'Dockerfile').read_text(
            encoding='utf-8')
        install = re.search(r'apt-get install[^;\n]*(?:\\\n[^;\n]*)*', dockerfile)
        self.assertIsNotNone(install, 'Dockerfile must install acme.sh runtime dependencies')
        packages = set(re.findall(r'(?<![\w-])[a-z0-9][a-z0-9+.-]*(?![\w-])', install.group()))
        self.assertIn('curl', packages)
        self.assertIn('cron', packages)


if __name__ == '__main__':
    unittest.main()
