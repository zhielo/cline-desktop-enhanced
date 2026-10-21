"""CI diagnostic parser regression tests (standard library only)."""
import importlib.util
from pathlib import Path
import tempfile
import subprocess
import sys
import os
import unittest

spec = importlib.util.spec_from_file_location("summary", Path(__file__).with_name("summarize-semantic-tests.py"))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


class DiagnosticsTests(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "result.xml"
            path.write_text(text, encoding="utf-8")
            return summary.summarize(path)

    def test_pass(self):
        self.assertEqual(self.parse('<testsuites><testsuite failures="0"><testcase name="a"/></testsuite></testsuites>'), (1, []))

    def test_failure_and_error(self):
        count, problems = self.parse('<testsuites><testsuite><testcase classname="owned" name="a"><failure>expected &lt;value&gt;\nreceived</failure></testcase><testcase name="b"><error message="startup"/></testcase></testsuite></testsuites>')
        self.assertEqual(count, 2)
        self.assertIn('expected <value>\nreceived', problems[0])
        self.assertIn('startup', problems[1])

    def test_cdata_and_bounds(self):
        _, problems = self.parse('<testsuites><testsuite><testcase><failure><![CDATA[' + ('x' * 9000) + ']]></failure></testcase></testsuite></testsuites>')
        self.assertEqual(len(problems[0]), 6000)

    def test_missing_cases_and_malformed_and_declarations(self):
        for text in ['<testsuites/>', '<broken', '<!DOCTYPE a><testsuite/>', '<testsuites><testsuite failures="1"><testcase/></testsuite></testsuites>']:
            with self.assertRaises(Exception):
                self.parse(text)

    def test_windows_console_encoding(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "result.xml"
            path.write_text('<testsuites><testsuite failures="1"><testcase name="owned"><failure>expected → actual ⎯</failure></testcase></testsuite></testsuites>', encoding="utf-8")
            result = subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("summarize-semantic-tests.py")), str(path)], env={**os.environ, "PYTHONIOENCODING": "cp1252"}, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("::error title=Semantic regression failure::", result.stdout.decode("utf-8"))
            self.assertIn("expected → actual ⎯", result.stdout.decode("utf-8"))

    def test_annotation_escape(self):
        self.assertEqual(summary.escape('a%\r\n::error::'), 'a%25%0D%0A::error::')


if __name__ == '__main__':
    unittest.main()
