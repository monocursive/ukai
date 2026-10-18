import unittest

from slug import slugify


class TestSlugify(unittest.TestCase):
    def test_lowercases(self):
        self.assertEqual(slugify("Hello World"), "hello-world")

    def test_collapses_separators(self):
        self.assertEqual(slugify("  Multiple   Spaces "), "multiple-spaces")

    def test_empty(self):
        self.assertEqual(slugify(""), "")


if __name__ == "__main__":
    unittest.main()
