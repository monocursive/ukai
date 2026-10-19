import unittest

from slug import slugify


class SlugifyTest(unittest.TestCase):
    def test_lowercase(self):
        self.assertEqual(slugify("Hello World"), "hello-world")

    def test_punctuation(self):
        self.assertEqual(slugify("Ready, set... go!"), "ready-set-go")

    def test_numbers(self):
        self.assertEqual(slugify("Top 10 Tips"), "top-10-tips")


if __name__ == "__main__":
    unittest.main()
