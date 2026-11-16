import unittest

from slug import slugify


class SlugifyTest(unittest.TestCase):
    def test_lower_case_words(self):
        self.assertEqual(slugify("hello world"), "hello-world")

    def test_capitals_are_lowered(self):
        self.assertEqual(slugify("Hello World"), "hello-world")

    def test_punctuation_separates_words(self):
        self.assertEqual(slugify("Ukai, the Jail: v1!"), "ukai-the-jail-v1")


if __name__ == "__main__":
    unittest.main()
