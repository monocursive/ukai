import unittest
from slug import slugify


class SlugTests(unittest.TestCase):
    def test_case(self):
        self.assertEqual(slugify("Hello World"), "hello-world")

    def test_spaces(self):
        self.assertEqual(slugify("  Ship   It  "), "ship-it")

    def test_numbers(self):
        self.assertEqual(slugify("top 10 tips"), "top-10-tips")


if __name__ == "__main__":
    unittest.main()
