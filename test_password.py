import unittest
from main import generate_password, assess_strength, generate_mnemonic_password

class TestPasswordFunctions(unittest.TestCase):

    def test_generate_password_length(self):
        """تأكد إن طول كلمة المرور مطابق للطلب"""
        pwd = generate_password(12)
        self.assertEqual(len(pwd), 12)

    def test_generate_password_has_symbols(self):
        """تأكد أن كلمة المرور تحتوي على رموز عند التفعيل"""
        pwd = generate_password(10, include_symbols=True)
        self.assertTrue(any(c in "!@#$%^&*()-_+=" for c in pwd))

    def test_mnemonic_password_format(self):
        """تأكد أن كلمة المرور السهلة تحتوي على كلمات مفهومة"""
        pwd = generate_mnemonic_password()
        self.assertTrue(any(word in pwd for word in ["Tiger", "Coffee", "Rain", "Planet", "Sky", "Moon", "Ocean", "Stone"]))

    def test_assess_strength_output(self):
        """تأكد أن تقييم القوة يرجع نجومًا وعددًا صحيحًا منها"""
        stars, tips = assess_strength("Abc123!@#")
        self.assertEqual(len(stars), 5)
        self.assertTrue("★" in stars)

if __name__ == '__main__':
    unittest.main()
