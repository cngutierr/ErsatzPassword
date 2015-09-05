import unittest,ersatzlib
from passlib import hash

class Test_ersatzLib(unittest.TestCase):

    def test_init_ersatzlib(self):
        erh = ersatzlib.ErsatzHashGenerator(hash.pbkdf2_sha256,"chris", "real", "fake")
        
    def test_ldap_salted_sha1(self):
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_salted_sha1,"chris", "real", "fake")
        self.assertEqual(erh.verify("real"), "True Password")
        self.assertEqual(erh.verify("fake"), "Ersatz password")
if __name__ == '__main__':
    unittest.main()