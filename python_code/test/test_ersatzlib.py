import unittest, sys, logging, ersatzlib
from passlib import hash
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

user="chris"
realPW = "test"
ersatzPW = "123451"
class Test_ersatzLib(unittest.TestCase):
    
    def verify_test(self, erh):
        self.assertEqual(erh.verify(realPW), "True Password")
        self.assertEqual(erh.verify(ersatzPW), "Ersatz password")
        self.assertEqual(erh.verify("false"), "Incorrect Password")
        
    def _test_pbkdf2_sha256(self):
        logging.info("---===test_pbkdf2_sha256===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.pbkdf2_sha256, user, realPW, ersatzPW)
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")

    def test_pbkdf2_sha512(self):
        logging.info("---===test_pbkdf2_sha512===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.pbkdf2_sha512, user, realPW, ersatzPW)
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")
        
    def test_ldap_salted_md5(self):
        logging.info("---===test_ldap_salted_md5===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_salted_md5, user, realPW, ersatzPW)
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")

    def test_ldap_sha1_crypt(self):
        logging.info("---===test_ldap_sha1_crypt===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_sha1_crypt, user, realPW, ersatzPW)
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")
        
    def test_ldap_sha256_crypt(self):
        logging.info("---===test_ldap_sha256_crypt===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_sha1_crypt, user, realPW, ersatzPW)
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")

    def test_ldap_sha512_crypt(self):
        logging.info("---===test_ldap_sha512_crypt===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_sha512_crypt, user, realPW, ersatzPW)
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")
         
if __name__ == '__main__':
    unittest.main()