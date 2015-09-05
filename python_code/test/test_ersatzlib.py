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
        
    def test_pbkdf2_sha256(self):
        logging.info("---===test_pbkdf2_sha256===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.pbkdf2_sha256, user, realPW, ersatzPW)
        self.verify_test(erh)
        logging.info("Passed!")

    def test_pbkdf2_sha512(self):
        logging.info("---===test_pbkdf2_sha512===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.pbkdf2_sha512, user, realPW, ersatzPW)
        self.verify_test(erh)
        logging.info("Passed!")
        
    def test_ldap_salted_sha1(self):
        logging.info("---===test_ldap_salted_sha1===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_salted_sha1, user, realPW, ersatzPW)
        self.verify_test(erh)
        logging.info("Passed!")
        
    def test_ldap_salted_md5(self):
        logging.info("---===test_ldap_salted_md5===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_salted_md5, user, realPW, ersatzPW)
        self.verify_test(erh)
        logging.info("Passed!")
        
    def test_ldap_ldap_sha512_crypt(self):
        logging.info("---===test_ldap_ldap_sha512_crypt===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_sha512_crypt, user, realPW, ersatzPW)
        self.verify_test(erh)
        logging.info("Passed!")
        
        
if __name__ == '__main__':
    unittest.main()