import unittest, sys, logging, ersatzlib
from passlib import hash
import timeit
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

user="chris"
realPW = "123456"
ersatzPW = "ersatz"
hashRounds = 5000 #default for crypt
class Test_ersatzLib(unittest.TestCase):
    
    def verify_test(self, erh):
        self.assertEqual(erh.verify(realPW), "True Password")
        self.assertEqual(erh.verify(ersatzPW), "Ersatz password")
        self.assertEqual(erh.verify("false"), "Incorrect Password")

    ##PBKDF2
    def _test_pbkdf2_sha1(self):
        logging.info("---===test_pbkdf2_sha1===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.pbkdf2_sha1, user, realPW, ersatzPW, rounds=hashRounds)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")

    def _test_pbkdf2_sha256(self):
        logging.info("---===test_pbkdf2_sha256===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.pbkdf2_sha256, user, realPW, ersatzPW, rounds=hashRounds)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")

    def test_pbkdf2_sha512(self):
        logging.info("---===test_pbkdf2_sha512===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.pbkdf2_sha512, user, realPW, ersatzPW, rounds=hashRounds)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")
        
    ##SALTED LDAP HASHES
    def test_ldap_salted_md5(self):
        logging.info("---===test_ldap_salted_md5===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_salted_md5, user, realPW, ersatzPW)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")

    def test_ldap_salted_sha1(self):
        logging.info("---===test_ldap_salted_sha1===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_salted_sha1, user, realPW, ersatzPW)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")

    def test_ldap_sha1_crypt(self):
        logging.info("---===test_ldap_sha1_crypt===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_sha1_crypt, user, realPW, ersatzPW, rounds=hashRounds)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")
        
    def test_ldap_sha256_crypt(self):
        logging.info("---===test_ldap_sha256_crypt===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_sha256_crypt, user, realPW, ersatzPW, rounds=hashRounds)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")

    def test_ldap_sha512_crypt(self):
        logging.info("---===test_ldap_sha512_crypt===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.ldap_sha512_crypt, user, realPW, ersatzPW, rounds=hashRounds)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")
    
    ##SALTED CRYPT
    def test_md5_crypt(self):
        logging.info("---===test_md5_crypt===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.md5_crypt, user, realPW, ersatzPW)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")

    def test_sha1_crypt(self):
        logging.info("---===test_sha1_crypt===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.sha1_crypt, user, realPW, ersatzPW, rounds=hashRounds)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")
        
    def test_sha256_crypt(self):
        logging.info("---===test_sha256_crypt===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.sha256_crypt, user, realPW, ersatzPW, rounds=hashRounds)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")

    def test_sha512_crypt(self):
        logging.info("---===test_sha512_crypt===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.sha512_crypt, user, realPW, ersatzPW, relaxed=True, rounds=hashRounds)
        erh.initSaltHash()
        self.verify_test(erh)
        print erh.hash
        logging.info("Passed!")
        
        
    def test_multithreaded(self):
        logging.info("---===test_multithreaded===--")
        erh = ersatzlib.ErsatzHashGenerator(hash.sha1_crypt, user, realPW, ersatzPW, rounds=hashRounds)
        erh.initSaltHash()
        start = timeit.default_timer()
        erh.multithreaded_verify(realPW)
        stop = timeit.default_timer()
        print stop - start
        
        start  = timeit.default_timer()
        erh.verify(realPW)
        stop = timeit.default_timer()
        print stop - start

        logging.info("Passed!")
                
if __name__ == '__main__':
    unittest.main()