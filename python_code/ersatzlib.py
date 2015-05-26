import pyhsm, hashlib, base64, collections, logging, sys

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

hsm = pyhsm.base.YHSM(device='/dev/cuaU0', debug=False)
hsm.unlock(password='')
key_handler = 0x1

test_user_password = 'password12345'

test_password = "test123"
test_salt     = "thisisreally"
test_ersatz   = "0123456789ab"

PASSWORD_CORRECT = 0
PASSWORD_INCORRECT = 1
PASSWORD_ERSATZ = 2

def hash(input_val):
	#input should be a string
	return base64.b64encode(hashlib.sha512(input_val).digest())

def hdf(input_val):
	return b64e(hsm.hmac_sha1(key_handler, input_val).execute().get_hash())

def b64e(input_val):
	return base64.b64encode(input_val)

def b64d(input_val):
	return base64.b64decode(input_val)

def sxor(str1, str2):
	#pad if they are not the same length
	if len(str1) > len(str2):
		str2 = str2 + ((len(str1)-len(str2))*'0')
	else:
		str1 = str1 + ((len(str2)-len(str1))*'0')
	#xor two strings, code based on Mark Byers posted on stack overflow
	return ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(str1, str2))

def sys_init(old_hash, old_salt):
	#get the old password hash and pass it through the HDF. Store the new hash.
	#e.g. let \alpha be the old password hash. then
	#		new_hash = hash( HDF(old_hash) || old_salt)
	#		Store <new_hash, old_salt>
	hdf_hash = hdf(old_hash)
	new_hash = hash(hdf_hash +old_salt)
	logging.debug('New hash: %s (%i)', new_hash, len(new_hash))
	return collections.namedtuple('PWEntry',['salt','hash'])

def compute_ersatz_salt(password, ersatz_pw):
	#should be in plain text, no b64encoding
	return b64e(sxor(hdf(password), encode_ersatz_pw(ersatz_pw)))#[0:16]

def compute_ersatz_hash(password, salt):
	return hash(sxor(hdf(password), b64d(salt))[0:16] + salt)

def encode_ersatz_pw(password):
	assert len(password) <= 12
	encoded_ersatz = b64e(password + " "*(12-len(password)))
	assert len(encoded_ersatz) == 16
	return encoded_ersatz

def first_login(password, ersatz_pw):
	#input is in plaintext
	updated_salt = compute_ersatz_salt(password, ersatz_pw)
	logging.debug("Salt'  : %s (%i)", updated_salt, len(updated_salt))
	updated_hash = compute_ersatz_hash(password, updated_salt)
	logging.debug("Hash'  : %s (%i)", updated_hash, len(updated_hash))
	#print "debug: " + b64e(sxor(hdf(password)[0:16], b64d(updated_salt))) + updated_salt

	logging.debug("%s == %s", sxor(hdf(password), b64d(updated_salt))[0:16], encode_ersatz_pw(ersatz_pw))
	PWErsatz = collections.namedtuple('PWErsatz', ["salt_prime", "hash_prime"])
	return PWErsatz(updated_salt, updated_hash)

def verify_ersatz_login(password, PWErsatz):
	#canidate =  hash(sxor(b64d(hdf(password)), b64d(PWErsatz.salt_prime)) + PWErsatz.salt_prime)
	canidate =  compute_ersatz_hash(password, PWErsatz.salt_prime)
	if canidate == PWErsatz.hash_prime:
		logging.info("Password correct!")
		return PASSWORD_CORRECT
	elif hash(encode_ersatz_pw(password) + PWErsatz.salt_prime) == PWErsatz.hash_prime:
		logging.info("Ersatz password!")
		return PASSWORD_ERSATZ
	else:
		logging.info("Incorrect password!")
		return PASSWORD_INCORRECT

def main():
	test_old_salt = b64e(test_salt)
	test_old_hash = hash(test_password + test_salt)
	print 'Password: %s' % test_password
	print 'Hash: %s (%i)' %  (test_old_hash, len(test_old_hash))
	print 'Salt: %s (%i)' % (test_old_salt, len(test_old_salt))

	updatedPWEntry = sys_init(test_old_salt, test_old_hash)
	print 'First log in'
	PWErsatzEntry = first_login(test_password, test_ersatz)
	verify_ersatz_login(test_password, PWErsatzEntry)
	verify_ersatz_login(test_ersatz, PWErsatzEntry)
	verify_ersatz_login("incorrect", PWErsatzEntry)

	logging.basicConfig(stream=sys.stderr, level=logging.INFO)
	print 'Testing: pw len 1-64'
	longPW = 'abcdefghijklmnopqrstuvwxyz01234567890!@#$%^&*()_+{}|:"<>?'
	for l in range(1,64):
		print "\tpw = '%s' (%i)" %(longPW[0:l], l)
		PWErsatzEntry = first_login(longPW[0:l], test_ersatz)

		ret = verify_ersatz_login(longPW[0:l], PWErsatzEntry)
		assert ret == PASSWORD_CORRECT
		ret = verify_ersatz_login(test_ersatz, PWErsatzEntry)
		assert ret == PASSWORD_ERSATZ
		ret = verify_ersatz_login("incorrect", PWErsatzEntry)
		assert ret == PASSWORD_INCORRECT

	longErsatz = 'abcdefghijklmnopqrstuvwxyz01234567890!@#$%^&*()_+{}|:"<>?'
	print 'Testing: Ersatz len'
	for l in range(1,64):
		print "\tersatz = '%s' (%i)" %(longErsatz[0:l], l)
		PWErsatzEntry = first_login(test_password, longErsatz[0:l])
		ret = verify_ersatz_login(test_password, PWErsatzEntry)
		assert ret == PASSWORD_CORRECT
		ret = verify_ersatz_login(longErsatz[0:l], PWErsatzEntry)
		assert ret == PASSWORD_ERSATZ
		ret = verify_ersatz_login("incorrect", PWErsatzEntry)
		assert ret == PASSWORD_INCORRECT


if __name__ == "__main__":
	main()
