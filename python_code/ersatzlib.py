import pyhsm

from passlib.utils import ab64_encode, ab64_decode
from multiprocessing.pool import Pool

def _multithreaded_helper(inputDict):
	try: 
		if inputDict["hashFunc"].verify(inputDict["inPassword"], inputDict["hashDigest"]):
			return True
		else:
			return False
	except:
		return False

class ErsatzHashGenerator():
	spacer = '|' # placed in between username and password in HSM
	def __init__(self,hashFunc, username, password, ersatzPassword, \
				dev='/dev/tty.usbmodemfd1231', hsmPassword='', \
				hsm_key_handler=0x1, salt_len=16, **kwargs):
		
		'''
			Inits the hash to be used in creating ersatz password hashes
			Inputs
				hashFunc - a function to be used in hashing.
		'''
		#assert hasattr(hash,hashFunc)
		assert (len(password) + 1) < salt_len
		assert (len(ersatzPassword) + 1) < salt_len
		self.hashFunc = hashFunc
		self._saltLen = salt_len
		assert self.spacer not in password and self.spacer not in username
		self.password = password
		self._username = username
		self.ersatzPassword = ersatzPassword
		
		self._hashKwargs = kwargs
		
		self._hsm = pyhsm.base.YHSM(device=dev, debug=False)
		self._hsm.unlock(password=hsmPassword)
		self._key_handler = hsm_key_handler
		self.saltString = True
		self._saltLen = 12
		self.salt = self._compute_ersatz_salt(self.password, ersatzPassword)
		self.hash = self._compute_ersatz_hash(self.password)
		
	def verify(self, inPassword):
		try: 
			if self.hashFunc.verify(self._ersatzfy_input(inPassword), self.hash):
				return "True Password"
			elif self.hashFunc.verify(inPassword, self.hash):
				return "Ersatz password"
			else:
				return "Incorrect Password"
		#hack hack hack - fix this 
		except:
			if self.hashFunc.verify(inPassword, self.hash):
				return "Ersatz password"
			else:
				return "Incorrect Password"
			

		
	def multithreaded_verify(self, inPassword):
		validCheck = self._ersatzfy_input(inPassword)
		ersatzCheck = inPassword
		
		p = Pool(processes=2)
		validCheckDic = {"inPassword":validCheck, "hashFunc":self.hashFunc, "hashDigest":self.hash}
		ersatzCheckDic = {"inPassword":ersatzCheck, "hashFunc":self.hashFunc, "hashDigest":self.hash}
		
		inputs = [validCheckDic, ersatzCheckDic]
		result = p.map(_multithreaded_helper, inputs)
		p.close()
		p.join()
		
		if result[0]:
			return "True Password"
		elif result[1]:
			return "Ersatz password"
		else:
			return "Incorrect Password"

		
	def _formatPassword(self,password):
		'''
			Forces the ersatz password to be length 12. 
				Inputs:
					password - (str) True user password
					username - (str) name of usr (duh)
				NOTE: the spacer cannot be in password and username
		'''
		totalLen = len(password) + len(self._username) + 1
		assert totalLen <= self._saltLen
		return password + self.spacer + self._username
	
	def _ersatzfy_input(self, inPassword):
		return self._sxor(self._hdf(self._formatPassword(inPassword)),\
							 ab64_decode(self.salt))[0:len(self.ersatzPassword)]

	def _compute_ersatz_salt(self, password, ersatz_password):
		'''
			Creates a ersatz salt
			Inputs
				password - True user password
				ersatz_pw- Fake user password
			todo: remove the array cut 
		'''
		return ab64_encode(self._sxor(self._hdf(self._formatPassword(password)),\
						 ersatz_password)[0:self._saltLen])

	
	def _compute_ersatz_hash(self, inPassword):
		'''
			Creates a ersatz hash
			Inputs
				password  	- (str) True user password
				salt 		- (str) Fake user password
		'''
		return self.hashFunc.encrypt(self._ersatzfy_input(inPassword), salt=self.salt, **self._hashKwargs)

	#helper functions
	def _sxor(self,str1, str2):
		#pad if they are not the same length
		if len(str1) > len(str2):
			str2 = str2 + ((len(str1)-len(str2))*'')
		else:
			str1 = str1 + ((len(str2)-len(str1))*'')
		#xor two strings, code based on Mark Byers posted on stack overflow
		return ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(str1, str2))

	
	def _hdf(self,input_val):
		return self._hsm.hmac_sha1(self._key_handler, input_val).execute().get_hash()
	
