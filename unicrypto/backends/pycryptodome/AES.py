
from Cryptodome.Cipher import AES as _pyCryptodomeAES
from Cryptodome.Util import Counter
from unicrypto.symmetric import symmetricBASE, cipherMODE

class AES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, segment_size = 128):
		symmetricBASE.__init__(self, key, mode, IV, segment_size=segment_size)

	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = _pyCryptodomeAES.new(self.key, _pyCryptodomeAES.MODE_ECB) #_pyCryptodomeDES.new(self.key, _pyCryptodomeDES.MODE_ECB)
		elif self.mode == cipherMODE.CBC:
			self._cipher = _pyCryptodomeAES.new(self.key, _pyCryptodomeAES.MODE_CBC, iv=self.IV)
		elif self.mode == cipherMODE.CTR:
			self._cipher = _pyCryptodomeAES.new(self.key, _pyCryptodomeAES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(self.IV, byteorder='big', signed=False)))
		elif self.mode == cipherMODE.CFB:
			self._cipher = _pyCryptodomeAES.new(self.key, _pyCryptodomeAES.MODE_CFB, iv=self.IV, segment_size=self.segment_size)
		elif self.mode == cipherMODE.OFB:
			self._cipher = _pyCryptodomeAES.new(self.key, _pyCryptodomeAES.MODE_OFB, iv=self.IV)
		else:
			raise Exception('Unknown cipher mode!')
		
	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)