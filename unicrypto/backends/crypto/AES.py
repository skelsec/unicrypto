
from Crypto.Cipher import AES as _pyCryptoAES
from Crypto.Util import Counter
from unicrypto.symmetric import symmetricBASE, cipherMODE

class AES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, segment_size = 8):
		symmetricBASE.__init__(self, key, mode, IV, segment_size = segment_size)
		
	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = _pyCryptoAES.new(self.key, _pyCryptoAES.MODE_ECB)
		elif self.mode == cipherMODE.CBC:
			self._cipher = _pyCryptoAES.new(self.key, _pyCryptoAES.MODE_CBC, self.IV)
		elif self.mode == cipherMODE.CTR:
			self._cipher = _pyCryptoAES.new(self.key, _pyCryptoAES.MODE_CTR, self.IV, counter=Counter.new(128, initial_value=int.from_bytes(self.IV, byteorder='big', signed=False)))
		elif self.mode == cipherMODE.CFB:
			self._cipher = _pyCryptoAES.new(self.key, _pyCryptoAES.MODE_CFB, self.IV, segment_size=self.segment_size)
		elif self.mode == cipherMODE.OFB:
			self._cipher = _pyCryptoAES.new(self.key, _pyCryptoAES.MODE_OFB, self.IV)
		else:
			raise Exception('Unknown cipher mode!')
		
	def encrypt(self, data):
		if (self.mode == cipherMODE.CFB or  self.mode == cipherMODE.OFB) and (self._cipher.block_size - len(data) % self._cipher.block_size) % self._cipher.block_size != 0:
			padding_length = (self._cipher.block_size - len(data) % self._cipher.block_size) % self._cipher.block_size
			padded_data = data + b'\x00'*padding_length
			enc_data = self._cipher.encrypt(padded_data)
			return enc_data[:len(data)]
		return self._cipher.encrypt(data)
	
	def decrypt(self, data):
		if (self.mode == cipherMODE.CFB or  self.mode == cipherMODE.OFB) and (self._cipher.block_size - len(data) % self._cipher.block_size) % self._cipher.block_size != 0:
			padding_length = (self._cipher.block_size - len(data) % self._cipher.block_size) % self._cipher.block_size
			padded_data = data + b'\x00'*padding_length
			enc_data = self._cipher.decrypt(padded_data)
			return enc_data[:len(data)]
		return self._cipher.decrypt(data)