
from mbedtls import cipher as mbedcipher
from unicrypto.symmetric import symmetricBASE, cipherMODE

class AES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, segment_size = 128):
		self.ctrint = None
		self.ctrlen = None
		symmetricBASE.__init__(self, key, mode, IV, segment_size=segment_size)

	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_ECB, b'')
		elif self.mode == cipherMODE.CBC:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CBC, self.IV)
		elif self.mode == cipherMODE.CTR:
			self.ctrlen = len(self.IV)
			self.ctrint = int.from_bytes(self.IV, byteorder = 'big', signed= False)
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CTR, self.IV)
		elif self.mode == cipherMODE.OFB:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_OFB, self.IV)
		elif self.mode == cipherMODE.CFB:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CFB, self.IV)
		else:
			raise Exception('Unknown cipher mode!')
		self._cipher.set_padding_mode(4)
		
	def encrypt(self, data):
		res = self._cipher.encrypt(data)
		if self.mode == cipherMODE.CBC:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CBC, res)
		elif self.mode == cipherMODE.CFB:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CFB, res)
		elif self.mode == cipherMODE.OFB:
			shouldntbedoingthis = bytes(res ^ data for (res, data) in zip(res, data))
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_OFB, shouldntbedoingthis)
		elif self.mode == cipherMODE.CTR:
			self.ctrint += 1
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CFB, self.ctrint.to_bytes(self.ctrlen, byteorder='big', signed = False))
		self._cipher.set_padding_mode(4)

		return res
	def decrypt(self, data):
		res = self._cipher.decrypt(data)
		if self.mode == cipherMODE.CBC:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CBC, data)
		elif self.mode == cipherMODE.CFB:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CFB, data)
		elif self.mode == cipherMODE.OFB:
			shouldntbedoingthis = bytes(res ^ data for (res, data) in zip(res, data))
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_OFB, shouldntbedoingthis)
		elif self.mode == cipherMODE.CTR:
			self.ctrint += 1
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CFB, self.ctrint.to_bytes(self.ctrlen, byteorder='big', signed = False))
		self._cipher.set_padding_mode(4)

		return res