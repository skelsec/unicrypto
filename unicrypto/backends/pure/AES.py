import io
from unicrypto.symmetric import symmetricBASE, cipherMODE
from unicrypto.backends.pure.external.AES import AESModeOfOperationCBC,\
    AESModeOfOperationECB, AESModeOfOperationCTR, AESModeOfOperationCFB,\
	AESModeOfOperationOFB, encrypt_stream, decrypt_stream, PADDING_NONE, Counter

class AES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, segment_size = 8):
		symmetricBASE.__init__(self, key, mode, IV, segment_size=segment_size)

	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = AESModeOfOperationECB(self.key)
		elif self.mode == cipherMODE.CBC:
			self._cipher = AESModeOfOperationCBC(self.key, iv = self.IV)
		elif self.mode == cipherMODE.CTR:
			self._cipher = AESModeOfOperationCTR(self.key, counter = Counter(int.from_bytes(self.IV, byteorder='big', signed=False)))
		elif self.mode == cipherMODE.CFB:
			self._cipher = AESModeOfOperationCFB(self.key, iv = self.IV, segment_size = self.segment_size//8)
		elif self.mode == cipherMODE.OFB:
			self._cipher = AESModeOfOperationOFB(self.key, iv = self.IV)
		else:
			raise Exception('Unknown cipher mode!')

	def encrypt(self, data):
		if self.mode != cipherMODE.CFB:
			in_buff = io.BytesIO(data)
			out_buff = io.BytesIO()
			encrypt_stream(self._cipher, in_buff, out_buff, padding = PADDING_NONE)
			out_buff.seek(0)
			return out_buff.read()
		else:
			return self._cipher.encrypt(data)

	def decrypt(self, data):
		if self.mode != cipherMODE.CFB:
			in_buff = io.BytesIO(data)
			out_buff = io.BytesIO()
			decrypt_stream(self._cipher, in_buff, out_buff, padding = PADDING_NONE)
			out_buff.seek(0)
			return out_buff.read()
		else:
			return self._cipher.decrypt(data)
	
	def update(self, data):
		if self.mode != cipherMODE.CCM:
			raise Exception('Not applicable!')

		return self._cipher.update(data)

	def digest(self):
		if self.mode != cipherMODE.CCM:
			raise Exception('Not applicable!')

		return self._cipher.digest()