package com.raufelder.gcmcryptotest

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@RunWith(AndroidJUnit4::class)
class GCMCryptoTest {

	@Test
	fun worksOnAPI26() {
		val input = "abcdef" // 6 bytes

		val key = ByteArray(16)
		SecureRandom().nextBytes(key)

		val cipher = Cipher.getInstance("AES/GCM/NoPadding")
		cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))

		val ciphertext = cipher.doFinal(input.toByteArray())
		val iv = cipher.iv

		cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))

		val payloadCleartextBuf = ByteBuffer.allocate(22) // should be 6 bytes
		assert(
			cipher.getOutputSize(ciphertext.size) == 22 // // should be 6 bytes
		)

		val decrypted = cipher.doFinal(ByteBuffer.wrap(ciphertext), payloadCleartextBuf)
		assert(decrypted == 6)

		payloadCleartextBuf.flip()

		println("plaintext : " + String(payloadCleartextBuf.array()))
	}


	@Test
	fun worksOnAPI30() {
		val input = "abcdef" // 6 bytes

		val key = ByteArray(16)
		SecureRandom().nextBytes(key)

		val cipher = Cipher.getInstance("AES/GCM/NoPadding")
		cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))

		val ciphertext = cipher.doFinal(input.toByteArray())
		val iv = cipher.iv

		cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))

		val payloadCleartextBuf = ByteBuffer.allocate(6)
		assert(cipher.getOutputSize(ciphertext.size) == 6)

		val decrypted = cipher.doFinal(ByteBuffer.wrap(ciphertext), payloadCleartextBuf)
		assert(decrypted == 6)

		payloadCleartextBuf.flip()

		println("plaintext : " + String(payloadCleartextBuf.array()))
	}
}
