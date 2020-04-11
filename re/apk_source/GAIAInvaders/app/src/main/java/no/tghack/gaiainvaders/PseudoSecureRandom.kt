package no.tghack.gaiainvaders

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.Salsa20Engine
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.security.Provider
import java.security.SecureRandom
import java.security.SecureRandomSpi


class PseudoSecureRandom(seed: ByteArray) :
    SecureRandom(PseudoSecureRandomSpi(seed), PROVIDER) {
    private class PseudoSecureRandomSpi(seed: ByteArray) : SecureRandomSpi() {
        private val cipher: Salsa20Engine
        private fun initialise(seed: ByteArray) { // Hash the seed to produce a 256-bit key
            val key = ByteArray(32)
            val digest = SHA256Digest()
            digest.update(seed, 0, seed.size)
            digest.doFinal(key, 0)
            // Initialise the stream cipher with an all-zero nonce
            val nonce = ByteArray(8)
            cipher.init(true, ParametersWithIV(KeyParameter(key), nonce))
        }

        override fun engineSetSeed(seed: ByteArray) {
            initialise(seed)
        }

        override fun engineNextBytes(out: ByteArray) {
            val blank = ByteArray(out.size)
            cipher.processBytes(blank, 0, out.size, out, 0)
        }

        override fun engineGenerateSeed(length: Int): ByteArray {
            val seed = ByteArray(length)
            engineNextBytes(seed)
            return seed
        }

        init {
            cipher = Salsa20Engine()
            initialise(seed)
        }
    }

    private class PseudoSecureRandomProvider() :
        Provider("PseudoSecureRandom", 1.0, "Deterministic PRNG")

    companion object {
        private val PROVIDER: Provider = PseudoSecureRandomProvider()
    }
}

