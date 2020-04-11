package no.tghack.gaiainvaders

import android.util.Base64
import android.util.Log
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

//fun encrypt(msg: String, seed: Number): String {
//    val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
//    cipher.init(Cipher.ENCRYPT_MODE, getKey(seed), PseudoSecureRandom(seed.toString().toByteArray()))
//    val ciphertext: ByteArray = cipher.doFinal(msg.toByteArray(charset("UTF-8")))
//    val iv: ByteArray = cipher.iv
//
//    val b64ciphertext = Base64.encodeToString(ciphertext, Base64.DEFAULT)
//    val b64iv = Base64.encodeToString(iv, Base64.DEFAULT)
//    Log.d("Debug:", "Ciphertext: $b64ciphertext, iv: $b64iv")
//
//    return b64iv
//}

fun decrypt(b64ciphertext: String, seed: Number, b64iv: String): String {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
    val iv: ByteArray = Base64.decode(b64iv, Base64.DEFAULT)
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.DECRYPT_MODE, getKey(seed), ivSpec, PseudoSecureRandom(seed.toString().toByteArray()))

    val ciphertext: ByteArray = Base64.decode(b64ciphertext, Base64.DEFAULT)
    val plaintext = cipher.doFinal(ciphertext)

    return plaintext.toString(charset("UTF-8"))
}

private fun getKey(seed: Number): SecretKey {
    val seed = seed.toString().toByteArray()
    val keygen = KeyGenerator.getInstance("AES")
    val key = PseudoSecureRandom(seed)
    keygen.init(256, key)
    return keygen.generateKey()
}
