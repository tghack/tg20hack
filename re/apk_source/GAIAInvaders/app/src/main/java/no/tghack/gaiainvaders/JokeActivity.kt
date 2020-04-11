package no.tghack.gaiainvaders

import androidx.appcompat.app.AppCompatActivity

import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.TextView
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class JokeActivity : AppCompatActivity() {
    private val ciphertext = "RTRvInzt/bzxdJgClIpZTftgpE2FwyjMyQMwCTnjQa0="
    private val key = "BG0I2BRlkbTPevVsWzdozg=="

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.joke_page)

        //generateKeyAndEncryptFlag()

        val getAnswerButton = findViewById<Button>(R.id.btn_get_answer)
        val answer = findViewById<TextView>(R.id.answer_text)

        getAnswerButton.setOnClickListener{
            decryptAnswer(key, answer)
            showHide(answer)
        }
    }

    private fun decryptAnswer(key: String, answer: TextView) {
        val decryptedFlag = decrypt(key, ciphertext)
        Log.d("Decrypted: ", decryptedFlag)
        answer.text = decryptedFlag
    }

    private fun showHide(view: View) {
        view.visibility = if (view.visibility == View.VISIBLE) {
            View.INVISIBLE
        } else {
            View.VISIBLE
        }
    }

    @Throws(Exception::class)
    fun decrypt(b64key: String, b64ciphertext: String): String {
        val decodedKey: ByteArray = Base64.decode(b64key, Base64.DEFAULT)
        val key = SecretKeySpec(decodedKey, 0, decodedKey.size, "AES")

        val cipher = Cipher.getInstance("AES", "BC")
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(ByteArray(cipher.blockSize)))
        val ciphertext: ByteArray = Base64.decode(b64ciphertext, Base64.DEFAULT)
        val decrypted = cipher.doFinal(ciphertext)
        return decrypted.toString(charset("UTF-8"))
    }

    //private fun generateKeyAndEncryptFlag() {
    //    val key = generateSecretKey()
    //    val b64key = Base64.encodeToString(key.encoded, Base64.DEFAULT)
    //    Log.d("SecretKey: ", b64key) // b64key)
    //    encrypt(key, flag.toByteArray())
    //}

    //@Throws(Exception::class)
    //fun encrypt(b64key: String, fileData: ByteArray) {
    //    val decodedKey: ByteArray = Base64.decode(b64key, Base64.DEFAULT)
    //    val key = SecretKeySpec(decodedKey, 0, 128, "AES")

    //    val data = key.encoded
    //    val skeySpec = SecretKeySpec(data, 0, data.size, "AES")
    //    val cipher = Cipher.getInstance("AES", "BC")
    //    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, IvParameterSpec(ByteArray(cipher.blockSize)))
    //    val ciphertext = cipher.doFinal(fileData)
    //    val b64ciphertext = Base64.encodeToString(ciphertext, Base64.DEFAULT)
    //    Log.d("Debug:", "Ciphertext: $b64ciphertext")
    //}

    //@Throws(Exception::class)
    //fun generateSecretKey(): SecretKey {
    //    val secureRandom = SecureRandom()
    //    val keyGenerator = KeyGenerator.getInstance("AES")
    //    //generate a key with secure random
    //    keyGenerator?.init(128, secureRandom)
    //    return keyGenerator.generateKey()
    //}
}
