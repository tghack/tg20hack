package no.tghack.gaiainvaders

import androidx.appcompat.app.AppCompatActivity
import android.content.Intent
import android.os.Bundle
import android.widget.Button

class HomeActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.home_page)

        val play_game_btn = findViewById<Button>(R.id.btn_play_game)

        play_game_btn.setOnClickListener{
            val intent = Intent(this, GaiaInvadersActivity::class.java)
            startActivity(intent)
        }
    }
}
