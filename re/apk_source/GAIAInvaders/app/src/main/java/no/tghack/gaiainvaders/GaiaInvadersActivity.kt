package no.tghack.gaiainvaders

import androidx.appcompat.app.AppCompatActivity
import android.graphics.Point
import android.os.Bundle

class GaiaInvadersActivity : AppCompatActivity() {

    // gaiaInvadersView will be the view of the game
    // It will also hold the logic of the game
    // and respond to screen touches as well
    private var gaiaInvadersView: GaiaInvadersView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Get a Display object to access screen details
        val display = windowManager.defaultDisplay
        val size = Point() // Load the resolution into a Point object
        display.getSize(size)

        gaiaInvadersView = GaiaInvadersView(this, size)
        setContentView(gaiaInvadersView)
    }

    // Executes when the player starts the game
    override fun onResume() {
        super.onResume()

        gaiaInvadersView?.resume()
    }

    // Executes when the player quits the game
    override fun onPause() {
        super.onPause()

        gaiaInvadersView?.pause()
    }
}
