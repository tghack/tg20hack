package no.tghack.gaiainvaders

import android.content.Context
import android.graphics.Bitmap
import android.graphics.RectF
import android.graphics.BitmapFactory

class PlayerShip(context: Context,
                 private val screenX: Int,
                 screenY: Int) {

    // The player ship will be represented by a Bitmap
    var bitmap: Bitmap = BitmapFactory.decodeResource(
        context.resources,
        R.drawable.playership
    )

    // How wide and high our ship will be
    val width = screenX / 20f
    private val height = screenY / 30f

    // This keeps track of where the ship is
    val position = RectF(
        screenX / 2f,
        screenY-height-240,
        screenX/2 + width,
        screenY.toFloat())

    // This will hold the pixels per second speed that the ship will move
    private val speed  = 450f

    // This data is accessible using ClassName.propertyName
    companion object {
        // Which ways can the ship move
        const val stopped = 0
        const val left = 1
        const val right = 2
    }

    // Is the ship moving and in which direction
    // Start off stopped
    var moving = stopped

    init{
        // stretch the bitmap to a size
        // appropriate for the screen resolution
        bitmap = Bitmap.createScaledBitmap(bitmap,
            width.toInt() ,
            height.toInt() ,
            false)
    }

    // This update method will be called from update in
    // KotlinInvadersView It determines if the player's
    // ship needs to move and changes the coordinates
    fun update(fps: Long) {
        // Move as long as it doesn't try and leave the screen
        if (moving == left && position.left > 0) {
            position.left -= speed / fps
        }

        else if (moving == right && position.left < screenX - width) {
            position.left += speed / fps
        }

        position.right = position.left + width
    }

}

