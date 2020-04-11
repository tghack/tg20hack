package no.tghack.gaiainvaders

import android.content.Context
import android.content.SharedPreferences
import android.graphics.*
import android.view.SurfaceView
import android.util.Log
import android.view.MotionEvent
import androidx.core.content.ContextCompat.getColor

class GaiaInvadersView(context: Context, private val size: Point) : SurfaceView(context), Runnable {
    private val soundPlayer = SoundPlayer(context)
    private val gameThread = Thread(this)
    private var playing = false
    private var paused = true // Game is paused at the start
    private var canvas: Canvas = Canvas() // A Canvas and a Paint object
    private val paint: Paint = Paint()
    private var playerShip: PlayerShip =
        PlayerShip(context, size.x, size.y)
    private val invaders = ArrayList<Invader>()
    private var numInvaders = 0
    private val bricks = ArrayList<DefenceBrick>() // The player's shelters are built from bricks
    private var numBricks: Int = 0

    // The player's playerBullet is
    // much faster and half the length
    // compared to invader's bullet
    private var playerBullet = Bullet(size.y, 1200f, 40f)

    // The invaders bullets
    private val invadersBullets = ArrayList<Bullet>()
    private var nextBullet = 0
    private val maxInvaderBullets = 10

    private var score = 0
    private var waves = 1
    private var lives = 3
    private var magic: Long = 0x1337

    // To remember the high score
    private val prefs: SharedPreferences = context.getSharedPreferences(
        "Gaia Invaders",
        Context.MODE_PRIVATE)

    private var highScore =  prefs.getInt("highScore", 0)
    private var menaceInterval: Long = 1000 // How menacing should the sound be?
    private var uhOrOh: Boolean = false // Which menace sound should play next
    private var lastMenaceTime = System.currentTimeMillis() // When did we last play a menacing sound

    private fun prepareLevel() {
        // Here we will initialize the game objects
        // Build an army of invaders
        Invader.numberOfInvaders = 0
        numInvaders = 0
        for (column in 0..10) {
            for (row in 0..5) {
                invaders.add(
                    Invader(
                        context,
                        row,
                        column,
                        size.x,
                        size.y
                    )
                )

                numInvaders++
            }
        }

        // Build the shelters
        numBricks = 0
        for (shelterNumber in 0..4) {
            for (column in 0..14) {
                for (row in 0..8) {
                    bricks.add(
                        DefenceBrick(
                            row,
                            column,
                            shelterNumber,
                            size.x,
                            size.y
                        )
                    )

                    numBricks++
                }
            }
        }

        // Initialize the invadersBullets array
        for (i in 0 until maxInvaderBullets) {
            invadersBullets.add(Bullet(size.y))
        }
    }

    override fun run() {
        // This variable tracks the game frame rate
        var fps: Long = 0

        while (playing) {

            // Capture the current time
            val startFrameTime = System.currentTimeMillis()

            // Update the frame
            if (!paused) {
                update(fps)
            }

            // Draw the frame
            draw()

            // Calculate the fps rate this frame
            val timeThisFrame = System.currentTimeMillis() - startFrameTime
            if (timeThisFrame >= 1) {
                fps = 1000 / timeThisFrame
            }

            // Play a sound based on the menace level
            if (!paused && ((startFrameTime - lastMenaceTime) > menaceInterval))
                menacePlayer()
        }
    }

    private fun menacePlayer() {
        if (uhOrOh) {
            // Play Uh
            soundPlayer.playSound(SoundPlayer.uhID)

        } else {
            // Play Oh
            soundPlayer.playSound(SoundPlayer.ohID)
        }

        // Reset the last menace time
        lastMenaceTime = System.currentTimeMillis()
        // Alter value of uhOrOh
        uhOrOh = !uhOrOh

    }

    private fun update(fps: Long) {
        // Update the state of all the game objects

        // Move the player's ship
        playerShip.update(fps)

        // Did an invader bump into the side of the screen
        var bumped = false
        var lost = false

        // Update all the invaders if visible
        for (invader in invaders) {

            if (invader.isVisible) {
                // Move the next invader
                invader.update(fps)

                // Does he want to take a shot?
                if (invader.takeAim(playerShip.position.left,
                        playerShip.width,
                        waves)) {

                    // If so try and spawn a bullet
                    if (invadersBullets[nextBullet].shoot(invader.position.left
                                + invader.width / 2,
                            invader.position.top, playerBullet.down)) {

                        // Shot fired
                        // Prepare for the next shot
                        nextBullet++

                        // Loop back to the first one if we have reached the last
                        if (nextBullet == maxInvaderBullets) {
                            // This stops the firing of bullet
                            // until one completes its journey
                            // Because if bullet 0 is still active
                            // shoot returns false.
                            nextBullet = 0
                        }
                    }
                }

                // If that move caused them to bump
                // the screen change bumped to true
                if (invader.position.left > size.x - invader.width
                    || invader.position.left < 0) {

                    bumped = true
                }
            }
        }

        // Update the players playerBullet
        if (playerBullet.isActive) {
            playerBullet.update(fps)
        }

        // Update all the invaders bullets if active

        for (bullet in invadersBullets) {
            if (bullet.isActive) {
                bullet.update(fps)
            }
        }

        // Did an invader bump into the edge of the screen
        if (bumped) {

            // Move all the invaders down and change direction
            for (invader in invaders) {
                invader.dropDownAndReverse(waves)
                // Have the invaders landed
                if (invader.position.bottom >= size.y && invader.isVisible) {
                    lost = true
                }
            }
        }

        // Has the player's playerBullet hit the top of the screen
        if (playerBullet.position.bottom < 0) {
            playerBullet.isActive =false
        }

        // Has an invaders playerBullet hit the bottom of the screen
        for (bullet in invadersBullets) {
            if (bullet.position.top > size.y) {
                bullet.isActive = false
            }
        }

        // Has the player's playerBullet hit an invader
        if (playerBullet.isActive) {
            for (invader in invaders) {
                if (invader.isVisible) {
                    if (RectF.intersects(playerBullet.position, invader.position)) {
                        invader.isVisible = false

                        soundPlayer.playSound(SoundPlayer.invaderExplodeID)
                        playerBullet.isActive = false
                        Invader.numberOfInvaders--
                        score += 10
                        if(score > highScore){
                            highScore = score
                        }

                        // Don't check any more invaders
                        break
                    }
                }
            }
        }

        // Has the player cleared the level
        //if (score == numInvaders * 10 * waves) {
        if (Invader.numberOfInvaders == 0) { // add " || true" to debug
            paused = true // comment out this one
            lives ++
            invaders.clear()
            bricks.clear()
            invadersBullets.clear()

            // Has the player cleared the game
            if (waves == 1000) {
                paused = true

                val picture = BitmapFactory.decodeResource(resources, R.drawable.space_cyan)
                val bitmap = Bitmap.createBitmap(size.x, size.y, Bitmap.Config.ARGB_8888)
                canvas = Canvas(bitmap)
                canvas = holder.lockCanvas()

                val rect = RectF(70F, 100F, size.x - 70F, size.y/2 - 160F)
                canvas.drawBitmap(picture, null, rect, null)

                paint.color = getColor(context, R.color.colorPink)
                paint.textSize = 80f
                val xPos = (canvas.width / 2F)
                val yPos = (canvas.height / 2F) - ((paint.descent() + paint.ascent()) / 2F)
                paint.textAlign = Paint.Align.CENTER

                val bonusMessage = "M6GzLMKMB7TO7qCwYIE6tWjstepv0Fa6B3yyCrRtFbNRb2+VVVCqDuDO6UWY14LEu9Ac3A2sVaKG4Thk1s1j0g=="
                val decryptedBonusMsg = decrypt(bonusMessage, magic, "ClcYYh9brZTGyTFG4kge7w==")
                canvas.drawText("Congrats!!!", xPos, yPos, paint)
                paint.textSize = 40f
                canvas.drawText("${decryptedBonusMsg}", xPos, yPos + 100, paint)
                holder.unlockCanvasAndPost(canvas)

                pause()
            }

            this.magic += (waves * 42) / 2 + (0xdeadbeef * lives)

            prepareLevel()
            waves ++
            //break
        }

        // Has an alien playerBullet hit a shelter brick
        for (bullet in invadersBullets) {
            if (bullet.isActive) {
                for (brick in bricks) {
                    if (brick.isVisible) {
                        if (RectF.intersects(bullet.position, brick.position)) {
                            // A collision has occurred
                            bullet.isActive = false
                            brick.isVisible = false
                            soundPlayer.playSound(SoundPlayer.damageShelterID)
                        }
                    }
                }
            }

        }

        // Has a player playerBullet hit a shelter brick
        if (playerBullet.isActive) {
            for (brick in bricks) {
                if (brick.isVisible) {
                    if (RectF.intersects(playerBullet.position, brick.position)) {
                        // A collision has occurred
                        playerBullet.isActive = false
                        brick.isVisible = false
                        soundPlayer.playSound(SoundPlayer.damageShelterID)
                    }
                }
            }
        }

        // Has an invader playerBullet hit the player ship
        for (bullet in invadersBullets) {
            if (bullet.isActive) {
                if (RectF.intersects(playerShip.position, bullet.position)) {
                    bullet.isActive = false
                    lives --
                    soundPlayer.playSound(SoundPlayer.playerExplodeID)

                    // Is it game over?
                    if (lives == 0) {
                        lost = true
                        break
                    }
                }
            }
        }

        if (lost) {
            paused = true
            lives = 3
            score = 0
            waves = 1
            invaders.clear()
            bricks.clear()
            invadersBullets.clear()
            prepareLevel()
        }
    }

    private fun draw() {
        // Make sure our drawing surface is valid or the game will crash
        if (holder.surface.isValid) {
            // Lock the canvas ready to draw
            canvas = holder.lockCanvas()

            // Draw the background color
            canvas.drawColor(getColor(context , R.color.colorPrimaryDark))

            // Choose the brush color for drawing
            paint.color = getColor(context, R.color.colorLight) //Color.argb(255, 0, 255, 0)

            // Draw all the game objects here
            // Now draw the player spaceship
            canvas.drawBitmap(playerShip.bitmap, playerShip.position.left,
                playerShip.position.top
                , paint)

            // Draw the invaders
            for (invader in invaders) {
                if (invader.isVisible) {
                    if (uhOrOh) {
                        canvas.drawBitmap(
                            Invader.bitmap1!!,
                            invader.position.left,
                            invader.position.top,
                            paint)
                    } else {
                        canvas.drawBitmap(
                            Invader.bitmap2!!,
                            invader.position.left,
                            invader.position.top,
                            paint)
                    }
                }
            }

            // Draw the bricks if visible
            for (brick in bricks) {
                if (brick.isVisible) {
                    canvas.drawRect(brick.position, paint)
                }
            }

            // Draw the players playerBullet if active
            if (playerBullet.isActive) {
                canvas.drawRect(playerBullet.position, paint)
            }

            // Draw the invaders bullets
            for (bullet in invadersBullets) {
                if (bullet.isActive) {
                    canvas.drawRect(bullet.position, paint)
                }
            }

            // Draw the score and remaining lives
            // Change the brush color
            paint.color = getColor(context, R.color.colorLight)
            paint.textSize = 50f
            val xPos = (canvas.width / 2F)
            paint.textAlign = Paint.Align.CENTER
            canvas.drawText("Score: $score      Lives: $lives       " +
                    "Wave: $waves       HI: $highScore", xPos, 75f, paint)

            // Draw everything to the screen
            holder.unlockCanvasAndPost(canvas)
        }
    }

    // If SpaceInvadersActivity is paused/stopped
    // then shut down our thread.
    fun pause() {
        playing = false
        try {
            gameThread.join()
        } catch (e: InterruptedException) {
            Log.e("Error:", "joining thread")
        }

        val prefs = context.getSharedPreferences(
            "Gaia Invaders",
            Context.MODE_PRIVATE)

        val oldHighScore = prefs.getInt("highScore", 0)

        if(highScore > oldHighScore) {
            val editor = prefs.edit()

            editor.putInt(
                "highScore", highScore)

            editor.apply()
        }
    }

    // If SpaceInvadersActivity is started then
    // start our thread.
    fun resume() {
        playing = true
        prepareLevel()
        gameThread.start()
    }

    // The SurfaceView class implements onTouchListener
    // So we can override this method and detect screen touches.
    override fun onTouchEvent(motionEvent: MotionEvent): Boolean {
        when (motionEvent.action and MotionEvent.ACTION_MASK) {

            // Player has touched the screen
            // Or moved their finger while touching screen
            MotionEvent.ACTION_POINTER_DOWN,
            MotionEvent.ACTION_DOWN,
            MotionEvent.ACTION_MOVE-> {
                paused = false

                if (motionEvent.y > size.y - size.y / 8) {
                    if (motionEvent.x > size.x / 2) {
                        playerShip.moving = PlayerShip.right
                    } else {
                        playerShip.moving = PlayerShip.left
                    }

                }

                if (motionEvent.y < size.y - size.y / 8) {
                    // Shots fired
                    if (playerBullet.shoot(
                            playerShip.position.left + playerShip.width / 2f,
                            playerShip.position.top,
                            playerBullet.up)) {

                        soundPlayer.playSound(SoundPlayer.shootID)
                    }
                }
            }

            // Player has removed finger from screen
            MotionEvent.ACTION_POINTER_UP,
            MotionEvent.ACTION_UP -> {
                if (motionEvent.y > size.y - size.y / 10) {
                    playerShip.moving = PlayerShip.stopped
                }
            }

        }
        return true
    }

}

