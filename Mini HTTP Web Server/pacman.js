class Pacman {
    constructor(x, y, width, height, speed) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        this.speed = speed;
        this.direction = null;
        this.nextDirection = null;
        this.frameCount = 7;
        this.currentFrame = 1;
        setInterval(() => {
            this.changeAnimation();
        }, 100);
    }

    moveProcess() {
        this.changeDirectionIfPossible();
        this.moveForwards();
        if (this.checkCollisions()) {
            this.moveBackwards();
            this.direction = null;
            this.nextDirection = null;
            return;
        }

        // Stop Pacman when he aligns with the next grid cell
        if (this.x % oneBlockSize === 0 && this.y % oneBlockSize === 0) {
            this.direction = null;
            this.nextDirection = null;
        }
    }

    eat() {
        for (let i = 0; i < map.length; i++) {
            for (let j = 0; j < map[0].length; j++) {
                if (
                    (map[i][j] == 2 || map[i][j] == 4) &&
                    this.getMapX() == j &&
                    this.getMapY() == i
                ) {
                    let isGolden = map[i][j] == 4;
                    map[i][j] = 3;
                    score++;

                    // Spawn cute heart particles
                    spawnHeartParticles(
                        j * oneBlockSize + oneBlockSize / 2,
                        i * oneBlockSize + oneBlockSize / 2
                    );

                    // Show cute romantic popup message
                    if (score % 15 === 0 && score > 0) {
                        spawnLoveMessage(this.x + oneBlockSize / 2, this.y);
                    }

                    if (isGolden) {
                        // Play special gold sound
                        playTone(523.25, 0.12, "sine", 0.18);
                        setTimeout(() => playTone(659.25, 0.12, "sine", 0.18), 80);
                        triggerFrightenedMode();
                    } else {
                        playEatSFX();
                    }
                }
            }
        }
    }

    moveBackwards() {
        switch (this.direction) {
            case DIRECTION_RIGHT: // Right
                this.x -= this.speed;
                break;
            case DIRECTION_UP: // Up
                this.y += this.speed;
                break;
            case DIRECTION_LEFT: // Left
                this.x += this.speed;
                break;
            case DIRECTION_BOTTOM: // Bottom
                this.y -= this.speed;
                break;
        }
    }

    moveForwards() {
        switch (this.direction) {
            case DIRECTION_RIGHT: // Right
                this.x += this.speed;
                break;
            case DIRECTION_UP: // Up
                this.y -= this.speed;
                break;
            case DIRECTION_LEFT: // Left
                this.x -= this.speed;
                break;
            case DIRECTION_BOTTOM: // Bottom
                this.y += this.speed;
                break;
        }
    }

    checkCollisions() {
        let isCollided = false;
        let y1 = parseInt(this.y / oneBlockSize);
        let y2 = parseInt(this.y / oneBlockSize + 0.9999);
        let x1 = parseInt(this.x / oneBlockSize);
        let x2 = parseInt(this.x / oneBlockSize + 0.9999);

        // Treat out of map boundaries as collision
        if (
            y1 < 0 || y1 >= map.length ||
            y2 < 0 || y2 >= map.length ||
            x1 < 0 || x1 >= map[0].length ||
            x2 < 0 || x2 >= map[0].length
        ) {
            return true;
        }

        if (
            map[y1][x1] == 1 ||
            map[y2][x1] == 1 ||
            map[y1][x2] == 1 ||
            map[y2][x2] == 1
        ) {
            isCollided = true;
        }
        return isCollided;
    }

    checkGhostCollision(ghosts) {
        for (let i = 0; i < ghosts.length; i++) {
            let ghost = ghosts[i];
            if (
                ghost.getMapX() == this.getMapX() &&
                ghost.getMapY() == this.getMapY()
            ) {
                return true;
            }
        }
        return false;
    }

    changeDirectionIfPossible() {
        if (this.x % oneBlockSize !== 0 || this.y % oneBlockSize !== 0) return;
        if (this.direction == this.nextDirection) return;
        let tempDirection = this.direction;
        this.direction = this.nextDirection;
        this.moveForwards();
        if (this.checkCollisions()) {
            this.moveBackwards();
            this.direction = tempDirection;
        } else {
            this.moveBackwards();
        }
    }

    getMapX() {
        let mapX = parseInt(this.x / oneBlockSize);
        return mapX;
    }

    getMapY() {
        let mapY = parseInt(this.y / oneBlockSize);

        return mapY;
    }

    getMapXRightSide() {
        let mapX = parseInt((this.x * 0.99 + oneBlockSize) / oneBlockSize);
        return mapX;
    }

    getMapYRightSide() {
        let mapY = parseInt((this.y * 0.99 + oneBlockSize) / oneBlockSize);
        return mapY;
    }

    changeAnimation() {
        this.currentFrame =
            this.currentFrame == this.frameCount ? 1 : this.currentFrame + 1;
    }

    draw() {
        canvasContext.save();
        canvasContext.translate(
            this.x + oneBlockSize / 2,
            this.y + oneBlockSize / 2
        );
        canvasContext.rotate((this.direction * 90 * Math.PI) / 180);
        canvasContext.translate(
            -this.x - oneBlockSize / 2,
            -this.y - oneBlockSize / 2
        );
        canvasContext.drawImage(
            pacmanFrames,
            (this.currentFrame - 1) * oneBlockSize,
            0,
            oneBlockSize,
            oneBlockSize,
            this.x,
            this.y,
            this.width,
            this.height
        );
        canvasContext.restore();
    }
}