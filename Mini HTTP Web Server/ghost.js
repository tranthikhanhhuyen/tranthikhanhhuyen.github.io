class Ghost {
    constructor(
        x,
        y,
        width,
        height,
        speed,
        imageX,
        imageY,
        imageWidth,
        imageHeight,
        range
    ) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        this.speed = speed;
        this.direction = DIRECTION_RIGHT;
        this.imageX = imageX;
        this.imageY = imageY;
        this.imageHeight = imageHeight;
        this.imageWidth = imageWidth;
        this.range = range;
        this.isFrightened = false; // Frightened state
        this.randomTargetIndex = parseInt(Math.random() * 4);
        this.target = randomTargetsForGhosts[this.randomTargetIndex];
        setInterval(() => {
            this.changeRandomDirection();
        }, 10000);
    }

    isInRange() {
        let xDistance = Math.abs(pacman.getMapX() - this.getMapX());
        let yDistance = Math.abs(pacman.getMapY() - this.getMapY());
        if (
            Math.sqrt(xDistance * xDistance + yDistance * yDistance) <=
            this.range
        ) {
            return true;
        }
        return false;
    }

    changeRandomDirection() {
        let addition = 1;
        this.randomTargetIndex += addition;
        this.randomTargetIndex = this.randomTargetIndex % 4;
    }

    moveProcess() {
        let currentSpeed = this.isFrightened ? this.speed / 2 : this.speed;

        if (this.isInRange()) {
            this.target = pacman;
        } else {
            this.target = randomTargetsForGhosts[this.randomTargetIndex];
        }

        if (this.x % oneBlockSize === 0 && this.y % oneBlockSize === 0) {
            this.changeDirectionIfPossible();
        }

        let origSpeed = this.speed;
        this.speed = currentSpeed;

        this.moveForwards();
        if (this.checkCollisions()) {
            this.moveBackwards();
            this.speed = origSpeed;
            return;
        }
        this.speed = origSpeed;
    }

    moveBackwards() {
        switch (this.direction) {
            case 4: // Right
                this.x -= this.speed;
                break;
            case 3: // Up
                this.y += this.speed;
                break;
            case 2: // Left
                this.x += this.speed;
                break;
            case 1: // Bottom
                this.y -= this.speed;
                break;
        }
    }

    moveForwards() {
        switch (this.direction) {
            case 4: // Right
                this.x += this.speed;
                break;
            case 3: // Up
                this.y -= this.speed;
                break;
            case 2: // Left
                this.x -= this.speed;
                break;
            case 1: // Bottom
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

    changeDirectionIfPossible() {
        let tempDirection = this.direction;
        this.direction = this.calculateNewDirection(
            map,
            parseInt(this.target.x / oneBlockSize),
            parseInt(this.target.y / oneBlockSize)
        );
        if (typeof this.direction == "undefined") {
            this.direction = tempDirection;
            return;
        }
        
        this.moveForwards();
        if (this.checkCollisions()) {
            this.moveBackwards();
            this.direction = tempDirection;
        } else {
            this.moveBackwards();
        }
    }

    calculateNewDirection(map, destX, destY) {
        let currentX = this.getMapX();
        let currentY = this.getMapY();
        
        let directions = [
            { dir: DIRECTION_RIGHT, dx: 1, dy: 0 },
            { dir: DIRECTION_UP, dx: 0, dy: -1 },
            { dir: DIRECTION_LEFT, dx: -1, dy: 0 },
            { dir: DIRECTION_BOTTOM, dx: 0, dy: 1 }
        ];
        
        let getOppositeDirection = (dir) => {
            switch (dir) {
                case 4: return 2;
                case 3: return 1;
                case 2: return 4;
                case 1: return 3;
                default: return null;
            }
        };

        let opp = getOppositeDirection(this.direction);
        let validDirs = [];

        directions.forEach(d => {
            let nextX = currentX + d.dx;
            let nextY = currentY + d.dy;
            
            if (nextX >= 0 && nextX < map[0].length && nextY >= 0 && nextY < map.length) {
                if (map[nextY][nextX] != 1) {
                    if (d.dir !== opp) {
                        validDirs.push(d);
                    }
                }
            }
        });

        // Fallback: If no moves possible without reversing, allow reversing
        if (validDirs.length === 0) {
            directions.forEach(d => {
                let nextX = currentX + d.dx;
                let nextY = currentY + d.dy;
                if (nextX >= 0 && nextX < map[0].length && nextY >= 0 && nextY < map.length) {
                    if (map[nextY][nextX] != 1) {
                        validDirs.push(d);
                    }
                }
            });
        }

        if (validDirs.length === 0) {
            return this.direction; // Stuck fallback
        }

        // Frightened ghosts wander randomly
        if (this.isFrightened) {
            let randomIndex = Math.floor(Math.random() * validDirs.length);
            return validDirs[randomIndex].dir;
        }

        let bestDir = validDirs[0].dir;
        let minDistance = Infinity;

        validDirs.forEach(d => {
            let nextX = currentX + d.dx;
            let nextY = currentY + d.dy;
            let distance = Math.pow(nextX - destX, 2) + Math.pow(nextY - destY, 2);
            if (distance < minDistance) {
                minDistance = distance;
                bestDir = d.dir;
            }
        });

        return bestDir;
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

    resetPosition() {
        this.x = 9 * oneBlockSize + (Math.random() > 0.5 ? 0 : 1) * oneBlockSize;
        this.y = 10 * oneBlockSize;
        this.direction = DIRECTION_RIGHT;
        this.isFrightened = false;
    }

    draw() {
        canvasContext.save();
        if (this.isFrightened) {
            canvasContext.filter = "hue-rotate(240deg) saturate(2)";
        }
        canvasContext.drawImage(
            ghostFrames,
            this.imageX,
            this.imageY,
            this.imageWidth,
            this.imageHeight,
            this.x,
            this.y,
            this.width,
            this.height
        );
        canvasContext.restore();
    }
}

let updateGhosts = () => {
    for (let i = 0; i < ghosts.length; i++) {
        ghosts[i].moveProcess();
    }
};

let drawGhosts = () => {
    for (let i = 0; i < ghosts.length; i++) {
        ghosts[i].draw();
    }
};