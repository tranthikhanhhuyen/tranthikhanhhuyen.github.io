const canvas = document.getElementById("canvas");
const canvasContext = canvas.getContext("2d");
const pacmanFrames = document.getElementById("animation");
const ghostFrames = document.getElementById("ghosts");

let createRect = (x, y, width, height, color) => {
    canvasContext.fillStyle = color;
    canvasContext.fillRect(x, y, width, height);
};

// Heart drawing helper for food
let drawHeart = (x, y, size, color) => {
    canvasContext.fillStyle = color;
    canvasContext.beginPath();
    let d = size;
    canvasContext.moveTo(x, y + d / 4);
    canvasContext.quadraticCurveTo(x, y, x - d / 2, y);
    canvasContext.quadraticCurveTo(x - d, y, x - d, y + d / 2);
    canvasContext.quadraticCurveTo(x - d, y + d * 0.75, x - d * 0.5, y + d);
    canvasContext.lineTo(x, y + d * 1.25);
    canvasContext.lineTo(x + d * 0.5, y + d);
    canvasContext.quadraticCurveTo(x + d, y + d * 0.75, x + d, y + d / 2);
    canvasContext.quadraticCurveTo(x + d, y, x + d * 0.5, y);
    canvasContext.quadraticCurveTo(x, y, x, y + d / 4);
    canvasContext.fill();
};

// ==========================================
// RETRO SYNTHESIZED SOUNDS (Web Audio API)
// ==========================================
let audioCtx = null;
let bgmInterval = null;
let isMuted = false;

let initAudio = () => {
    if (audioCtx) return;
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
};

let playTone = (freq, duration, type = "sine", volume = 0.1) => {
    if (!audioCtx) initAudio();
    if (isMuted) return;
    try {
        let osc = audioCtx.createOscillator();
        let gainNode = audioCtx.createGain();
        
        osc.type = type;
        osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
        
        gainNode.gain.setValueAtTime(volume, audioCtx.currentTime);
        // Exponential fade out
        gainNode.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + duration);
        
        osc.connect(gainNode);
        gainNode.connect(audioCtx.destination);
        
        osc.start();
        osc.stop(audioCtx.currentTime + duration);
    } catch (e) {
        console.log("Audio failed:", e);
    }
};

let playBGM = () => {
    initAudio();
    if (isMuted || gameState !== STATE_PLAYING) {
        stopBGM();
        return;
    }
    if (bgmInterval) return;

    // Cute romantic chiptune melody
    let notes = [
        329.63, 392.00, 523.25, 659.25, 523.25, 392.00,
        349.23, 440.00, 587.33, 698.46, 587.33, 440.00,
        392.00, 493.88, 587.33, 783.99, 587.33, 493.88,
        349.23, 440.00, 523.25, 698.46, 523.25, 440.00
    ];
    let noteIndex = 0;
    
    bgmInterval = setInterval(() => {
        if (isMuted || gameState !== STATE_PLAYING) {
            stopBGM();
            return;
        }
        playTone(notes[noteIndex], 0.12, "triangle", 0.05);
        noteIndex = (noteIndex + 1) % notes.length;
    }, 180);
};

let stopBGM = () => {
    if (bgmInterval) {
        clearInterval(bgmInterval);
        bgmInterval = null;
    }
};

let playEatSFX = () => {
    playTone(880, 0.05, "sine", 0.08);
};

let playWinSFX = () => {
    let arpeggio = [523.25, 659.25, 783.99, 1046.50, 1318.51];
    arpeggio.forEach((f, idx) => {
        setTimeout(() => {
            playTone(f, 0.3, "triangle", 0.15);
        }, idx * 100);
    });
};

let playGameOverSFX = () => {
    let notes = [392.00, 311.13, 261.63, 196.00];
    notes.forEach((f, idx) => {
        setTimeout(() => {
            playTone(f, 0.4, "sawtooth", 0.1);
        }, idx * 180);
    });
};

// ==========================================
// PARTICLE SYSTEM (HEART EXPLOSIONS)
// ==========================================
let particles = [];

class HeartParticle {
    constructor(x, y) {
        this.x = x;
        this.y = y;
        this.size = Math.random() * 4 + 3;
        this.speedX = (Math.random() - 0.5) * 3;
        this.speedY = -Math.random() * 2 - 0.5;
        this.alpha = 1;
        this.color = Math.random() > 0.5 ? "#ff4081" : "#ff1a53";
    }
    update() {
        this.x += this.speedX;
        this.y += this.speedY;
        this.alpha -= 0.04;
    }
    draw() {
        canvasContext.save();
        canvasContext.globalAlpha = this.alpha;
        drawHeart(this.x, this.y, this.size, this.color);
        canvasContext.restore();
    }
}

let spawnHeartParticles = (x, y) => {
    for (let i = 0; i < 6; i++) {
        particles.push(new HeartParticle(x, y));
    }
};

let updateParticles = () => {
    for (let i = particles.length - 1; i >= 0; i--) {
        particles[i].update();
        if (particles[i].alpha <= 0) {
            particles.splice(i, 1);
        }
    }
};

let drawParticles = () => {
    particles.forEach(p => p.draw());
};

// ==========================================
// LOVE MESSAGES POPUPS
// ==========================================
let loveMessages = [
    "Khánh iu ngoan quá! ❤️",
    "Yêu Khánh nhất! 💕",
    "Moa moa! 😘",
    "Chụt chụt! 💋",
    "Khánh iu giỏi thế! 🌸",
    "Thương thương! 🥰",
    "Mãi yêu Khánh iu! ✨"
];
let floatingTexts = [];

class FloatingText {
    constructor(text, x, y) {
        this.text = text;
        this.x = x;
        this.y = y;
        this.speedY = -0.6;
        this.alpha = 1;
    }
    update() {
        this.y += this.speedY;
        this.alpha -= 0.02;
    }
    draw() {
        canvasContext.save();
        canvasContext.globalAlpha = this.alpha;
        canvasContext.font = "bold 12px 'Outfit', sans-serif";
        canvasContext.fillStyle = "#d81b60";
        canvasContext.strokeStyle = "#ffffff";
        canvasContext.lineWidth = 3;
        canvasContext.strokeText(this.text, this.x - 30, this.y);
        canvasContext.fillText(this.text, this.x - 30, this.y);
        canvasContext.restore();
    }
}

let spawnLoveMessage = (x, y) => {
    let msg = loveMessages[Math.floor(Math.random() * loveMessages.length)];
    floatingTexts.push(new FloatingText(msg, x, y));
};

let updateFloatingTexts = () => {
    for (let i = floatingTexts.length - 1; i >= 0; i--) {
        floatingTexts[i].update();
        if (floatingTexts[i].alpha <= 0) {
            floatingTexts.splice(i, 1);
        }
    }
};

let drawFloatingTexts = () => {
    floatingTexts.forEach(t => t.draw());
};

// ==========================================
// SPAWN ADDITIONAL GOLDEN HEART FOR NEW LIFE
// ==========================================
let spawnAdditionalGoldenHeart = () => {
    let foodLocations = [];
    for (let i = 0; i < map.length; i++) {
        for (let j = 0; j < map[0].length; j++) {
            if (map[i][j] == 2) {
                foodLocations.push({ r: i, c: j });
            }
        }
    }
    if (foodLocations.length > 0) {
        let randLoc = foodLocations[Math.floor(Math.random() * foodLocations.length)];
        map[randLoc.r][randLoc.c] = 4; // Spawn a Golden Heart!
    }
};

// ==========================================
// GAME CORE LOGIC
// ==========================================
const DIRECTION_RIGHT = 4;
const DIRECTION_UP = 3;
const DIRECTION_LEFT = 2;
const DIRECTION_BOTTOM = 1;
let lives = 3;
let ghostCount = 4;
let ghostImageLocations = [
    { x: 0, y: 0 },
    { x: 176, y: 0 },
    { x: 0, y: 121 },
    { x: 176, y: 121 },
];

let fps = 30;
let pacman;
let oneBlockSize = 20;
let score = 0;
let ghosts = [];
let wallSpaceWidth = oneBlockSize / 1.6;
let wallOffset = (oneBlockSize - wallSpaceWidth) / 2;
let wallInnerColor = "#fff0f3"; // Soft rose-cream path backings

const STATE_START = "START";
const STATE_PLAYING = "PLAYING";
const STATE_GAMEOVER = "GAMEOVER";
const STATE_VICTORY = "VICTORY";
let gameState = STATE_START;

// We store the default map (updated with 4 Power Pellets (value 4) in the corners)
const defaultMap = [
    [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    [1, 4, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 4, 1], // Golden heart at (1,1) and (1,19)
    [1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1],
    [1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1],
    [1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1],
    [1, 2, 1, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1, 2, 1, 2, 1, 1, 1, 2, 1],
    [1, 2, 2, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 2, 2, 1],
    [1, 1, 1, 1, 1, 2, 1, 1, 1, 2, 1, 2, 1, 1, 1, 2, 1, 1, 1, 1, 1],
    [0, 0, 0, 0, 1, 2, 1, 2, 2, 2, 2, 2, 2, 2, 1, 2, 1, 0, 0, 0, 0],
    [1, 1, 1, 1, 1, 2, 1, 2, 1, 1, 2, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1],
    [2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2],
    [1, 1, 1, 1, 1, 2, 1, 2, 1, 2, 2, 2, 1, 2, 1, 2, 1, 1, 1, 1, 1],
    [0, 0, 0, 0, 1, 2, 1, 2, 1, 1, 1, 1, 1, 2, 1, 2, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 2, 1, 2, 2, 2, 2, 2, 2, 2, 1, 2, 1, 0, 0, 0, 0],
    [1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1],
    [1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1],
    [1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1],
    [1, 2, 2, 2, 1, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 1, 2, 2, 2, 1],
    [1, 1, 2, 2, 1, 2, 1, 2, 1, 1, 1, 1, 1, 2, 1, 2, 1, 2, 2, 1, 1],
    [1, 2, 2, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 2, 2, 1],
    [1, 2, 1, 1, 1, 1, 1, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 2, 1],
    [1, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 1], // Golden heart at (21,1) and (21,19)
    [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
];

let map = JSON.parse(JSON.stringify(defaultMap));

let randomTargetsForGhosts = [
    { x: 1 * oneBlockSize, y: 1 * oneBlockSize },
    { x: 1 * oneBlockSize, y: (map.length - 2) * oneBlockSize },
    { x: (map[0].length - 2) * oneBlockSize, y: oneBlockSize },
    {
        x: (map[0].length - 2) * oneBlockSize,
        y: (map.length - 2) * oneBlockSize,
    },
];

let createNewPacman = () => {
    pacman = new Pacman(
        oneBlockSize,
        oneBlockSize,
        oneBlockSize,
        oneBlockSize,
        oneBlockSize / 5
    );
};

let gameLoop = () => {
    update();
    draw();
};

let gameInterval = setInterval(gameLoop, 1000 / fps);

let restartPacmanAndGhosts = () => {
    createNewPacman();
    createGhosts();
};

// Power pellet frightened state tracking
let frightenedTimer = null;
let isFrightened = false;

let triggerFrightenedMode = () => {
    isFrightened = true;
    ghosts.forEach(g => {
        g.isFrightened = true;
    });
    
    if (frightenedTimer) clearTimeout(frightenedTimer);
    frightenedTimer = setTimeout(() => {
        isFrightened = false;
        ghosts.forEach(g => {
            g.isFrightened = false;
        });
    }, 7000); // lasts 7 seconds
};

let onGhostCollision = () => {
    lives--;
    if (lives <= 0) {
        gameState = STATE_GAMEOVER;
        stopBGM();
        playGameOverSFX();
        document.getElementById("final-score").innerText = score;
        document.getElementById("game-over-screen").classList.remove("hidden");
    } else {
        restartPacmanAndGhosts();
        spawnAdditionalGoldenHeart(); // Spawn a Golden Heart for the new life!
    }
};

let checkGhostCollisionWithPacman = () => {
    for (let i = 0; i < ghosts.length; i++) {
        let ghost = ghosts[i];
        if (
            ghost.getMapX() == pacman.getMapX() &&
            ghost.getMapY() == pacman.getMapY()
        ) {
            return ghost;
        }
    }
    return null;
};

let update = () => {
    if (gameState !== STATE_PLAYING) return;

    pacman.moveProcess();
    pacman.eat();
    updateGhosts();
    
    // Handle ghost collisions
    let collidedGhost = checkGhostCollisionWithPacman();
    if (collidedGhost) {
        if (collidedGhost.isFrightened) {
            // Eat the ghost (hug mode!)
            playTone(392.00, 0.08, "sine", 0.2);
            setTimeout(() => playTone(523.25, 0.08, "sine", 0.2), 50);
            setTimeout(() => playTone(659.25, 0.08, "sine", 0.2), 100);
            
            // Remove the ghost completely from the ghosts array!
            let ghostIndex = ghosts.indexOf(collidedGhost);
            if (ghostIndex > -1) {
                ghosts.splice(ghostIndex, 1);
            }
            
            score += 10;
            spawnLoveMessage(pacman.x + oneBlockSize / 2, pacman.y);
            
            // Immediately end frightened mode for all remaining ghosts!
            isFrightened = false;
            ghosts.forEach(g => {
                g.isFrightened = false;
            });
            if (frightenedTimer) {
                clearTimeout(frightenedTimer);
                frightenedTimer = null;
            }
        } else {
            onGhostCollision();
        }
    }
    
    checkWinCondition();
    updateParticles();
    updateFloatingTexts();
};

let checkWinCondition = () => {
    let hasFood = false;
    for (let i = 0; i < map.length; i++) {
        for (let j = 0; j < map[0].length; j++) {
            if (map[i][j] == 2 || map[i][j] == 4) {
                hasFood = true;
                break;
            }
        }
        if (hasFood) break;
    }
    if (!hasFood) {
        gameState = STATE_VICTORY;
        stopBGM();
        playWinSFX();
        document.getElementById("victory-score").innerText = score;
        document.getElementById("victory-screen").classList.remove("hidden");
    }
};

let drawFoods = () => {
    for (let i = 0; i < map.length; i++) {
        for (let j = 0; j < map[0].length; j++) {
            if (map[i][j] == 2) {
                drawHeart(
                    j * oneBlockSize + oneBlockSize / 2,
                    i * oneBlockSize + oneBlockSize / 3,
                    6,
                    "#ff1a53"
                );
            } else if (map[i][j] == 4) {
                // Pulsing Golden Hearts
                let pulse = 7 + Math.sin(Date.now() / 150) * 1.5;
                drawHeart(
                    j * oneBlockSize + oneBlockSize / 2,
                    i * oneBlockSize + oneBlockSize / 3,
                    pulse,
                    "#ffd700"
                );
            }
        }
    }
};

let drawRemainingLives = () => {
    canvasContext.font = "14px 'Press Start 2P'";
    canvasContext.fillStyle = "#d81b60";
    canvasContext.fillText("Lives: ", 220, oneBlockSize * (map.length + 1));

    for (let i = 0; i < lives; i++) {
        canvasContext.drawImage(
            pacmanFrames,
            2 * oneBlockSize,
            0,
            oneBlockSize,
            oneBlockSize,
            330 + i * oneBlockSize, // shifted left to fit aligned map
            oneBlockSize * map.length + 2,
            oneBlockSize,
            oneBlockSize
        );
    }
};

let drawScore = () => {
    canvasContext.font = "14px 'Press Start 2P'";
    canvasContext.fillStyle = "#d81b60";
    canvasContext.fillText(
        "Score: " + score,
        40, // aligned with translated map start x
        oneBlockSize * (map.length + 1)
    );
};

let draw = () => {
    canvasContext.clearRect(0, 0, canvas.width, canvas.height);
    createRect(0, 0, canvas.width, canvas.height, "#fff9fa"); // Soft pink-white background
    
    // Centering context translation
    canvasContext.save();
    canvasContext.translate(40, 0); // Shift horizontally by 40px to center the 420px map in 500px canvas!
    
    drawWalls();
    drawFoods();
    drawGhosts();
    pacman.draw();
    drawParticles();
    drawFloatingTexts();
    
    canvasContext.restore();
    
    // Draw HUD outside translation
    drawScore();
    drawRemainingLives();
};

let drawWalls = () => {
    for (let i = 0; i < map.length; i++) {
        for (let j = 0; j < map[0].length; j++) {
            if (map[i][j] == 1) {
                createRect(
                    j * oneBlockSize,
                    i * oneBlockSize,
                    oneBlockSize,
                    oneBlockSize,
                    "#ff6f91" // Pretty pastel rose pink
                );
                if (j > 0 && map[i][j - 1] == 1) {
                    createRect(
                        j * oneBlockSize,
                        i * oneBlockSize + wallOffset,
                        wallSpaceWidth + wallOffset,
                        wallSpaceWidth,
                        wallInnerColor
                    );
                }

                if (j < map[0].length - 1 && map[i][j + 1] == 1) {
                    createRect(
                        j * oneBlockSize + wallOffset,
                        i * oneBlockSize + wallOffset,
                        wallSpaceWidth + wallOffset,
                        wallSpaceWidth,
                        wallInnerColor
                    );
                }

                if (i < map.length - 1 && map[i + 1][j] == 1) {
                    createRect(
                        j * oneBlockSize + wallOffset,
                        i * oneBlockSize + wallOffset,
                        wallSpaceWidth,
                        wallSpaceWidth + wallOffset,
                        wallInnerColor
                    );
                }

                if (i > 0 && map[i - 1][j] == 1) {
                    createRect(
                        j * oneBlockSize + wallOffset,
                        i * oneBlockSize,
                        wallSpaceWidth,
                        wallSpaceWidth + wallOffset,
                        wallInnerColor
                    );
                }
            }
        }
    }
};

let createGhosts = () => {
    ghosts = [];
    for (let i = 0; i < ghostCount * 2; i++) {
        let newGhost = new Ghost(
            9 * oneBlockSize + (i % 2 == 0 ? 0 : 1) * oneBlockSize,
            10 * oneBlockSize + (i % 2 == 0 ? 0 : 1) * oneBlockSize,
            oneBlockSize,
            oneBlockSize,
            pacman.speed / 2,
            ghostImageLocations[i % 4].x,
            ghostImageLocations[i % 4].y,
            124,
            116,
            6 + i
        );
        ghosts.push(newGhost);
    }
};

let resetGame = () => {
    lives = 3;
    score = 0;
    map = JSON.parse(JSON.stringify(defaultMap));
    gameState = STATE_PLAYING;
    isFrightened = false;
    if (frightenedTimer) clearTimeout(frightenedTimer);
    restartPacmanAndGhosts();
    document.getElementById("game-over-screen").classList.add("hidden");
    document.getElementById("victory-screen").classList.add("hidden");
    playBGM();
};

let startGame = () => {
    gameState = STATE_PLAYING;
    document.getElementById("start-screen").classList.add("hidden");
    playBGM();
};

// Bind HTML overlay buttons
document.getElementById("start-button").addEventListener("click", startGame);
document.getElementById("restart-button").addEventListener("click", resetGame);
document.getElementById("win-restart-button").addEventListener("click", resetGame);

// Audio Toggle Button binding
const audioToggleBtn = document.getElementById("audio-toggle");
audioToggleBtn.addEventListener("click", () => {
    isMuted = !isMuted;
    if (isMuted) {
        audioToggleBtn.innerText = "💔 MUSIC OFF";
        audioToggleBtn.style.background = "rgba(113, 128, 150, 0.85)";
        stopBGM();
    } else {
        audioToggleBtn.innerText = "❤️ MUSIC ON";
        audioToggleBtn.style.background = "rgba(216, 27, 96, 0.85)";
        if (gameState === STATE_PLAYING) {
            playBGM();
        }
    }
});

createNewPacman();
createGhosts();
gameLoop();

window.addEventListener("keydown", (event) => {
    if (gameState !== STATE_PLAYING) return;
    let k = event.keyCode;
    setTimeout(() => {
        if (k == 37 || k == 65) {
            pacman.nextDirection = DIRECTION_LEFT;
        } else if (k == 38 || k == 87) {
            pacman.nextDirection = DIRECTION_UP;
        } else if (k == 39 || k == 68) {
            pacman.nextDirection = DIRECTION_RIGHT;
        } else if (k == 40 || k == 83) {
            pacman.nextDirection = DIRECTION_BOTTOM;
        }
    }, 1);
});