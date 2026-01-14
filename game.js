#!/usr/bin/env node

/**
 * CAUTIOUS ENGINE - Interactive ASCII Dungeon Crawler
 * Navigate dangerous dungeons where one wrong move could be your last!
 * Be cautious, be smart, survive!
 */

const readline = require('readline');

// ANSI color codes for cool terminal effects
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m'
};

class CautiousEngine {
  constructor() {
    this.width = 50;
    this.height = 15;
    this.player = { x: 2, y: 2, health: 100, coins: 0, moves: 0 };
    this.exit = { x: 47, y: 12 };
    this.traps = this.generateTraps();
    this.treasures = this.generateTreasures();
    this.enemies = this.generateEnemies();
    this.gameOver = false;
    this.won = false;
    this.rl = null;
    this.cautionMode = true; // Players must be cautious!
    this.warnings = [];
  }

  generateTraps() {
    const traps = [];
    for (let i = 0; i < 20; i++) {
      traps.push({
        x: Math.floor(Math.random() * (this.width - 4)) + 2,
        y: Math.floor(Math.random() * (this.height - 4)) + 2,
        damage: 20,
        visible: Math.random() > 0.5 // Some traps are hidden!
      });
    }
    return traps;
  }

  generateTreasures() {
    const treasures = [];
    for (let i = 0; i < 10; i++) {
      treasures.push({
        x: Math.floor(Math.random() * (this.width - 4)) + 2,
        y: Math.floor(Math.random() * (this.height - 4)) + 2,
        value: Math.floor(Math.random() * 50) + 10
      });
    }
    return treasures;
  }

  generateEnemies() {
    const enemies = [];
    for (let i = 0; i < 8; i++) {
      enemies.push({
        x: Math.floor(Math.random() * (this.width - 4)) + 2,
        y: Math.floor(Math.random() * (this.height - 4)) + 2,
        damage: 15,
        alive: true
      });
    }
    return enemies;
  }

  checkDanger(x, y) {
    const dangers = [];
    
    // Check for traps nearby
    const nearbyTraps = this.traps.filter(t => 
      Math.abs(t.x - x) <= 1 && Math.abs(t.y - y) <= 1
    );
    if (nearbyTraps.length > 0) {
      dangers.push(`${colors.yellow}⚠ CAUTION: Trap detected nearby!${colors.reset}`);
    }

    // Check for enemies nearby
    const nearbyEnemies = this.enemies.filter(e => 
      e.alive && Math.abs(e.x - x) <= 2 && Math.abs(e.y - y) <= 2
    );
    if (nearbyEnemies.length > 0) {
      dangers.push(`${colors.red}⚠ CAUTION: Enemy nearby!${colors.reset}`);
    }

    return dangers;
  }

  move(dx, dy) {
    if (this.gameOver) return;

    const newX = this.player.x + dx;
    const newY = this.player.y + dy;

    // Check boundaries
    if (newX < 1 || newX >= this.width - 1 || newY < 1 || newY >= this.height - 1) {
      this.warnings = [`${colors.red}Can't move there - wall!${colors.reset}`];
      return;
    }

    this.warnings = [];
    this.player.x = newX;
    this.player.y = newY;
    this.player.moves++;

    // Check for exit
    if (this.player.x === this.exit.x && this.player.y === this.exit.y) {
      this.won = true;
      this.gameOver = true;
      return;
    }

    // Check for traps
    const trap = this.traps.find(t => t.x === newX && t.y === newY);
    if (trap) {
      this.player.health -= trap.damage;
      this.warnings.push(`${colors.red}💥 OUCH! Stepped on a trap! -${trap.damage} HP${colors.reset}`);
      this.traps = this.traps.filter(t => t !== trap);
      
      if (this.player.health <= 0) {
        this.gameOver = true;
        return;
      }
    }

    // Check for treasures
    const treasure = this.treasures.find(t => t.x === newX && t.y === newY);
    if (treasure) {
      this.player.coins += treasure.value;
      this.warnings.push(`${colors.yellow}✨ Found treasure! +${treasure.value} coins${colors.reset}`);
      this.treasures = this.treasures.filter(t => t !== treasure);
    }

    // Check for enemies
    const enemy = this.enemies.find(e => e.alive && e.x === newX && e.y === newY);
    if (enemy) {
      this.player.health -= enemy.damage;
      enemy.alive = false;
      this.warnings.push(`${colors.red}⚔️  Fought an enemy! -${enemy.damage} HP${colors.reset}`);
      
      if (this.player.health <= 0) {
        this.gameOver = true;
        return;
      }
    }

    // Check for dangers ahead
    const dangers = this.checkDanger(this.player.x, this.player.y);
    this.warnings.push(...dangers);
  }

  render() {
    console.clear();
    
    // Title banner
    console.log(`${colors.bright}${colors.cyan}
╔═══════════════════════════════════════════════════════════╗
║         🏰 CAUTIOUS ENGINE - DUNGEON CRAWLER 🏰          ║
║              One wrong step could be your last!           ║
╚═══════════════════════════════════════════════════════════╝${colors.reset}\n`);

    // Stats bar
    const healthBar = '█'.repeat(Math.max(0, Math.floor(this.player.health / 5)));
    const healthColor = this.player.health > 60 ? colors.green : 
                       this.player.health > 30 ? colors.yellow : colors.red;
    
    console.log(`${healthColor}HP: ${healthBar} ${this.player.health}${colors.reset}  ` +
                `${colors.yellow}Coins: ${this.player.coins}${colors.reset}  ` +
                `Moves: ${this.player.moves}\n`);

    // Render dungeon
    for (let y = 0; y < this.height; y++) {
      let row = '';
      for (let x = 0; x < this.width; x++) {
        // Walls
        if (y === 0 || y === this.height - 1 || x === 0 || x === this.width - 1) {
          row += `${colors.bright}█${colors.reset}`;
        }
        // Player
        else if (x === this.player.x && y === this.player.y) {
          row += `${colors.green}${colors.bright}@${colors.reset}`;
        }
        // Exit
        else if (x === this.exit.x && y === this.exit.y) {
          row += `${colors.magenta}${colors.bright}E${colors.reset}`;
        }
        // Enemies
        else if (this.enemies.find(e => e.alive && e.x === x && e.y === y)) {
          row += `${colors.red}M${colors.reset}`;
        }
        // Treasures
        else if (this.treasures.find(t => t.x === x && t.y === y)) {
          row += `${colors.yellow}$${colors.reset}`;
        }
        // Visible traps
        else if (this.traps.find(t => t.visible && t.x === x && t.y === y)) {
          row += `${colors.red}^${colors.reset}`;
        }
        // Empty space
        else {
          row += ' ';
        }
      }
      console.log(row);
    }

    console.log(`\n${colors.cyan}Legend: ${colors.green}@ = You${colors.reset}  ` +
                `${colors.magenta}E = Exit${colors.reset}  ` +
                `${colors.yellow}$ = Treasure${colors.reset}  ` +
                `${colors.red}M = Enemy  ^ = Trap${colors.reset}\n`);

    // Display warnings
    if (this.warnings.length > 0) {
      this.warnings.forEach(w => console.log(w));
      console.log();
    }

    // Controls
    console.log(`${colors.bright}Controls:${colors.reset} W/A/S/D to move  Q to quit\n`);
  }

  async start() {
    return new Promise((resolve) => {
      this.rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
      });

      // Set raw mode for immediate key capture
      if (process.stdin.setRawMode) {
        process.stdin.setRawMode(true);
      }
      
      readline.emitKeypressEvents(process.stdin);

      this.render();

      process.stdin.on('keypress', (str, key) => {
        if (this.gameOver) return;

        if (key.ctrl && key.name === 'c' || key.name === 'q') {
          this.cleanup();
          resolve();
          return;
        }

        switch (key.name) {
          case 'w':
          case 'up':
            this.move(0, -1);
            break;
          case 's':
          case 'down':
            this.move(0, 1);
            break;
          case 'a':
          case 'left':
            this.move(-1, 0);
            break;
          case 'd':
          case 'right':
            this.move(1, 0);
            break;
        }

        this.render();

        if (this.gameOver) {
          this.showEndScreen();
          setTimeout(() => {
            this.cleanup();
            resolve();
          }, 3000);
        }
      });
    });
  }

  showEndScreen() {
    console.log('\n' + '='.repeat(60));
    if (this.won) {
      console.log(`${colors.green}${colors.bright}
🎉 VICTORY! 🎉
You cautiously navigated the dungeon and escaped!

Final Score:
  Coins Collected: ${this.player.coins}
  Health Remaining: ${this.player.health}
  Moves Taken: ${this.player.moves}
  Total Score: ${this.player.coins * 10 + this.player.health + (1000 - this.player.moves * 5)}

You are a true master of caution!
${colors.reset}`);
    } else {
      console.log(`${colors.red}${colors.bright}
💀 GAME OVER 💀
You were not cautious enough and perished in the dungeon!

Final Stats:
  Coins Collected: ${this.player.coins}
  Moves Taken: ${this.player.moves}

Better luck next time! Remember: CAUTION is key!
${colors.reset}`);
    }
    console.log('='.repeat(60));
  }

  cleanup() {
    if (this.rl) {
      this.rl.close();
    }
    if (process.stdin.setRawMode) {
      process.stdin.setRawMode(false);
    }
    process.stdin.pause();
  }
}

// Run the game if executed directly
if (require.main === module) {
  const game = new CautiousEngine();
  game.start().then(() => {
    process.exit(0);
  });
}

module.exports = CautiousEngine;
