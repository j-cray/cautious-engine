/**
 * DEMO - Automated playthrough of Cautious Engine
 * This demonstrates the game mechanics without user interaction
 */

const CautiousEngine = require('./game.js');

class DemoEngine extends CautiousEngine {
  constructor() {
    super();
    this.autoPlay = true;
  }

  async runDemo() {
    console.log('Starting Cautious Engine Demo...\n');
    console.log('This demo shows an automated playthrough of the dungeon crawler.\n');
    
    await this.sleep(2000);
    
    // Show initial state
    this.render();
    console.log('\n🎮 Demo Mode: Watch the AI navigate the dungeon!\n');
    await this.sleep(2000);

    // Make some strategic moves
    const moves = [
      { dx: 1, dy: 0, desc: 'Moving right...' },
      { dx: 0, dy: 1, desc: 'Moving down...' },
      { dx: 1, dy: 0, desc: 'Moving right...' },
      { dx: 1, dy: 0, desc: 'Moving right...' },
      { dx: 0, dy: 1, desc: 'Heading south...' },
      { dx: 1, dy: 0, desc: 'Moving east...' },
      { dx: 0, dy: 1, desc: 'Going down...' },
      { dx: 1, dy: 0, desc: 'Continuing east...' },
      { dx: 1, dy: 0, desc: 'Almost there...' },
      { dx: 0, dy: 1, desc: 'Moving carefully...' },
    ];

    for (const move of moves) {
      if (this.gameOver) break;
      
      console.log(`\n🎯 ${move.desc}`);
      await this.sleep(1000);
      
      this.move(move.dx, move.dy);
      this.render();
      
      await this.sleep(1500);
    }

    if (!this.gameOver) {
      console.log('\n✨ Demo complete! The game continues...');
      console.log(`\nCurrent Status:
  - Health: ${this.player.health}
  - Coins: ${this.player.coins}
  - Position: (${this.player.x}, ${this.player.y})
  - Exit at: (${this.exit.x}, ${this.exit.y})\n`);
      
      console.log('This shows how the Cautious Engine works:');
      console.log('  ✓ Real-time movement and collision detection');
      console.log('  ✓ Health and damage system');
      console.log('  ✓ Treasure collection');
      console.log('  ✓ Enemy encounters');
      console.log('  ✓ Hidden and visible traps');
      console.log('  ✓ Proximity warnings (caution system!)');
      console.log('  ✓ ASCII art rendering');
      console.log('  ✓ Colorful terminal output\n');
    } else {
      this.showEndScreen();
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Run demo
const demo = new DemoEngine();
demo.runDemo().then(() => {
  console.log('\n🎉 Thanks for watching the demo! Run "npm start" to play yourself!\n');
  process.exit(0);
});
