# 🏰 cautious-engine

An **epic ASCII dungeon crawler** where one wrong step could be your last! Navigate treacherous dungeons filled with traps, enemies, and treasure. Being cautious isn't just recommended—it's **essential for survival**.

![Game Banner](https://img.shields.io/badge/Game-ASCII%20Dungeon%20Crawler-purple?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Terminal-blue?style=for-the-badge)

## 🎮 What is cautious-engine?

**Cautious Engine** is an interactive terminal-based adventure game where you explore procedurally generated dungeons. Every move counts, every decision matters, and being cautious is the difference between victory and defeat!

### 🌟 Features

- **🎨 Beautiful ASCII Graphics** - Colorful terminal rendering with ANSI colors
- **⚠️ Caution System** - Get proximity warnings when dangers are near
- **💀 Deadly Traps** - Both visible and hidden traps await the unwary
- **👾 Enemies** - Fight monsters lurking in the darkness
- **💰 Treasures** - Collect coins scattered throughout the dungeon
- **🏆 Scoring System** - Compete for the highest score based on coins, health, and efficiency
- **🎲 Procedural Generation** - Every dungeon is unique
- **⌨️ Smooth Controls** - Responsive WASD movement

## 🚀 Quick Start

```bash
# Clone or download the repository
cd cautious-engine

# Install (no dependencies needed!)
npm install

# Play the game
npm start

# Or watch a demo
npm run demo
```

## 🎯 How to Play

### Objective
Navigate from your starting position **@** to the exit **E** while collecting treasure and avoiding dangers!

### Controls
- **W** or **↑** - Move up
- **A** or **←** - Move left  
- **S** or **↓** - Move down
- **D** or **→** - Move right
- **Q** - Quit game

### Legend
- **@** (Green) - That's you!
- **E** (Magenta) - Exit to victory
- **$** (Yellow) - Treasure (collect for points!)
- **M** (Red) - Enemy (fight them, but take damage)
- **^** (Red) - Visible trap (avoid!)
- **Space** - Could be safe... or a hidden trap!
- **█** - Walls (impassable)

### Strategy Tips

1. **Move Carefully** - Some traps are invisible!
2. **Watch for Warnings** - The caution system alerts you to nearby dangers
3. **Collect Treasure** - More coins = higher score
4. **Conserve Health** - Every hit counts
5. **Plan Your Route** - The shortest path isn't always the safest

## 📊 Scoring

Your final score is calculated based on:
- **Coins Collected** × 10
- **Health Remaining**
- **Movement Efficiency** (fewer moves = bonus points)

Formula: `(Coins × 10) + Health + (1000 - Moves × 5)`

## 🎬 Demo Mode

Want to see the game in action first? Run the demo:

```bash
npm run demo
```

This shows an automated playthrough demonstrating all the game mechanics.

## 🛠️ Technical Details

### Game Engine Features

- **Real-time Input Handling** - Immediate keypress response
- **Collision Detection** - Smart boundary and object collision
- **State Management** - Efficient game state tracking
- **Procedural Generation** - Randomized trap, enemy, and treasure placement
- **Proximity Detection** - Warning system for nearby dangers
- **ANSI Color Support** - Beautiful colored terminal output

### Architecture

```javascript
const CautiousEngine = require('./game.js');

const game = new CautiousEngine();
game.start();
```

The engine is modular and can be extended with:
- Custom dungeon layouts
- New enemy types
- Additional items and power-ups
- Boss battles
- Multiple levels

## 🎨 Screenshots

```
╔═══════════════════════════════════════════════════════════╗
║         🏰 CAUTIOUS ENGINE - DUNGEON CRAWLER 🏰          ║
║              One wrong step could be your last!           ║
╚═══════════════════════════════════════════════════════════╝

HP: ████████████████ 80  Coins: 45  Moves: 23

██████████████████████████████████████████████████
█                                                █
█  @        $                    M               █
█              ^                                 █
█                                                █
█        M                  $                    █
█                    ^                           █
█                              M                 █
█           $                                    █
█                                                █
█                       $                        █
█                                            E   █
█                                                █
██████████████████████████████████████████████████

Legend: @ = You  E = Exit  $ = Treasure  M = Enemy  ^ = Trap

⚠ CAUTION: Trap detected nearby!
⚠ CAUTION: Enemy nearby!

Controls: W/A/S/D to move  Q to quit
```

## 🏅 Example Game Session

```
Starting position: (2, 2)
Move right → Found treasure! +25 coins
Move down → ⚠ CAUTION: Trap detected nearby!
Move right → All clear!
Move down → 💥 OUCH! Stepped on trap! -20 HP
Move right → ⚔️ Fought an enemy! -15 HP
Continue to exit...
🎉 VICTORY! Final Score: 1,285
```

## 🤝 Extending the Game

The Cautious Engine is designed to be hackable! Here are some ideas:

- Add new enemy types with different behaviors
- Create themed dungeons (ice, fire, forest)
- Implement power-ups and healing items
- Add boss fights
- Create a level progression system
- Build a high score leaderboard
- Add sound effects (terminal beeps!)

## 📝 License

MIT - Feel free to use, modify, and distribute!

## 🎮 Pro Tips

- **Patience is key** - Rushing leads to death!
- **Map as you go** - Remember dangerous areas
- **Risk vs Reward** - Is that treasure worth the nearby trap?
- **Health management** - Know when to avoid fights
- **Corner strategy** - Enemies often patrol edges

---

**Remember: In the Cautious Engine, caution isn't cowardice—it's survival!** 🛡️

Ready to test your skills? `npm start` and enter the dungeon! 🏰
