#!/usr/bin/env node

/**
 * Automated tests for Cautious Engine game mechanics
 */

const CautiousEngine = require('./game.js');

console.log('🧪 Testing Cautious Engine...\n');

let passed = 0;
let failed = 0;

function test(description, fn) {
  try {
    fn();
    passed++;
    console.log(`✓ ${description}`);
  } catch (error) {
    failed++;
    console.log(`✗ ${description}`);
    console.log(`  Error: ${error.message}`);
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

// Test 1: Game initialization
test('Game initializes with correct starting state', () => {
  const game = new CautiousEngine();
  assert(game.player.health === 100, 'Player should start with 100 health');
  assert(game.player.coins === 0, 'Player should start with 0 coins');
  assert(game.player.moves === 0, 'Player should start with 0 moves');
  assert(game.gameOver === false, 'Game should not be over at start');
});

// Test 2: Player movement
test('Player can move within boundaries', () => {
  const game = new CautiousEngine();
  const initialX = game.player.x;
  const initialY = game.player.y;
  
  game.move(1, 0); // Move right
  assert(game.player.x === initialX + 1, 'Player should move right');
  assert(game.player.moves === 1, 'Move counter should increment');
});

// Test 3: Boundary checking
test('Player cannot move through walls', () => {
  const game = new CautiousEngine();
  game.player.x = 1;
  game.player.y = 1;
  
  game.move(-1, 0); // Try to move into left wall
  assert(game.player.x === 1, 'Player should not move through wall');
  assert(game.warnings.length > 0, 'Should warn about wall collision');
});

// Test 4: Trap collision
test('Stepping on trap reduces health', () => {
  const game = new CautiousEngine();
  const trap = { x: 10, y: 10, damage: 20, visible: true };
  game.traps = [trap];
  game.player.x = 9;
  game.player.y = 10;
  
  const initialHealth = game.player.health;
  game.move(1, 0); // Move onto trap
  
  assert(game.player.health < initialHealth, 'Health should decrease');
  assert(game.traps.length === 0, 'Trap should be removed after triggering');
});

// Test 5: Treasure collection
test('Collecting treasure increases coins', () => {
  const game = new CautiousEngine();
  const treasure = { x: 10, y: 10, value: 50 };
  game.treasures = [treasure];
  game.player.x = 9;
  game.player.y = 10;
  
  game.move(1, 0); // Move onto treasure
  
  assert(game.player.coins === 50, 'Coins should increase by treasure value');
  assert(game.treasures.length === 0, 'Treasure should be removed after collection');
});

// Test 6: Enemy encounter
test('Fighting enemy reduces health', () => {
  const game = new CautiousEngine();
  const enemy = { x: 10, y: 10, damage: 15, alive: true };
  game.enemies = [enemy];
  game.player.x = 9;
  game.player.y = 10;
  
  const initialHealth = game.player.health;
  game.move(1, 0); // Move onto enemy
  
  assert(game.player.health === initialHealth - 15, 'Health should decrease by enemy damage');
  assert(enemy.alive === false, 'Enemy should be defeated');
});

// Test 7: Danger detection
test('Caution system detects nearby dangers', () => {
  const game = new CautiousEngine();
  game.traps = [{ x: 5, y: 5, damage: 20, visible: true }];
  
  const warnings = game.checkDanger(5, 6); // Check position near trap
  assert(warnings.length > 0, 'Should warn about nearby trap');
});

// Test 8: Victory condition
test('Reaching exit triggers victory', () => {
  const game = new CautiousEngine();
  game.player.x = game.exit.x - 1;
  game.player.y = game.exit.y;
  
  game.move(1, 0); // Move to exit
  
  assert(game.won === true, 'Game should be won');
  assert(game.gameOver === true, 'Game should be over');
});

// Test 9: Death condition
test('Health reaching zero triggers game over', () => {
  const game = new CautiousEngine();
  game.player.health = 10;
  game.traps = [{ x: 5, y: 5, damage: 20, visible: true }];
  game.player.x = 4;
  game.player.y = 5;
  
  game.move(1, 0); // Step on trap that kills player
  
  assert(game.player.health <= 0, 'Health should be zero or negative');
  assert(game.gameOver === true, 'Game should be over');
  assert(game.won === false, 'Player should not have won');
});

// Test 10: Procedural generation
test('Game generates random elements', () => {
  const game1 = new CautiousEngine();
  const game2 = new CautiousEngine();
  
  // Very unlikely to have identical layouts
  const sameTraps = JSON.stringify(game1.traps) === JSON.stringify(game2.traps);
  assert(!sameTraps, 'Traps should be randomly generated');
});

// Print summary
console.log('\n' + '='.repeat(60));
console.log(`✅ Tests passed: ${passed}`);
console.log(`❌ Tests failed: ${failed}`);
console.log('='.repeat(60));

if (failed === 0) {
  console.log('\n🎉 All tests passed! The Cautious Engine is ready to play!\n');
}

process.exit(failed > 0 ? 1 : 0);
