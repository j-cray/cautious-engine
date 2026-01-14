/**
 * Tests for Cautious Engine
 */

const cautiousEngine = require('./index.js');

// Track test results
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

// String validation tests
test('validateString accepts valid strings', () => {
  const result = cautiousEngine.validateString('Hello World');
  assert(result.valid === true, 'Should be valid');
  assert(result.errors.length === 0, 'Should have no errors');
});

test('validateString rejects non-strings', () => {
  const result = cautiousEngine.validateString(123);
  assert(result.valid === false, 'Should be invalid');
  assert(result.errors.length > 0, 'Should have errors');
});

test('validateString rejects empty strings by default', () => {
  const result = cautiousEngine.validateString('');
  assert(result.valid === false, 'Should be invalid');
});

test('validateString accepts empty strings when allowed', () => {
  const result = cautiousEngine.validateString('', { allowEmpty: true });
  assert(result.valid === true, 'Should be valid');
});

test('validateString rejects strings with null bytes', () => {
  const result = cautiousEngine.validateString('Hello\0World');
  assert(result.valid === false, 'Should be invalid');
});

test('validateString rejects strings exceeding maxLength', () => {
  const result = cautiousEngine.validateString('x'.repeat(100), { maxLength: 50 });
  assert(result.valid === false, 'Should be invalid');
});

// Number validation tests
test('validateNumber accepts valid numbers', () => {
  const result = cautiousEngine.validateNumber(42);
  assert(result.valid === true, 'Should be valid');
});

test('validateNumber rejects NaN', () => {
  const result = cautiousEngine.validateNumber(NaN);
  assert(result.valid === false, 'Should be invalid');
});

test('validateNumber rejects non-numbers', () => {
  const result = cautiousEngine.validateNumber('42');
  assert(result.valid === false, 'Should be invalid');
});

test('validateNumber checks min/max bounds', () => {
  const result = cautiousEngine.validateNumber(150, { min: 0, max: 100 });
  assert(result.valid === false, 'Should be invalid');
});

// HTML sanitization tests
test('sanitizeHTML escapes HTML entities', () => {
  const result = cautiousEngine.sanitizeHTML('<script>alert("xss")</script>');
  assert(!result.includes('<script>'), 'Should escape script tags');
  assert(result.includes('&lt;'), 'Should contain escaped brackets');
});

test('sanitizeHTML handles non-strings', () => {
  const result = cautiousEngine.sanitizeHTML(null);
  assert(result === '', 'Should return empty string');
});

// Email validation tests
test('validateEmail accepts valid emails', () => {
  const result = cautiousEngine.validateEmail('user@example.com');
  assert(result.valid === true, 'Should be valid');
});

test('validateEmail rejects invalid emails', () => {
  const result = cautiousEngine.validateEmail('not-an-email');
  assert(result.valid === false, 'Should be invalid');
});

test('validateEmail rejects non-strings', () => {
  const result = cautiousEngine.validateEmail(null);
  assert(result.valid === false, 'Should be invalid');
});

// URL validation tests
test('validateURL accepts valid URLs', () => {
  const result = cautiousEngine.validateURL('https://example.com');
  assert(result.valid === true, 'Should be valid');
});

test('validateURL rejects invalid URLs', () => {
  const result = cautiousEngine.validateURL('not a url');
  assert(result.valid === false, 'Should be invalid');
});

test('validateURL rejects disallowed protocols', () => {
  const result = cautiousEngine.validateURL('javascript:alert(1)');
  assert(result.valid === false, 'Should be invalid');
});

test('validateURL accepts custom protocols', () => {
  const result = cautiousEngine.validateURL('ftp://example.com', { allowedProtocols: ['ftp:'] });
  assert(result.valid === true, 'Should be valid with custom protocols');
});

// JSON parsing tests
test('safeJSONParse handles valid JSON', () => {
  const result = cautiousEngine.safeJSONParse('{"key": "value"}');
  assert(result.success === true, 'Should succeed');
  assert(result.data.key === 'value', 'Should parse correctly');
});

test('safeJSONParse handles invalid JSON', () => {
  const result = cautiousEngine.safeJSONParse('{invalid}');
  assert(result.success === false, 'Should fail');
  assert(result.error !== null, 'Should have error message');
});

// Required properties tests
test('validateRequiredProps accepts objects with all required props', () => {
  const result = cautiousEngine.validateRequiredProps({ a: 1, b: 2 }, ['a', 'b']);
  assert(result.valid === true, 'Should be valid');
});

test('validateRequiredProps rejects objects missing required props', () => {
  const result = cautiousEngine.validateRequiredProps({ a: 1 }, ['a', 'b']);
  assert(result.valid === false, 'Should be invalid');
});

test('validateRequiredProps rejects non-objects', () => {
  const result = cautiousEngine.validateRequiredProps(null, ['a']);
  assert(result.valid === false, 'Should be invalid');
});

// Print summary
console.log('\n' + '='.repeat(50));
console.log(`Tests passed: ${passed}`);
console.log(`Tests failed: ${failed}`);
console.log('='.repeat(50));

process.exit(failed > 0 ? 1 : 0);
