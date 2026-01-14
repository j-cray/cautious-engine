const cautiousEngine = require('./index.js');

console.log('='.repeat(60));
console.log('Cautious Engine - Usage Examples');
console.log('='.repeat(60));

// Example 1: String Validation
console.log('\n1. String Validation:');
console.log('-'.repeat(40));
const stringTest1 = cautiousEngine.validateString('Hello, World!');
console.log('Input: "Hello, World!"');
console.log('Result:', stringTest1);

const stringTest2 = cautiousEngine.validateString('');
console.log('\nInput: "" (empty string)');
console.log('Result:', stringTest2);

const stringTest3 = cautiousEngine.validateString('x'.repeat(100), { maxLength: 50 });
console.log('\nInput: 100 character string with maxLength: 50');
console.log('Result:', stringTest3);

// Example 2: Number Validation
console.log('\n\n2. Number Validation:');
console.log('-'.repeat(40));
const numberTest1 = cautiousEngine.validateNumber(42, { min: 0, max: 100 });
console.log('Input: 42 (min: 0, max: 100)');
console.log('Result:', numberTest1);

const numberTest2 = cautiousEngine.validateNumber(150, { min: 0, max: 100 });
console.log('\nInput: 150 (min: 0, max: 100)');
console.log('Result:', numberTest2);

const numberTest3 = cautiousEngine.validateNumber(NaN);
console.log('\nInput: NaN');
console.log('Result:', numberTest3);

// Example 3: HTML Sanitization
console.log('\n\n3. HTML Sanitization:');
console.log('-'.repeat(40));
const dangerousHTML = '<script>alert("XSS")</script>';
const safeHTML = cautiousEngine.sanitizeHTML(dangerousHTML);
console.log('Input:', dangerousHTML);
console.log('Sanitized:', safeHTML);

const userInput = 'Hello <b>World</b> & "Friends"';
const safeuserInput = cautiousEngine.sanitizeHTML(userInput);
console.log('\nInput:', userInput);
console.log('Sanitized:', safeuserInput);

// Example 4: Email Validation
console.log('\n\n4. Email Validation:');
console.log('-'.repeat(40));
const emailTest1 = cautiousEngine.validateEmail('user@example.com');
console.log('Input: "user@example.com"');
console.log('Result:', emailTest1);

const emailTest2 = cautiousEngine.validateEmail('invalid-email');
console.log('\nInput: "invalid-email"');
console.log('Result:', emailTest2);

// Example 5: URL Validation
console.log('\n\n5. URL Validation:');
console.log('-'.repeat(40));
const urlTest1 = cautiousEngine.validateURL('https://github.com/j-cray/cautious-engine');
console.log('Input: "https://github.com/j-cray/cautious-engine"');
console.log('Result:', urlTest1);

const urlTest2 = cautiousEngine.validateURL('javascript:alert(1)');
console.log('\nInput: "javascript:alert(1)"');
console.log('Result:', urlTest2);

// Example 6: Safe JSON Parsing
console.log('\n\n6. Safe JSON Parsing:');
console.log('-'.repeat(40));
const jsonTest1 = cautiousEngine.safeJSONParse('{"name": "cautious-engine", "version": "1.0.0"}');
console.log('Input: \'{"name": "cautious-engine", "version": "1.0.0"}\'');
console.log('Result:', jsonTest1);

const jsonTest2 = cautiousEngine.safeJSONParse('{invalid json}');
console.log('\nInput: \'{invalid json}\'');
console.log('Result:', jsonTest2);

// Example 7: Required Properties Validation
console.log('\n\n7. Required Properties Validation:');
console.log('-'.repeat(40));
const config = { host: 'localhost', port: 3000 };
const propsTest1 = cautiousEngine.validateRequiredProps(config, ['host', 'port']);
console.log('Input: { host: "localhost", port: 3000 }');
console.log('Required: ["host", "port"]');
console.log('Result:', propsTest1);

const incompleteConfig = { host: 'localhost' };
const propsTest2 = cautiousEngine.validateRequiredProps(incompleteConfig, ['host', 'port', 'database']);
console.log('\nInput: { host: "localhost" }');
console.log('Required: ["host", "port", "database"]');
console.log('Result:', propsTest2);

console.log('\n' + '='.repeat(60));
