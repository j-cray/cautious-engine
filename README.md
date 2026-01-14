# cautious-engine

A validation and safety-checking utility that helps developers avoid common mistakes by providing robust input validation, sanitization, and safety checks.

## 🛡️ What does cautious-engine do?

The **cautious-engine** is a lightweight JavaScript library designed to help you write safer, more reliable code. It provides a collection of validation and sanitization functions that help prevent common security vulnerabilities and programming errors.

### Key Features

- **String Validation**: Validate strings with configurable length limits and safety checks
- **Number Validation**: Ensure numbers are within safe bounds and not NaN/Infinity
- **HTML Sanitization**: Escape HTML entities to prevent XSS attacks
- **Email Validation**: Verify email format with reasonable constraints
- **URL Validation**: Check URLs and restrict to safe protocols
- **Safe JSON Parsing**: Parse JSON with proper error handling
- **Required Properties**: Validate objects have all required fields

## 📦 Installation

```bash
# Clone or copy the files to your project
npm install
```

## 🚀 Quick Start

```javascript
const cautiousEngine = require('./index.js');

// Validate a string
const result = cautiousEngine.validateString('Hello World');
console.log(result); // { valid: true, errors: [] }

// Sanitize HTML to prevent XSS
const safe = cautiousEngine.sanitizeHTML('<script>alert("XSS")</script>');
console.log(safe); // &lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;

// Validate email format
const email = cautiousEngine.validateEmail('user@example.com');
console.log(email); // { valid: true, errors: [] }
```

## 📖 API Reference

### `validateString(value, options)`

Validates if a value is a safe string.

**Parameters:**
- `value` (string): The value to validate
- `options` (Object):
  - `maxLength` (number): Maximum allowed length (default: 10000)
  - `allowEmpty` (boolean): Allow empty strings (default: false)

**Returns:** `{ valid: boolean, errors: string[] }`

**Example:**
```javascript
cautiousEngine.validateString('Hello', { maxLength: 100 });
// { valid: true, errors: [] }

cautiousEngine.validateString('', { allowEmpty: false });
// { valid: false, errors: ['String cannot be empty'] }
```

### `validateNumber(value, options)`

Validates if a number is within safe bounds.

**Parameters:**
- `value` (number): The value to validate
- `options` (Object):
  - `min` (number): Minimum allowed value
  - `max` (number): Maximum allowed value

**Returns:** `{ valid: boolean, errors: string[] }`

**Example:**
```javascript
cautiousEngine.validateNumber(42, { min: 0, max: 100 });
// { valid: true, errors: [] }

cautiousEngine.validateNumber(NaN);
// { valid: false, errors: ['Value is NaN'] }
```

### `sanitizeHTML(value)`

Sanitizes a string for safe use in HTML contexts by escaping special characters.

**Parameters:**
- `value` (string): The string to sanitize

**Returns:** `string` - Sanitized string

**Example:**
```javascript
cautiousEngine.sanitizeHTML('<script>alert("XSS")</script>');
// &lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;
```

### `validateEmail(email)`

Validates an email address format.

**Parameters:**
- `email` (string): The email to validate

**Returns:** `{ valid: boolean, errors: string[] }`

**Example:**
```javascript
cautiousEngine.validateEmail('user@example.com');
// { valid: true, errors: [] }
```

### `validateURL(url, options)`

Validates a URL format and checks for safe protocols.

**Parameters:**
- `url` (string): The URL to validate
- `options` (Object):
  - `allowedProtocols` (string[]): Allowed protocols (default: ['http:', 'https:'])

**Returns:** `{ valid: boolean, errors: string[] }`

**Example:**
```javascript
cautiousEngine.validateURL('https://example.com');
// { valid: true, errors: [] }

cautiousEngine.validateURL('javascript:alert(1)');
// { valid: false, errors: ['Protocol javascript: is not allowed'] }
```

### `safeJSONParse(jsonString)`

Safely parses JSON with error handling.

**Parameters:**
- `jsonString` (string): The JSON string to parse

**Returns:** `{ success: boolean, data: any, error: string }`

**Example:**
```javascript
cautiousEngine.safeJSONParse('{"key": "value"}');
// { success: true, data: { key: 'value' }, error: null }

cautiousEngine.safeJSONParse('{invalid}');
// { success: false, data: null, error: '...' }
```

### `validateRequiredProps(obj, requiredProps)`

Validates an object has required properties.

**Parameters:**
- `obj` (Object): The object to validate
- `requiredProps` (string[]): Required property names

**Returns:** `{ valid: boolean, errors: string[] }`

**Example:**
```javascript
cautiousEngine.validateRequiredProps({ a: 1, b: 2 }, ['a', 'b']);
// { valid: true, errors: [] }

cautiousEngine.validateRequiredProps({ a: 1 }, ['a', 'b']);
// { valid: false, errors: ['Missing required property: b'] }
```

## 🧪 Testing

Run the test suite:

```bash
npm test
```

## 📝 Examples

Run the examples to see the library in action:

```bash
node examples.js
```

## 🎯 Use Cases

- **Input Validation**: Validate user input before processing
- **Security**: Sanitize data to prevent XSS and injection attacks
- **Configuration Validation**: Ensure configuration objects have required fields
- **Data Quality**: Verify data meets expected constraints before using it
- **API Input Checking**: Validate API request parameters
- **Form Validation**: Check form data before submission

## 🤝 Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

## 📄 License

MIT
