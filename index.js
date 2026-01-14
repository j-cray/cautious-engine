/**
 * Cautious Engine - A validation and safety-checking utility
 * 
 * This module provides functions to validate inputs, sanitize data,
 * and perform safety checks to help prevent common programming errors.
 */

class CautiousEngine {
  /**
   * Validates if a value is a safe string (non-empty, no null bytes, reasonable length)
   * @param {string} value - The value to validate
   * @param {Object} options - Validation options
   * @param {number} options.maxLength - Maximum allowed length (default: 10000)
   * @param {boolean} options.allowEmpty - Allow empty strings (default: false)
   * @returns {Object} - { valid: boolean, errors: string[] }
   */
  validateString(value, options = {}) {
    const { maxLength = 10000, allowEmpty = false } = options;
    const errors = [];

    if (typeof value !== 'string') {
      errors.push('Value must be a string');
      return { valid: false, errors };
    }

    if (!allowEmpty && value.length === 0) {
      errors.push('String cannot be empty');
    }

    if (value.length > maxLength) {
      errors.push(`String exceeds maximum length of ${maxLength}`);
    }

    if (value.includes('\0')) {
      errors.push('String contains null bytes');
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Validates if a number is within safe bounds
   * @param {number} value - The value to validate
   * @param {Object} options - Validation options
   * @param {number} options.min - Minimum allowed value
   * @param {number} options.max - Maximum allowed value
   * @returns {Object} - { valid: boolean, errors: string[] }
   */
  validateNumber(value, options = {}) {
    const { min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER } = options;
    const errors = [];

    if (typeof value !== 'number') {
      errors.push('Value must be a number');
      return { valid: false, errors };
    }

    if (isNaN(value)) {
      errors.push('Value is NaN');
    }

    if (!isFinite(value)) {
      errors.push('Value must be finite');
    }

    if (value < min) {
      errors.push(`Value ${value} is below minimum ${min}`);
    }

    if (value > max) {
      errors.push(`Value ${value} exceeds maximum ${max}`);
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Sanitizes a string for safe use in HTML contexts
   * @param {string} value - The string to sanitize
   * @returns {string} - Sanitized string
   */
  sanitizeHTML(value) {
    if (typeof value !== 'string') {
      return '';
    }

    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /**
   * Validates an email address format
   * @param {string} email - The email to validate
   * @returns {Object} - { valid: boolean, errors: string[] }
   */
  validateEmail(email) {
    const errors = [];

    if (typeof email !== 'string') {
      errors.push('Email must be a string');
      return { valid: false, errors };
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      errors.push('Invalid email format');
    }

    if (email.length > 254) {
      errors.push('Email exceeds maximum length');
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Validates a URL format and checks for safe protocols
   * @param {string} url - The URL to validate
   * @param {Object} options - Validation options
   * @param {string[]} options.allowedProtocols - Allowed protocols (default: ['http:', 'https:'])
   * @returns {Object} - { valid: boolean, errors: string[] }
   */
  validateURL(url, options = {}) {
    const { allowedProtocols = ['http:', 'https:'] } = options;
    const errors = [];

    if (typeof url !== 'string') {
      errors.push('URL must be a string');
      return { valid: false, errors };
    }

    let urlObject;
    try {
      urlObject = new URL(url);
    } catch (e) {
      errors.push('Invalid URL format');
      return { valid: false, errors };
    }

    if (!allowedProtocols.includes(urlObject.protocol)) {
      errors.push(`Protocol ${urlObject.protocol} is not allowed`);
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Safely parses JSON with error handling
   * @param {string} jsonString - The JSON string to parse
   * @returns {Object} - { success: boolean, data: any, error: string }
   */
  safeJSONParse(jsonString) {
    try {
      const data = JSON.parse(jsonString);
      return { success: true, data, error: null };
    } catch (e) {
      return { success: false, data: null, error: e.message };
    }
  }

  /**
   * Validates an object has required properties
   * @param {Object} obj - The object to validate
   * @param {string[]} requiredProps - Required property names
   * @returns {Object} - { valid: boolean, errors: string[] }
   */
  validateRequiredProps(obj, requiredProps) {
    const errors = [];

    if (typeof obj !== 'object' || obj === null) {
      errors.push('Value must be an object');
      return { valid: false, errors };
    }

    for (const prop of requiredProps) {
      if (!(prop in obj)) {
        errors.push(`Missing required property: ${prop}`);
      }
    }

    return { valid: errors.length === 0, errors };
  }
}

// Export singleton instance
module.exports = new CautiousEngine();
module.exports.CautiousEngine = CautiousEngine;
