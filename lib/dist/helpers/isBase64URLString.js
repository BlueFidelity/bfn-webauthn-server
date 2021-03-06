"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
}); // Base64URL, with optional padding

const base64urlRegEx = /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}=?))?$/;
/**
 * Check to see if a string only contains valid Base64URL values
 */

function isBase64URLString(value) {
  if (!value) {
    return false;
  }

  return base64urlRegEx.test(value);
}

exports.default = isBase64URLString;