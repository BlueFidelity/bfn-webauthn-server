"use strict";

require("core-js/modules/es.regexp.to-string");

Object.defineProperty(exports, "__esModule", {
  value: true
});
/**
 * Convert the aaguid buffer in authData into a UUID string
 */

function convertAAGUIDToString(aaguid) {
  // Raw Hex: adce000235bcc60a648b0b25f1f05503
  const hex = aaguid.toString('hex');
  const segments = [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32)]; // Formatted: adce0002-35bc-c60a-648b-0b25f1f05503

  return segments.join('-');
}

exports.default = convertAAGUIDToString;