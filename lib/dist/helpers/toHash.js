"use strict";

var __importDefault = void 0 && (void 0).__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};

Object.defineProperty(exports, "__esModule", {
  value: true
});

const crypto_1 = __importDefault(require("crypto"));
/**
 * Returns hash digest of the given data using the given algorithm.
 * @param data Data to hash
 * @return The hash
 */


function toHash(data) {
  let algo = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'SHA256';
  return crypto_1.default.createHash(algo).update(data).digest();
}

exports.default = toHash;