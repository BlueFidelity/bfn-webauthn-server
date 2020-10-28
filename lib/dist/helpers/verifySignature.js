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
 * Verify an authenticator's signature
 *
 * @param signature attStmt.sig
 * @param signatureBase Output from Buffer.concat()
 * @param publicKey Authenticator's public key as a PEM certificate
 * @param algo Which algorithm to use to verify the signature (default: `'sha256'`)
 */


function verifySignature(signature, signatureBase, publicKey) {
  let algo = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : 'sha256';
  return crypto_1.default.createVerify(algo).update(signatureBase).verify(publicKey, signature);
}

exports.default = verifySignature;