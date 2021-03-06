"use strict";

var __importDefault = void 0 && (void 0).__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.COSEALGHASH = exports.COSECRV = exports.COSERSASCHEME = exports.COSEKTY = exports.COSEKEYS = void 0;

const cbor_1 = __importDefault(require("cbor"));
/**
 * Takes COSE-encoded public key and converts it to PKCS key
 */


function convertCOSEtoPKCS(cosePublicKey) {
  const struct = cbor_1.default.decodeFirstSync(cosePublicKey);
  const tag = Buffer.from([0x04]);
  const x = struct.get(COSEKEYS.x);
  const y = struct.get(COSEKEYS.y);

  if (!x) {
    throw new Error('COSE public key was missing x');
  }

  if (y) {
    return Buffer.concat([tag, x, y]);
  }

  return Buffer.concat([tag, x]);
}

exports.default = convertCOSEtoPKCS;
var COSEKEYS;

(function (COSEKEYS) {
  COSEKEYS[COSEKEYS["kty"] = 1] = "kty";
  COSEKEYS[COSEKEYS["alg"] = 3] = "alg";
  COSEKEYS[COSEKEYS["crv"] = -1] = "crv";
  COSEKEYS[COSEKEYS["x"] = -2] = "x";
  COSEKEYS[COSEKEYS["y"] = -3] = "y";
  COSEKEYS[COSEKEYS["n"] = -1] = "n";
  COSEKEYS[COSEKEYS["e"] = -2] = "e";
})(COSEKEYS = exports.COSEKEYS || (exports.COSEKEYS = {}));

var COSEKTY;

(function (COSEKTY) {
  COSEKTY[COSEKTY["OKP"] = 1] = "OKP";
  COSEKTY[COSEKTY["EC2"] = 2] = "EC2";
  COSEKTY[COSEKTY["RSA"] = 3] = "RSA";
})(COSEKTY = exports.COSEKTY || (exports.COSEKTY = {}));

exports.COSERSASCHEME = {
  '-3': 'pss-sha256',
  '-39': 'pss-sha512',
  '-38': 'pss-sha384',
  '-65535': 'pkcs1-sha1',
  '-257': 'pkcs1-sha256',
  '-258': 'pkcs1-sha384',
  '-259': 'pkcs1-sha512'
}; // See https://w3c.github.io/webauthn/#sctn-alg-identifier

exports.COSECRV = {
  // alg: -7
  1: 'p256',
  // alg: -35
  2: 'p384',
  // alg: -36
  3: 'p521',
  // alg: -8
  6: 'ed25519'
};
exports.COSEALGHASH = {
  '-257': 'sha256',
  '-258': 'sha384',
  '-259': 'sha512',
  '-65535': 'sha1',
  '-39': 'sha512',
  '-38': 'sha384',
  '-37': 'sha256',
  '-7': 'sha256',
  '-8': 'sha512',
  '-36': 'sha512'
};