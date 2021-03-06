"use strict";

require("core-js/modules/es.regexp.to-string");

require("core-js/modules/es.string.replace");

var __importDefault = void 0 && (void 0).__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};

Object.defineProperty(exports, "__esModule", {
  value: true
});

const cbor_1 = __importDefault(require("cbor"));

const jwk_to_pem_1 = __importDefault(require("jwk-to-pem"));

const base64url_1 = __importDefault(require("base64url"));

const convertCOSEtoPKCS_1 = require("./convertCOSEtoPKCS");

function convertPublicKeyToPEM(publicKey) {
  const publicKeyBuffer = base64url_1.default.toBuffer(publicKey);
  let struct;

  try {
    struct = cbor_1.default.decodeAllSync(publicKeyBuffer)[0];
  } catch (err) {
    throw new Error("Error decoding public key while converting to PEM: ".concat(err.message));
  }

  const kty = struct.get(convertCOSEtoPKCS_1.COSEKEYS.kty);

  if (!kty) {
    throw new Error('Public key was missing kty');
  }

  if (kty === convertCOSEtoPKCS_1.COSEKTY.EC2) {
    const crv = struct.get(convertCOSEtoPKCS_1.COSEKEYS.crv);
    const x = struct.get(convertCOSEtoPKCS_1.COSEKEYS.x);
    const y = struct.get(convertCOSEtoPKCS_1.COSEKEYS.y);

    if (!crv) {
      throw new Error('Public key was missing crv (EC2)');
    }

    if (!x) {
      throw new Error('Public key was missing x (EC2)');
    }

    if (!y) {
      throw new Error('Public key was missing y (EC2)');
    }

    const ecPEM = jwk_to_pem_1.default({
      kty: 'EC',
      // Specify curve as "P-256" from "p256"
      crv: convertCOSEtoPKCS_1.COSECRV[crv].replace('p', 'P-'),
      x: x.toString('base64'),
      y: y.toString('base64')
    });
    return ecPEM;
  } else if (kty === convertCOSEtoPKCS_1.COSEKTY.RSA) {
    const n = struct.get(convertCOSEtoPKCS_1.COSEKEYS.n);
    const e = struct.get(convertCOSEtoPKCS_1.COSEKEYS.e);

    if (!n) {
      throw new Error('Public key was missing n (RSA)');
    }

    if (!e) {
      throw new Error('Public key was missing e (RSA)');
    }

    const rsaPEM = jwk_to_pem_1.default({
      kty: 'RSA',
      n: n.toString('base64'),
      e: e.toString('base64')
    });
    return rsaPEM;
  }

  throw new Error("Could not convert public key type ".concat(kty, " to PEM"));
}

exports.default = convertPublicKeyToPEM;