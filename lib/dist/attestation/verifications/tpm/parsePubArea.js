"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});

const constants_1 = require("./constants");
/**
 * Break apart a TPM attestation's pubArea buffer
 */


function parsePubArea(pubArea) {
  let pubBuffer = pubArea;
  const typeBuffer = pubBuffer.slice(0, 2);
  pubBuffer = pubBuffer.slice(2);
  const type = constants_1.TPM_ALG[typeBuffer.readUInt16BE(0)];
  const nameAlgBuffer = pubBuffer.slice(0, 2);
  pubBuffer = pubBuffer.slice(2);
  const nameAlg = constants_1.TPM_ALG[nameAlgBuffer.readUInt16BE(0)]; // Get some authenticator attributes(?)

  const objectAttributesInt = pubBuffer.slice(0, 4).readUInt32BE(0);
  pubBuffer = pubBuffer.slice(4);
  const objectAttributes = {
    fixedTPM: !!(objectAttributesInt & 1),
    stClear: !!(objectAttributesInt & 2),
    fixedParent: !!(objectAttributesInt & 8),
    sensitiveDataOrigin: !!(objectAttributesInt & 16),
    userWithAuth: !!(objectAttributesInt & 32),
    adminWithPolicy: !!(objectAttributesInt & 64),
    noDA: !!(objectAttributesInt & 512),
    encryptedDuplication: !!(objectAttributesInt & 1024),
    restricted: !!(objectAttributesInt & 32768),
    decrypt: !!(objectAttributesInt & 65536),
    signOrEncrypt: !!(objectAttributesInt & 131072)
  }; // Slice out the authPolicy of dynamic length

  const authPolicyLength = pubBuffer.slice(0, 2).readUInt16BE(0);
  pubBuffer = pubBuffer.slice(2);
  const authPolicy = pubBuffer.slice(0, authPolicyLength);
  pubBuffer = pubBuffer.slice(authPolicyLength); // Extract additional curve params according to type

  const parameters = {};

  if (type === 'TPM_ALG_RSA') {
    const rsaBuffer = pubBuffer.slice(0, 10);
    pubBuffer = pubBuffer.slice(10);
    parameters.rsa = {
      symmetric: constants_1.TPM_ALG[rsaBuffer.slice(0, 2).readUInt16BE(0)],
      scheme: constants_1.TPM_ALG[rsaBuffer.slice(2, 4).readUInt16BE(0)],
      keyBits: rsaBuffer.slice(4, 6).readUInt16BE(0),
      exponent: rsaBuffer.slice(6, 10).readUInt32BE(0)
    };
  } else if (type === 'TPM_ALG_ECC') {
    const eccBuffer = pubBuffer.slice(0, 8);
    pubBuffer = pubBuffer.slice(8);
    parameters.ecc = {
      symmetric: constants_1.TPM_ALG[eccBuffer.slice(0, 2).readUInt16BE(0)],
      scheme: constants_1.TPM_ALG[eccBuffer.slice(2, 4).readUInt16BE(0)],
      curveID: constants_1.TPM_ECC_CURVE[eccBuffer.slice(4, 6).readUInt16BE(0)],
      kdf: constants_1.TPM_ALG[eccBuffer.slice(6, 8).readUInt16BE(0)]
    };
  } else {
    throw new Error("Unexpected type \"".concat(type, "\" (TPM)"));
  } // Slice out unique of dynamic length


  const uniqueLength = pubBuffer.slice(0, 2).readUInt16BE(0);
  pubBuffer = pubBuffer.slice(2);
  const unique = pubBuffer.slice(0, uniqueLength);
  pubBuffer = pubBuffer.slice(uniqueLength);
  return {
    type,
    nameAlg,
    objectAttributes,
    authPolicy,
    parameters,
    unique
  };
}

exports.default = parsePubArea;