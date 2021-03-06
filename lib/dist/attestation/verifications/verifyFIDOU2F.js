"use strict";

require("core-js/modules/es.regexp.to-string");

var __importDefault = void 0 && (void 0).__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};

Object.defineProperty(exports, "__esModule", {
  value: true
});

const convertCOSEtoPKCS_1 = __importDefault(require("../../helpers/convertCOSEtoPKCS"));

const convertX509CertToPEM_1 = __importDefault(require("../../helpers/convertX509CertToPEM"));

const verifySignature_1 = __importDefault(require("../../helpers/verifySignature"));
/**
 * Verify an attestation response with fmt 'fido-u2f'
 */


function verifyAttestationFIDOU2F(options) {
  const {
    attStmt,
    clientDataHash,
    rpIdHash,
    credentialID,
    credentialPublicKey,
    aaguid = ''
  } = options;
  const reservedByte = Buffer.from([0x00]);
  const publicKey = convertCOSEtoPKCS_1.default(credentialPublicKey);
  const signatureBase = Buffer.concat([reservedByte, rpIdHash, clientDataHash, credentialID, publicKey]);
  const {
    sig,
    x5c
  } = attStmt;

  if (!x5c) {
    throw new Error('No attestation certificate provided in attestation statement (FIDOU2F)');
  }

  if (!sig) {
    throw new Error('No attestation signature provided in attestation statement (FIDOU2F)');
  } // FIDO spec says that aaguid _must_ equal 0x00 here to be legit


  const aaguidToHex = Number.parseInt(aaguid.toString('hex'), 16);

  if (aaguidToHex !== 0x00) {
    throw new Error("AAGUID \"".concat(aaguidToHex, "\" was not expected value"));
  }

  const leafCertPEM = convertX509CertToPEM_1.default(x5c[0]);
  return verifySignature_1.default(sig, signatureBase, leafCertPEM);
}

exports.default = verifyAttestationFIDOU2F;