"use strict";

var __importDefault = void 0 && (void 0).__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};

Object.defineProperty(exports, "__esModule", {
  value: true
});

const cbor_1 = __importDefault(require("cbor"));
/**
 * Make sense of the authData buffer contained in an Attestation
 */


function parseAuthenticatorData(authData) {
  if (authData.byteLength < 37) {
    throw new Error("Authenticator data was ".concat(authData.byteLength, " bytes, expected at least 37 bytes"));
  }

  let intBuffer = authData;
  const rpIdHash = intBuffer.slice(0, 32);
  intBuffer = intBuffer.slice(32);
  const flagsBuf = intBuffer.slice(0, 1);
  intBuffer = intBuffer.slice(1);
  const flagsInt = flagsBuf[0];
  const flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
    flagsInt
  };
  const counterBuf = intBuffer.slice(0, 4);
  intBuffer = intBuffer.slice(4);
  const counter = counterBuf.readUInt32BE(0);
  let aaguid = undefined;
  let credentialID = undefined;
  let credentialPublicKey = undefined;

  if (flags.at) {
    aaguid = intBuffer.slice(0, 16);
    intBuffer = intBuffer.slice(16);
    const credIDLenBuf = intBuffer.slice(0, 2);
    intBuffer = intBuffer.slice(2);
    const credIDLen = credIDLenBuf.readUInt16BE(0);
    credentialID = intBuffer.slice(0, credIDLen);
    intBuffer = intBuffer.slice(credIDLen); // Decode the next CBOR item in the buffer, then re-encode it back to a Buffer

    const firstDecoded = cbor_1.default.decodeFirstSync(intBuffer);
    const firstEncoded = Buffer.from(cbor_1.default.encode(firstDecoded));
    credentialPublicKey = firstEncoded;
    intBuffer = intBuffer.slice(firstEncoded.byteLength);
  }

  let extensionsDataBuffer = undefined;

  if (flags.ed) {
    const firstDecoded = cbor_1.default.decodeFirstSync(intBuffer);
    const firstEncoded = Buffer.from(cbor_1.default.encode(firstDecoded));
    extensionsDataBuffer = firstEncoded;
    intBuffer = intBuffer.slice(firstEncoded.byteLength);
  }

  if (intBuffer.byteLength > 0) {
    throw new Error('Leftover bytes detected while parsing authenticator data');
  }

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credentialID,
    credentialPublicKey,
    extensionsDataBuffer
  };
}

exports.default = parseAuthenticatorData;