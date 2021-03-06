"use strict";

var __importDefault = void 0 && (void 0).__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ATTESTATION_FORMATS = void 0;

const base64url_1 = __importDefault(require("base64url"));

const cbor_1 = __importDefault(require("cbor"));
/**
 * Convert an AttestationObject from base64url string to a proper object
 *
 * @param base64AttestationObject Base64URL-encoded Attestation Object
 */


function decodeAttestationObject(base64AttestationObject) {
  const toBuffer = base64url_1.default.toBuffer(base64AttestationObject);
  const toCBOR = cbor_1.default.decodeAllSync(toBuffer)[0];
  return toCBOR;
}

exports.default = decodeAttestationObject;
var ATTESTATION_FORMATS;

(function (ATTESTATION_FORMATS) {
  ATTESTATION_FORMATS["FIDO_U2F"] = "fido-u2f";
  ATTESTATION_FORMATS["PACKED"] = "packed";
  ATTESTATION_FORMATS["ANDROID_SAFETYNET"] = "android-safetynet";
  ATTESTATION_FORMATS["ANDROID_KEY"] = "android-key";
  ATTESTATION_FORMATS["TPM"] = "tpm";
  ATTESTATION_FORMATS["APPLE"] = "apple";
  ATTESTATION_FORMATS["NONE"] = "none";
})(ATTESTATION_FORMATS = exports.ATTESTATION_FORMATS || (exports.ATTESTATION_FORMATS = {}));