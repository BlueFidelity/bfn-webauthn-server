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

const base64url_1 = __importDefault(require("base64url"));
/**
 * Convert X.509 certificate to an OpenSSL-compatible PEM text format.
 */


function convertX509CertToPEM(certBuffer) {
  let buffer;

  if (typeof certBuffer === 'string') {
    buffer = base64url_1.default.toBuffer(certBuffer);
  } else {
    buffer = certBuffer;
  }

  const b64cert = buffer.toString('base64');
  let PEMKey = '';

  for (let i = 0; i < Math.ceil(b64cert.length / 64); i += 1) {
    const start = 64 * i;
    PEMKey += "".concat(b64cert.substr(start, 64), "\n");
  }

  PEMKey = "-----BEGIN CERTIFICATE-----\n".concat(PEMKey, "-----END CERTIFICATE-----\n");
  return PEMKey;
}

exports.default = convertX509CertToPEM;