"use strict";

require("core-js/modules/es.promise");

require("core-js/modules/web.dom-collections.iterator");

function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { Promise.resolve(value).then(_next, _throw); } }

function _asyncToGenerator(fn) { return function () { var self = this, args = arguments; return new Promise(function (resolve, reject) { var gen = fn.apply(self, args); function _next(value) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value); } function _throw(err) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err); } _next(undefined); }); }; }

var __importDefault = void 0 && (void 0).__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};

Object.defineProperty(exports, "__esModule", {
  value: true
});

const constants_1 = require("../helpers/constants");

const convertX509CertToPEM_1 = __importDefault(require("../helpers/convertX509CertToPEM"));

const validateCertificatePath_1 = __importDefault(require("../helpers/validateCertificatePath"));

function verifyAttestationWithMetadata(_x, _x2, _x3) {
  return _verifyAttestationWithMetadata.apply(this, arguments);
}

function _verifyAttestationWithMetadata() {
  _verifyAttestationWithMetadata = _asyncToGenerator(function* (statement, alg, x5c) {
    // Make sure the alg in the attestation statement matches the one specified in the metadata
    const metaCOSE = constants_1.FIDO_METADATA_AUTH_ALG_TO_COSE[statement.authenticationAlgorithm];

    if (metaCOSE.alg !== alg) {
      throw new Error("Attestation alg \"".concat(alg, "\" did not match metadata auth alg \"").concat(metaCOSE.alg, "\""));
    } // Make a copy of x5c so we don't modify the original


    const path = [...x5c].map(convertX509CertToPEM_1.default); // Try to validate the chain with each metadata root cert until we find one that works

    let foundValidPath = false;

    for (const rootCert of statement.attestationRootCertificates) {
      try {
        // Push the root cert to the cert path and try to validate it
        path.push(convertX509CertToPEM_1.default(rootCert));
        foundValidPath = yield validateCertificatePath_1.default(path);
      } catch (err) {
        // Swallow the error for now
        foundValidPath = false; // Remove the root cert before we try again with another

        path.splice(path.length - 1, 1);
      } // Don't continue if we've validated a full path


      if (foundValidPath) {
        break;
      }
    }

    if (!foundValidPath) {
      throw new Error("Could not validate certificate path with any metadata root certificates");
    }

    return true;
  });
  return _verifyAttestationWithMetadata.apply(this, arguments);
}

exports.default = verifyAttestationWithMetadata;