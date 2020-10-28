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
/* eslint-disable @typescript-eslint/ban-ts-comment */
// `ASN1HEX` exists in the lib but not in its typings
// @ts-ignore 2305

const jsrsasign_1 = require("jsrsasign");

const isCertRevoked_1 = __importDefault(require("./isCertRevoked"));

const {
  crypto
} = jsrsasign_1.KJUR;
/**
 * Traverse an array of PEM certificates and ensure they form a proper chain
 * @param certificates Typically the result of `x5c.map(convertASN1toPEM)`
 */

function validateCertificatePath(_x) {
  return _validateCertificatePath.apply(this, arguments);
}

function _validateCertificatePath() {
  _validateCertificatePath = _asyncToGenerator(function* (certificates) {
    if (new Set(certificates).size !== certificates.length) {
      throw new Error('Invalid certificate path: found duplicate certificates');
    } // From leaf to root, make sure each cert is issued by the next certificate in the chain


    for (let i = 0; i < certificates.length; i += 1) {
      const subjectPem = certificates[i];
      const subjectCert = new jsrsasign_1.X509();
      subjectCert.readCertPEM(subjectPem);
      let issuerPem = '';

      if (i + 1 >= certificates.length) {
        issuerPem = subjectPem;
      } else {
        issuerPem = certificates[i + 1];
      }

      const issuerCert = new jsrsasign_1.X509();
      issuerCert.readCertPEM(issuerPem); // Check for certificate revocation

      const subjectCertRevoked = yield isCertRevoked_1.default(subjectCert);

      if (subjectCertRevoked) {
        throw new Error("Found revoked certificate in certificate path");
      } // Check that intermediate certificate is within its valid time window


      const notBefore = jsrsasign_1.zulutodate(issuerCert.getNotBefore());
      const notAfter = jsrsasign_1.zulutodate(issuerCert.getNotAfter());
      const now = new Date();

      if (notBefore > now || notAfter < now) {
        throw new Error('Intermediate certificate is not yet valid or expired');
      }

      if (subjectCert.getIssuerString() !== issuerCert.getSubjectString()) {
        throw new Error('Invalid certificate path: subject issuer did not match issuer subject');
      }

      const subjectCertStruct = jsrsasign_1.ASN1HEX.getTLVbyList(subjectCert.hex, 0, [0]);
      const alg = subjectCert.getSignatureAlgorithmField();
      const signatureHex = subjectCert.getSignatureValueHex();
      const Signature = new crypto.Signature({
        alg
      });
      Signature.init(issuerPem);
      Signature.updateHex(subjectCertStruct);

      if (!Signature.verify(signatureHex)) {
        throw new Error('Invalid certificate path: invalid signature');
      }
    }

    return true;
  });
  return _validateCertificatePath.apply(this, arguments);
}

exports.default = validateCertificatePath;