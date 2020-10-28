"use strict";

require("core-js/modules/es.promise");

require("core-js/modules/es.regexp.to-string");

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

const jsrsasign_1 = require("jsrsasign");

const node_fetch_1 = __importDefault(require("node-fetch"));

const asn1_schema_1 = require("@peculiar/asn1-schema");

const asn1_x509_1 = require("@peculiar/asn1-x509");

const cacheRevokedCerts = {};
/**
 * A method to pull a CRL from a certificate and compare its serial number to the list of revoked
 * certificate serial numbers within the CRL.
 *
 * CRL certificate structure referenced from https://tools.ietf.org/html/rfc5280#page-117
 */

function isCertRevoked(_x) {
  return _isCertRevoked.apply(this, arguments);
}

function _isCertRevoked() {
  _isCertRevoked = _asyncToGenerator(function* (cert) {
    const certSerialHex = cert.getSerialNumberHex(); // Check to see if we've got cached info for the cert's CA

    let certAuthKeyID = null;

    try {
      certAuthKeyID = cert.getExtAuthorityKeyIdentifier();
    } catch (err) {
      return false;
    }

    if (certAuthKeyID) {
      const cached = cacheRevokedCerts[certAuthKeyID.kid];

      if (cached) {
        const now = new Date(); // If there's a nextUpdate then make sure we're before it

        if (!cached.nextUpdate || cached.nextUpdate > now) {
          return cached.revokedCerts.indexOf(certSerialHex) >= 0;
        }
      }
    }

    let crlURL = undefined;

    try {
      crlURL = cert.getExtCRLDistributionPointsURI();
    } catch (err) {
      // Cert probably didn't include any CDP URIs
      return false;
    } // If no URL is provided then we have nothing to check


    if (!crlURL) {
      return false;
    } // Download and read the CRL


    const crlCert = new jsrsasign_1.X509();

    try {
      const respCRL = yield node_fetch_1.default(crlURL[0]);
      const dataCRL = yield respCRL.text();
      crlCert.readCertPEM(dataCRL);
    } catch (err) {
      return false;
    }

    const data = asn1_schema_1.AsnParser.parse(Buffer.from(crlCert.hex, 'hex'), asn1_x509_1.CertificateList);
    const newCached = {
      revokedCerts: [],
      nextUpdate: undefined
    }; // nextUpdate

    if (data.tbsCertList.nextUpdate) {
      newCached.nextUpdate = data.tbsCertList.nextUpdate.getTime();
    } // revokedCertificates


    const revokedCerts = data.tbsCertList.revokedCertificates;

    if (revokedCerts) {
      for (const cert of revokedCerts) {
        const revokedHex = Buffer.from(cert.userCertificate).toString('hex');
        newCached.revokedCerts.push(revokedHex);
      } // Cache the results


      if (certAuthKeyID) {
        cacheRevokedCerts[certAuthKeyID.kid] = newCached;
      }

      return newCached.revokedCerts.indexOf(certSerialHex) >= 0;
    }

    return false;
  });
  return _isCertRevoked.apply(this, arguments);
}

exports.default = isCertRevoked;