"use strict";

require("core-js/modules/es.promise");

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

const asn1_schema_1 = require("@peculiar/asn1-schema");

const asn1_x509_1 = require("@peculiar/asn1-x509");

const validateCertificatePath_1 = __importDefault(require("../../helpers/validateCertificatePath"));

const convertX509CertToPEM_1 = __importDefault(require("../../helpers/convertX509CertToPEM"));

const toHash_1 = __importDefault(require("../../helpers/toHash"));

const convertCOSEtoPKCS_1 = __importDefault(require("../../helpers/convertCOSEtoPKCS"));

function verifyApple(_x) {
  return _verifyApple.apply(this, arguments);
}

function _verifyApple() {
  _verifyApple = _asyncToGenerator(function* (options) {
    const {
      attStmt,
      authData,
      clientDataHash,
      credentialPublicKey
    } = options;
    const {
      x5c
    } = attStmt;

    if (!x5c) {
      throw new Error('No attestation certificate provided in attestation statement (Apple)');
    }
    /**
     * Verify certificate path
     */


    const certPath = x5c.map(convertX509CertToPEM_1.default);
    certPath.push(AppleWebAuthnRootCertificate);

    try {
      yield validateCertificatePath_1.default(certPath);
    } catch (err) {
      throw new Error("".concat(err.message, " (Apple)"));
    }
    /**
     * Compare nonce in certificate extension to computed nonce
     */


    const parsedCredCert = asn1_schema_1.AsnParser.parse(x5c[0], asn1_x509_1.Certificate);
    const {
      extensions,
      subjectPublicKeyInfo
    } = parsedCredCert.tbsCertificate;

    if (!extensions) {
      throw new Error('credCert missing extensions (Apple)');
    }

    const extCertNonce = extensions.find(ext => ext.extnID === '1.2.840.113635.100.8.2');

    if (!extCertNonce) {
      throw new Error('credCert missing "1.2.840.113635.100.8.2" extension (Apple)');
    }

    const nonceToHash = Buffer.concat([authData, clientDataHash]);
    const nonce = toHash_1.default(nonceToHash, 'SHA256');
    /**
     * Ignore the first six ASN.1 structure bytes that define the nonce as an OCTET STRING. Should
     * trim off <Buffer 30 24 a1 22 04 20>
     *
     * TODO: Try and get @peculiar (GitHub) to add a schema for "1.2.840.113635.100.8.2" when we
     * find out where it's defined (doesn't seem to be publicly documented at the moment...)
     */

    const extNonce = Buffer.from(extCertNonce.extnValue.buffer).slice(6);

    if (!nonce.equals(extNonce)) {
      throw new Error("credCert nonce was not expected value (Apple)");
    }
    /**
     * Verify credential public key matches the Subject Public Key of credCert
     */


    const credPubKeyPKCS = convertCOSEtoPKCS_1.default(credentialPublicKey);
    const credCertSubjectPublicKey = Buffer.from(subjectPublicKeyInfo.subjectPublicKey);

    if (!credPubKeyPKCS.equals(credCertSubjectPublicKey)) {
      throw new Error('Credential public key does not equal credCert public key (Apple)');
    }

    return true;
  });
  return _verifyApple.apply(this, arguments);
}

exports.default = verifyApple;
/**
 * Apple WebAuthn Root CA PEM
 *
 * Downloaded from https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
 *
 * Valid until 03/14/2045 @ 5:00 PM PST
 */

const AppleWebAuthnRootCertificate = "-----BEGIN CERTIFICATE-----\nMIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w\nHQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ\nbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx\nNTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG\nA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49\nAgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k\nxu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/\npcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk\n2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA\nMGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3\njAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B\n1bWeT0vT\n-----END CERTIFICATE-----";