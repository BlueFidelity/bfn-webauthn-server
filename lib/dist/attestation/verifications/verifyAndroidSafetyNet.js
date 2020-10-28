"use strict";

require("core-js/modules/es.promise");

require("core-js/modules/es.regexp.to-string");

require("core-js/modules/es.string.split");

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

const base64url_1 = __importDefault(require("base64url"));

const toHash_1 = __importDefault(require("../../helpers/toHash"));

const verifySignature_1 = __importDefault(require("../../helpers/verifySignature"));

const getCertificateInfo_1 = __importDefault(require("../../helpers/getCertificateInfo"));

const validateCertificatePath_1 = __importDefault(require("../../helpers/validateCertificatePath"));

const convertX509CertToPEM_1 = __importDefault(require("../../helpers/convertX509CertToPEM"));

const metadataService_1 = __importDefault(require("../../metadata/metadataService"));

const verifyAttestationWithMetadata_1 = __importDefault(require("../../metadata/verifyAttestationWithMetadata"));
/**
 * Verify an attestation response with fmt 'android-safetynet'
 */


function verifyAttestationAndroidSafetyNet(_x) {
  return _verifyAttestationAndroidSafetyNet.apply(this, arguments);
}

function _verifyAttestationAndroidSafetyNet() {
  _verifyAttestationAndroidSafetyNet = _asyncToGenerator(function* (options) {
    const {
      attStmt,
      clientDataHash,
      authData,
      aaguid,
      verifyTimestampMS = true
    } = options;
    const {
      response,
      ver
    } = attStmt;

    if (!ver) {
      throw new Error('No ver value in attestation (SafetyNet)');
    }

    if (!response) {
      throw new Error('No response was included in attStmt by authenticator (SafetyNet)');
    } // Prepare to verify a JWT


    const jwt = response.toString('utf8');
    const jwtParts = jwt.split('.');
    const HEADER = JSON.parse(base64url_1.default.decode(jwtParts[0]));
    const PAYLOAD = JSON.parse(base64url_1.default.decode(jwtParts[1]));
    const SIGNATURE = jwtParts[2];
    /**
     * START Verify PAYLOAD
     */

    const {
      nonce,
      ctsProfileMatch,
      timestampMs
    } = PAYLOAD;

    if (verifyTimestampMS) {
      // Make sure timestamp is in the past
      let now = Date.now();

      if (timestampMs > Date.now()) {
        throw new Error("Payload timestamp \"".concat(timestampMs, "\" was later than \"").concat(now, "\" (SafetyNet)"));
      } // Consider a SafetyNet attestation valid within a minute of it being performed


      const timestampPlusDelay = timestampMs + 60 * 1000;
      now = Date.now();

      if (timestampPlusDelay < now) {
        throw new Error("Payload timestamp \"".concat(timestampPlusDelay, "\" has expired (SafetyNet)"));
      }
    }

    const nonceBase = Buffer.concat([authData, clientDataHash]);
    const nonceBuffer = toHash_1.default(nonceBase);
    const expectedNonce = nonceBuffer.toString('base64');

    if (nonce !== expectedNonce) {
      throw new Error('Could not verify payload nonce (SafetyNet)');
    }

    if (!ctsProfileMatch) {
      throw new Error('Could not verify device integrity (SafetyNet)');
    }
    /**
     * END Verify PAYLOAD
     */

    /**
     * START Verify Header
     */


    const leafCert = convertX509CertToPEM_1.default(HEADER.x5c[0]);
    const leafCertInfo = getCertificateInfo_1.default(leafCert);
    const {
      subject
    } = leafCertInfo; // Ensure the certificate was issued to this hostname
    // See https://developer.android.com/training/safetynet/attestation#verify-attestation-response

    if (subject.CN !== 'attest.android.com') {
      throw new Error('Certificate common name was not "attest.android.com" (SafetyNet)');
    }

    const statement = yield metadataService_1.default.getStatement(aaguid);

    if (statement) {
      try {
        // Convert from alg in JWT header to a number in the metadata
        const alg = HEADER.alg === 'RS256' ? -257 : -99999;
        yield verifyAttestationWithMetadata_1.default(statement, alg, HEADER.x5c);
      } catch (err) {
        throw new Error("".concat(err.message, " (SafetyNet)"));
      }
    } else {
      // Validate certificate path using a fixed global root cert
      const path = HEADER.x5c.concat([GlobalSignRootCAR2]).map(convertX509CertToPEM_1.default);

      try {
        yield validateCertificatePath_1.default(path);
      } catch (err) {
        throw new Error("".concat(err.message, " (SafetyNet)"));
      }
    }
    /**
     * END Verify Header
     */

    /**
     * START Verify Signature
     */


    const signatureBaseBuffer = Buffer.from("".concat(jwtParts[0], ".").concat(jwtParts[1]));
    const signatureBuffer = base64url_1.default.toBuffer(SIGNATURE);
    const verified = verifySignature_1.default(signatureBuffer, signatureBaseBuffer, leafCert);
    /**
     * END Verify Signature
     */

    return verified;
  });
  return _verifyAttestationAndroidSafetyNet.apply(this, arguments);
}

exports.default = verifyAttestationAndroidSafetyNet;
/**
 * This "GS Root R2" root certificate was downloaded from https://pki.goog/gsr2/GSR2.crt
 * on 08/10/2019 and then run through `base64url.encode()` to get this representation.
 *
 * The certificate is valid until Dec 15, 2021
 */

const GlobalSignRootCAR2 = 'MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UEC' + 'xMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhc' + 'NMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA' + '1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKb' + 'PJA6-Lm8omUVCxKs-IVSbC9N_hHD6ErPLv4dfxn-G07IwXNb9rfF73OX4YJYJkhD10FPe-3t-c4isUoh7SqbKSaZeqKeMW' + 'hG8eoLrvozps6yWJQeXSpkqBy-0Hne_ig-1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx' + '5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ_gk' + 'wpRl4pazq-r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQY' + 'wDwYDVR0TAQH_BAUwAwEB_zAdBgNVHQ4EFgQUm-IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0c' + 'DovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgk' + 'qhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0_WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk' + '7mpM0sYmsL4h4hO291xNBrBVNpGP-DTKqttVCL1OmLNIG-6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot-3i9DAgBkcRcA' + 'tjOj4LaR0VknFBbVPFd5uRHg5h6h-u_N5GJG79G-dwfCMNYxdAfvDbbnvRG15RjF-Cv6pgsH_76tuIMRQyV-dTZsXjAzlA' + 'cmgQWpzU_qlULRuJQ_7TBj0_VLZjmmx6BEP3ojY-x1J96relc8geMJgEtslQIxq_H5COEBkEveegeGTLg';