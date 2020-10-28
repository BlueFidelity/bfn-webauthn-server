"use strict";

require("core-js/modules/es.promise");

function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { Promise.resolve(value).then(_next, _throw); } }

function _asyncToGenerator(fn) { return function () { var self = this, args = arguments; return new Promise(function (resolve, reject) { var gen = fn.apply(self, args); function _next(value) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value); } function _throw(err) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err); } _next(undefined); }); }; }

var __createBinding = void 0 && (void 0).__createBinding || (Object.create ? function (o, m, k, k2) {
  if (k2 === undefined) k2 = k;
  Object.defineProperty(o, k2, {
    enumerable: true,
    get: function get() {
      return m[k];
    }
  });
} : function (o, m, k, k2) {
  if (k2 === undefined) k2 = k;
  o[k2] = m[k];
});

var __setModuleDefault = void 0 && (void 0).__setModuleDefault || (Object.create ? function (o, v) {
  Object.defineProperty(o, "default", {
    enumerable: true,
    value: v
  });
} : function (o, v) {
  o["default"] = v;
});

var __importStar = void 0 && (void 0).__importStar || function (mod) {
  if (mod && mod.__esModule) return mod;
  var result = {};
  if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);

  __setModuleDefault(result, mod);

  return result;
};

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

const asn1_android_1 = require("@peculiar/asn1-android");

const convertX509CertToPEM_1 = __importDefault(require("../../helpers/convertX509CertToPEM"));

const verifySignature_1 = __importDefault(require("../../helpers/verifySignature"));

const convertCOSEtoPKCS_1 = __importStar(require("../../helpers/convertCOSEtoPKCS"));

const metadataService_1 = __importDefault(require("../../metadata/metadataService"));

const verifyAttestationWithMetadata_1 = __importDefault(require("../../metadata/verifyAttestationWithMetadata"));

function verifyAttestationAndroidKey(_x) {
  return _verifyAttestationAndroidKey.apply(this, arguments);
}

function _verifyAttestationAndroidKey() {
  _verifyAttestationAndroidKey = _asyncToGenerator(function* (options) {
    var _a;

    const {
      authData,
      clientDataHash,
      attStmt,
      credentialPublicKey,
      aaguid
    } = options;
    const {
      x5c,
      sig,
      alg
    } = attStmt;

    if (!x5c) {
      throw new Error('No attestation certificate provided in attestation statement (AndroidKey)');
    }

    if (!sig) {
      throw new Error('No attestation signature provided in attestation statement (AndroidKey)');
    }

    if (!alg) {
      throw new Error("Attestation statement did not contain alg (AndroidKey)");
    } // Check that credentialPublicKey matches the public key in the attestation certificate
    // Find the public cert in the certificate as PKCS


    const parsedCert = asn1_schema_1.AsnParser.parse(x5c[0], asn1_x509_1.Certificate);
    const parsedCertPubKey = Buffer.from(parsedCert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey); // Convert the credentialPublicKey to PKCS

    const credPubKeyPKCS = convertCOSEtoPKCS_1.default(credentialPublicKey);

    if (!credPubKeyPKCS.equals(parsedCertPubKey)) {
      throw new Error('Credential public key does not equal leaf cert public key (AndroidKey)');
    } // Find Android KeyStore Extension in certificate extensions


    const extKeyStore = (_a = parsedCert.tbsCertificate.extensions) === null || _a === void 0 ? void 0 : _a.find(ext => ext.extnID === asn1_android_1.id_ce_keyDescription);

    if (!extKeyStore) {
      throw new Error('Certificate did not contain extKeyStore (AndroidKey)');
    }

    const parsedExtKeyStore = asn1_schema_1.AsnParser.parse(extKeyStore.extnValue, asn1_android_1.KeyDescription); // Verify extKeyStore values

    const {
      attestationChallenge,
      teeEnforced,
      softwareEnforced
    } = parsedExtKeyStore;

    if (!Buffer.from(attestationChallenge.buffer).equals(clientDataHash)) {
      throw new Error('Attestation challenge was not equal to client data hash (AndroidKey)');
    } // Ensure that the key is strictly bound to the caller app identifier (shouldn't contain the
    // [600] tag)


    if (teeEnforced.allApplications !== undefined) {
      throw new Error('teeEnforced contained "allApplications [600]" tag (AndroidKey)');
    }

    if (softwareEnforced.allApplications !== undefined) {
      throw new Error('teeEnforced contained "allApplications [600]" tag (AndroidKey)');
    } // TODO: Confirm that the root certificate is an expected certificate
    // const rootCertPEM = convertX509CertToPEM(x5c[x5c.length - 1]);
    // console.log(rootCertPEM);
    // if (rootCertPEM !== expectedRootCert) {
    //   throw new Error('Root certificate was not expected certificate (AndroidKey)');
    // }


    const statement = yield metadataService_1.default.getStatement(aaguid);

    if (statement) {
      try {
        yield verifyAttestationWithMetadata_1.default(statement, alg, x5c);
      } catch (err) {
        throw new Error("".concat(err.message, " (AndroidKey)"));
      }
    }

    const signatureBase = Buffer.concat([authData, clientDataHash]);
    const leafCertPEM = convertX509CertToPEM_1.default(x5c[0]);
    const hashAlg = convertCOSEtoPKCS_1.COSEALGHASH[alg];
    return verifySignature_1.default(sig, signatureBase, leafCertPEM, hashAlg);
  });
  return _verifyAttestationAndroidKey.apply(this, arguments);
}

exports.default = verifyAttestationAndroidKey; // TODO: Find the most up-to-date expected root cert, the one from Yuriy's article doesn't match

const expectedRootCert = "";