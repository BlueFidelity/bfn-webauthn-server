"use strict";

require("core-js/modules/es.promise");

require("core-js/modules/es.regexp.to-string");

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

const elliptic_1 = __importDefault(require("elliptic"));

const node_rsa_1 = __importDefault(require("node-rsa"));

const convertCOSEtoPKCS_1 = __importStar(require("../../helpers/convertCOSEtoPKCS"));

const constants_1 = require("../../helpers/constants");

const toHash_1 = __importDefault(require("../../helpers/toHash"));

const convertX509CertToPEM_1 = __importDefault(require("../../helpers/convertX509CertToPEM"));

const getCertificateInfo_1 = __importDefault(require("../../helpers/getCertificateInfo"));

const verifySignature_1 = __importDefault(require("../../helpers/verifySignature"));

const decodeCredentialPublicKey_1 = __importDefault(require("../../helpers/decodeCredentialPublicKey"));

const metadataService_1 = __importDefault(require("../../metadata/metadataService"));

const verifyAttestationWithMetadata_1 = __importDefault(require("../../metadata/verifyAttestationWithMetadata"));
/**
 * Verify an attestation response with fmt 'packed'
 */


function verifyAttestationPacked(_x) {
  return _verifyAttestationPacked.apply(this, arguments);
}

function _verifyAttestationPacked() {
  _verifyAttestationPacked = _asyncToGenerator(function* (options) {
    const {
      attStmt,
      clientDataHash,
      authData,
      credentialPublicKey,
      aaguid
    } = options;
    const {
      sig,
      x5c,
      alg
    } = attStmt;

    if (!sig) {
      throw new Error('No attestation signature provided in attestation statement (Packed)');
    }

    if (typeof alg !== 'number') {
      throw new Error("Attestation Statement alg \"".concat(alg, "\" is not a number (Packed)"));
    }

    const signatureBase = Buffer.concat([authData, clientDataHash]);
    let verified = false;
    const pkcsPublicKey = convertCOSEtoPKCS_1.default(credentialPublicKey);

    if (x5c) {
      const leafCert = convertX509CertToPEM_1.default(x5c[0]);
      const {
        subject,
        basicConstraintsCA,
        version,
        notBefore,
        notAfter
      } = getCertificateInfo_1.default(leafCert);
      const {
        OU,
        CN,
        O,
        C
      } = subject;

      if (OU !== 'Authenticator Attestation') {
        throw new Error('Certificate OU was not "Authenticator Attestation" (Packed|Full)');
      }

      if (!CN) {
        throw new Error('Certificate CN was empty (Packed|Full)');
      }

      if (!O) {
        throw new Error('Certificate O was empty (Packed|Full)');
      }

      if (!C || C.length !== 2) {
        throw new Error('Certificate C was not two-character ISO 3166 code (Packed|Full)');
      }

      if (basicConstraintsCA) {
        throw new Error('Certificate basic constraints CA was not `false` (Packed|Full)');
      }

      if (version !== 3) {
        throw new Error('Certificate version was not `3` (ASN.1 value of 2) (Packed|Full)');
      }

      let now = new Date();

      if (notBefore > now) {
        throw new Error("Certificate not good before \"".concat(notBefore.toString(), "\" (Packed|Full)"));
      }

      now = new Date();

      if (notAfter < now) {
        throw new Error("Certificate not good after \"".concat(notAfter.toString(), "\" (Packed|Full)"));
      } // TODO: If certificate contains id-fido-gen-ce-aaguid(1.3.6.1.4.1.45724.1.1.4) extension, check
      // that it’s value is set to the same AAGUID as in authData.
      // If available, validate attestation alg and x5c with info in the metadata statement


      const statement = yield metadataService_1.default.getStatement(aaguid);

      if (statement) {
        // The presence of x5c means this is a full attestation. Check to see if attestationTypes
        // includes packed attestations.
        if (statement.attestationTypes.indexOf(constants_1.FIDO_METADATA_ATTESTATION_TYPES.ATTESTATION_BASIC_FULL) < 0) {
          throw new Error('Metadata does not indicate support for full attestations (Packed|Full)');
        }

        try {
          yield verifyAttestationWithMetadata_1.default(statement, alg, x5c);
        } catch (err) {
          throw new Error("".concat(err.message, " (Packed|Full)"));
        }
      }

      verified = verifySignature_1.default(sig, signatureBase, leafCert);
    } else {
      const cosePublicKey = decodeCredentialPublicKey_1.default(credentialPublicKey);
      const kty = cosePublicKey.get(convertCOSEtoPKCS_1.COSEKEYS.kty);

      if (!kty) {
        throw new Error('COSE public key was missing kty (Packed|Self)');
      }

      const hashAlg = convertCOSEtoPKCS_1.COSEALGHASH[alg];

      if (kty === convertCOSEtoPKCS_1.COSEKTY.EC2) {
        const crv = cosePublicKey.get(convertCOSEtoPKCS_1.COSEKEYS.crv);

        if (!crv) {
          throw new Error('COSE public key was missing kty crv (Packed|EC2)');
        }

        const signatureBaseHash = toHash_1.default(signatureBase, hashAlg);
        /**
         * Instantiating the curve here is _very_ computationally heavy - a bit of profiling
         * (in compiled JS, not TS) reported an average of ~125ms to execute this line. The elliptic
         * README states, "better do it once and reuse it", so maybe there's a better way to handle
         * this in a server context, when we can re-use an existing instance.
         *
         * For now, it's worth noting that this line is probably the reason why it can take
         * 5-6 seconds to run tests.
         */

        const ec = new elliptic_1.default.ec(convertCOSEtoPKCS_1.COSECRV[crv]);
        const key = ec.keyFromPublic(pkcsPublicKey);
        verified = key.verify(signatureBaseHash, sig);
      } else if (kty === convertCOSEtoPKCS_1.COSEKTY.RSA) {
        const n = cosePublicKey.get(convertCOSEtoPKCS_1.COSEKEYS.n);

        if (!n) {
          throw new Error('COSE public key was missing n (Packed|RSA)');
        }

        const signingScheme = convertCOSEtoPKCS_1.COSERSASCHEME[alg]; // TODO: Verify this works

        const key = new node_rsa_1.default();
        key.setOptions({
          signingScheme
        });
        key.importKey({
          n: n,
          e: 65537
        }, 'components-public');
        verified = key.verify(signatureBase, sig);
      } else if (kty === convertCOSEtoPKCS_1.COSEKTY.OKP) {
        const x = cosePublicKey.get(convertCOSEtoPKCS_1.COSEKEYS.x);

        if (!x) {
          throw new Error('COSE public key was missing x (Packed|OKP)');
        }

        const signatureBaseHash = toHash_1.default(signatureBase, hashAlg);
        const key = new elliptic_1.default.eddsa('ed25519');
        key.keyFromPublic(x); // TODO: is `publicKey` right here?

        verified = key.verify(signatureBaseHash, sig, pkcsPublicKey);
      }
    }

    return verified;
  });
  return _verifyAttestationPacked.apply(this, arguments);
}

exports.default = verifyAttestationPacked;