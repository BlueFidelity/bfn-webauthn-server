"use strict";

require("core-js/modules/es.promise");

require("core-js/modules/es.regexp.flags");

require("core-js/modules/es.string.includes");

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

const base64url_1 = __importDefault(require("base64url"));

const decodeAttestationObject_1 = __importStar(require("../helpers/decodeAttestationObject"));

const decodeClientDataJSON_1 = __importDefault(require("../helpers/decodeClientDataJSON"));

const parseAuthenticatorData_1 = __importDefault(require("../helpers/parseAuthenticatorData"));

const toHash_1 = __importDefault(require("../helpers/toHash"));

const decodeCredentialPublicKey_1 = __importDefault(require("../helpers/decodeCredentialPublicKey"));

const convertCOSEtoPKCS_1 = require("../helpers/convertCOSEtoPKCS");

const generateAttestationOptions_1 = require("./generateAttestationOptions");

const verifyFIDOU2F_1 = __importDefault(require("./verifications/verifyFIDOU2F"));

const verifyPacked_1 = __importDefault(require("./verifications/verifyPacked"));

const verifyAndroidSafetyNet_1 = __importDefault(require("./verifications/verifyAndroidSafetyNet"));

const verifyTPM_1 = __importDefault(require("./verifications/tpm/verifyTPM"));

const verifyAndroidKey_1 = __importDefault(require("./verifications/verifyAndroidKey"));

const verifyApple_1 = __importDefault(require("./verifications/verifyApple"));
/**
 * Verify that the user has legitimately completed the registration process
 *
 * **Options:**
 *
 * @param credential Authenticator credential returned by browser's `startAttestation()`
 * @param expectedChallenge The base64url-encoded `options.challenge` returned by
 * `generateAttestationOptions()`
 * @param expectedOrigin Website URL that the attestation should have occurred on
 * @param expectedRPID RP ID that was specified in the attestation options
 * @param requireUserVerification (Optional) Enforce user verification by the authenticator
 * (via PIN, fingerprint, etc...)
 * @param supportedAlgorithmIDs Array of numeric COSE algorithm identifiers supported for
 * attestation by this RP. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */


function verifyAttestationResponse(_x) {
  return _verifyAttestationResponse.apply(this, arguments);
}

function _verifyAttestationResponse() {
  _verifyAttestationResponse = _asyncToGenerator(function* (options) {
    const {
      credential,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      requireUserVerification = false,
      supportedAlgorithmIDs = generateAttestationOptions_1.supportedCOSEAlgorithmIdentifiers
    } = options;
    const {
      id,
      rawId,
      type: credentialType,
      response
    } = credential; // Ensure credential specified an ID

    if (!id) {
      throw new Error('Missing credential ID');
    } // Ensure ID is base64url-encoded


    if (id !== rawId) {
      throw new Error('Credential ID was not base64url-encoded');
    } // Make sure credential type is public-key


    if (credentialType !== 'public-key') {
      throw new Error("Unexpected credential type ".concat(credentialType, ", expected \"public-key\""));
    }

    const clientDataJSON = decodeClientDataJSON_1.default(response.clientDataJSON);
    const {
      type,
      origin,
      challenge,
      tokenBinding
    } = clientDataJSON; // Make sure we're handling an attestation

    if (type !== 'webauthn.create') {
      throw new Error("Unexpected attestation type: ".concat(type));
    } // Ensure the device provided the challenge we gave it


    if (challenge !== expectedChallenge) {
      throw new Error("Unexpected attestation challenge \"".concat(challenge, "\", expected \"").concat(expectedChallenge, "\""));
    } // Check that the origin is our site


    if (origin !== expectedOrigin) {
      throw new Error("Unexpected attestation origin \"".concat(origin, "\", expected \"").concat(expectedOrigin, "\""));
    }

    if (tokenBinding) {
      if (typeof tokenBinding !== 'object') {
        throw new Error("Unexpected value for TokenBinding \"".concat(tokenBinding, "\""));
      }

      if (['present', 'supported', 'not-supported'].indexOf(tokenBinding.status) < 0) {
        throw new Error("Unexpected tokenBinding.status value of \"".concat(tokenBinding.status, "\""));
      }
    }

    const attestationObject = decodeAttestationObject_1.default(response.attestationObject);
    const {
      fmt,
      authData,
      attStmt
    } = attestationObject;
    const parsedAuthData = parseAuthenticatorData_1.default(authData);
    const {
      aaguid,
      rpIdHash,
      flags,
      credentialID,
      counter,
      credentialPublicKey
    } = parsedAuthData; // Make sure the response's RP ID is ours

    if (expectedRPID) {
      const expectedRPIDHash = toHash_1.default(Buffer.from(expectedRPID, 'ascii'));

      if (!rpIdHash.equals(expectedRPIDHash)) {
        throw new Error("Unexpected RP ID hash");
      }
    } // Make sure someone was physically present


    if (!flags.up) {
      throw new Error('User not present during assertion');
    } // Enforce user verification if specified


    if (requireUserVerification && !flags.uv) {
      throw new Error('User verification required, but user could not be verified');
    }

    if (!credentialID) {
      throw new Error('No credential ID was provided by authenticator');
    }

    if (!credentialPublicKey) {
      throw new Error('No public key was provided by authenticator');
    }

    if (!aaguid) {
      throw new Error('No AAGUID was present in attestation');
    }

    const decodedPublicKey = decodeCredentialPublicKey_1.default(credentialPublicKey);
    const alg = decodedPublicKey.get(convertCOSEtoPKCS_1.COSEKEYS.alg);

    if (typeof alg !== 'number') {
      throw new Error('Credential public key was missing numeric alg');
    } // Make sure the key algorithm is one we specified within the attestation options


    if (!supportedAlgorithmIDs.includes(alg)) {
      const supported = supportedAlgorithmIDs.join(', ');
      throw new Error("Unexpected public key alg \"".concat(alg, "\", expected one of \"").concat(supported, "\""));
    }

    const clientDataHash = toHash_1.default(base64url_1.default.toBuffer(response.clientDataJSON));
    /**
     * Verification can only be performed when attestation = 'direct'
     */

    let verified = false;

    if (fmt === decodeAttestationObject_1.ATTESTATION_FORMATS.FIDO_U2F) {
      verified = verifyFIDOU2F_1.default({
        attStmt,
        clientDataHash,
        credentialID,
        credentialPublicKey,
        rpIdHash,
        aaguid
      });
    } else if (fmt === decodeAttestationObject_1.ATTESTATION_FORMATS.PACKED) {
      verified = yield verifyPacked_1.default({
        attStmt,
        authData,
        clientDataHash,
        credentialPublicKey,
        aaguid
      });
    } else if (fmt === decodeAttestationObject_1.ATTESTATION_FORMATS.ANDROID_SAFETYNET) {
      verified = yield verifyAndroidSafetyNet_1.default({
        attStmt,
        authData,
        clientDataHash,
        aaguid
      });
    } else if (fmt === decodeAttestationObject_1.ATTESTATION_FORMATS.ANDROID_KEY) {
      verified = yield verifyAndroidKey_1.default({
        attStmt,
        authData,
        clientDataHash,
        credentialPublicKey,
        aaguid
      });
    } else if (fmt === decodeAttestationObject_1.ATTESTATION_FORMATS.TPM) {
      verified = yield verifyTPM_1.default({
        aaguid,
        attStmt,
        authData,
        credentialPublicKey,
        clientDataHash
      });
    } else if (fmt === decodeAttestationObject_1.ATTESTATION_FORMATS.APPLE) {
      verified = yield verifyApple_1.default({
        attStmt,
        authData,
        clientDataHash,
        credentialPublicKey
      });
    } else if (fmt === decodeAttestationObject_1.ATTESTATION_FORMATS.NONE) {
      if (Object.keys(attStmt).length > 0) {
        throw new Error('None attestation had unexpected attestation statement');
      } // This is the weaker of the attestations, so there's nothing else to really check


      verified = true;
    } else {
      throw new Error("Unsupported Attestation Format: ".concat(fmt));
    }

    const toReturn = {
      verified,
      userVerified: flags.uv
    };

    if (toReturn.verified) {
      toReturn.userVerified = flags.uv;
      toReturn.authenticatorInfo = {
        fmt,
        counter,
        base64PublicKey: base64url_1.default.encode(credentialPublicKey),
        base64CredentialID: base64url_1.default.encode(credentialID)
      };
    }

    return toReturn;
  });
  return _verifyAttestationResponse.apply(this, arguments);
}

exports.default = verifyAttestationResponse;