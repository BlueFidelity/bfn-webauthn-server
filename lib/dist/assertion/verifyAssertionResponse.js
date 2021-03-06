"use strict";

require("core-js/modules/es.regexp.flags");

var __importDefault = void 0 && (void 0).__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};

Object.defineProperty(exports, "__esModule", {
  value: true
});

const base64url_1 = __importDefault(require("base64url"));

const decodeClientDataJSON_1 = __importDefault(require("../helpers/decodeClientDataJSON"));

const toHash_1 = __importDefault(require("../helpers/toHash"));

const convertPublicKeyToPEM_1 = __importDefault(require("../helpers/convertPublicKeyToPEM"));

const verifySignature_1 = __importDefault(require("../helpers/verifySignature"));

const parseAuthenticatorData_1 = __importDefault(require("../helpers/parseAuthenticatorData"));

const isBase64URLString_1 = __importDefault(require("../helpers/isBase64URLString"));
/**
 * Verify that the user has legitimately completed the login process
 *
 * **Options:**
 *
 * @param credential Authenticator credential returned by browser's `startAssertion()`
 * @param expectedChallenge The base64url-encoded `options.challenge` returned by
 * `generateAssertionOptions()`
 * @param expectedOrigin Website URL that the attestation should have occurred on
 * @param expectedRPID RP ID that was specified in the attestation options
 * @param authenticator An internal {@link AuthenticatorDevice} matching the credential's ID
 * @param fidoUserVerification (Optional) The value specified for `userVerification` when calling
 * `generateAssertionOptions()`. Activates FIDO-specific user presence and verification checks.
 * Omitting this value defaults verification to a WebAuthn-specific user presence requirement.
 */


function verifyAssertionResponse(options) {
  const {
    credential,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    authenticator,
    fidoUserVerification
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

  if (!response) {
    throw new Error('Credential missing response');
  }

  if (typeof (response === null || response === void 0 ? void 0 : response.clientDataJSON) !== 'string') {
    throw new Error('Credential response clientDataJSON was not a string');
  }

  const clientDataJSON = decodeClientDataJSON_1.default(response.clientDataJSON);
  const {
    type,
    origin,
    challenge,
    tokenBinding
  } = clientDataJSON; // Make sure we're handling an assertion

  if (type !== 'webauthn.get') {
    throw new Error("Unexpected assertion type: ".concat(type));
  } // Ensure the device provided the challenge we gave it


  if (challenge !== expectedChallenge) {
    throw new Error("Unexpected assertion challenge \"".concat(challenge, "\", expected \"").concat(expectedChallenge, "\""));
  } // Check that the origin is our site


  if (origin !== expectedOrigin) {
    throw new Error("Unexpected assertion origin \"".concat(origin, "\", expected \"").concat(expectedOrigin, "\""));
  }

  if (!isBase64URLString_1.default(response.authenticatorData)) {
    throw new Error('Credential response authenticatorData was not a base64url string');
  }

  if (!isBase64URLString_1.default(response.signature)) {
    throw new Error('Credential response signature was not a base64url string');
  }

  if (response.userHandle && typeof response.userHandle !== 'string') {
    throw new Error('Credential response userHandle was not a string');
  }

  if (tokenBinding) {
    if (typeof tokenBinding !== 'object') {
      throw new Error('ClientDataJSON tokenBinding was not an object');
    }

    if (['present', 'supported', 'notSupported'].indexOf(tokenBinding.status) < 0) {
      throw new Error("Unexpected tokenBinding status ".concat(tokenBinding.status));
    }
  }

  const authDataBuffer = base64url_1.default.toBuffer(response.authenticatorData);
  const parsedAuthData = parseAuthenticatorData_1.default(authDataBuffer);
  const {
    rpIdHash,
    flags,
    counter
  } = parsedAuthData; // Make sure the response's RP ID is ours

  const expectedRPIDHash = toHash_1.default(Buffer.from(expectedRPID, 'ascii'));

  if (!rpIdHash.equals(expectedRPIDHash)) {
    throw new Error("Unexpected RP ID hash");
  } // Enforce user verification if required


  if (fidoUserVerification) {
    if (fidoUserVerification === 'required') {
      // Require `flags.uv` be true (implies `flags.up` is true)
      if (!flags.uv) {
        throw new Error('User verification required, but user could not be verified');
      }
    } else if (fidoUserVerification === 'preferred' || fidoUserVerification === 'discouraged') {// Ignore `flags.uv`
    }
  } else {
    // WebAuthn only requires the user presence flag be true
    if (!flags.up) {
      throw new Error('User not present during assertion');
    }
  }

  const clientDataHash = toHash_1.default(base64url_1.default.toBuffer(response.clientDataJSON));
  const signatureBase = Buffer.concat([authDataBuffer, clientDataHash]);
  const publicKey = convertPublicKeyToPEM_1.default(authenticator.publicKey);
  const signature = base64url_1.default.toBuffer(response.signature);

  if ((counter > 0 || authenticator.counter > 0) && counter <= authenticator.counter) {
    // Error out when the counter in the DB is greater than or equal to the counter in the
    // dataStruct. It's related to how the authenticator maintains the number of times its been
    // used for this client. If this happens, then someone's somehow increased the counter
    // on the device without going through this site
    throw new Error("Response counter value ".concat(counter, " was lower than expected ").concat(authenticator.counter));
  }

  const toReturn = {
    verified: verifySignature_1.default(signature, signatureBase, publicKey),
    authenticatorInfo: {
      counter,
      base64CredentialID: credential.id
    }
  };
  return toReturn;
}

exports.default = verifyAssertionResponse;