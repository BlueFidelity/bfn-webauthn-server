"use strict";

var __importDefault = void 0 && (void 0).__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};

Object.defineProperty(exports, "__esModule", {
  value: true
});

const base64url_1 = __importDefault(require("base64url"));

const generateChallenge_1 = __importDefault(require("../helpers/generateChallenge"));
/**
 * Prepare a value to pass into navigator.credentials.get(...) for authenticator "login"
 *
 * @param allowCredentials Authenticators previously registered by the user
 * @param challenge Random value the authenticator needs to sign and pass back
 * user for assertion
 * @param timeout How long (in ms) the user can take to complete assertion
 * @param userVerification Set to `'discouraged'` when asserting as part of a 2FA flow, otherwise
 * set to `'preferred'` or `'required'` as desired.
 * @param extensions Additional plugins the authenticator or browser should use during assertion
 * @param rpID Valid domain name (after `https://`)
 */


function generateAssertionOptions(options) {
  const {
    allowCredentials,
    challenge = generateChallenge_1.default(),
    timeout = 60000,
    userVerification,
    extensions,
    rpID
  } = options;
  return {
    challenge: base64url_1.default.encode(challenge),
    allowCredentials,
    timeout,
    userVerification,
    extensions,
    rpId: rpID
  };
}

exports.default = generateAssertionOptions;