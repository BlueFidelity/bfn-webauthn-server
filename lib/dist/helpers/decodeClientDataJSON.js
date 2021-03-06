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
/**
 * Decode an authenticator's base64url-encoded clientDataJSON to JSON
 */


function decodeClientDataJSON(data) {
  const toString = base64url_1.default.decode(data);
  const clientData = JSON.parse(toString);
  return clientData;
}

exports.default = decodeClientDataJSON;