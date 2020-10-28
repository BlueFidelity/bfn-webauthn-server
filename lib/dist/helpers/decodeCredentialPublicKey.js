"use strict";

var __importDefault = void 0 && (void 0).__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};

Object.defineProperty(exports, "__esModule", {
  value: true
});

const cbor_1 = __importDefault(require("cbor"));

function decodeCredentialPublicKey(publicKey) {
  return cbor_1.default.decodeFirstSync(publicKey);
}

exports.default = decodeCredentialPublicKey;