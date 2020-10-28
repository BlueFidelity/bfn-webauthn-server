"use strict";

require("core-js/modules/es.string.split");

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
 * Process a JWT into Javascript-friendly data structures
 */


function parseJWT(jwt) {
  const parts = jwt.split('.');
  return [JSON.parse(base64url_1.default.decode(parts[0])), JSON.parse(base64url_1.default.decode(parts[1])), parts[2]];
}

exports.default = parseJWT;