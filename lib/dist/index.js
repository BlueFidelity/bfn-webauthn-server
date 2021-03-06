"use strict";

var __importDefault = void 0 && (void 0).__importDefault || function (mod) {
  return mod && mod.__esModule ? mod : {
    "default": mod
  };
};

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.MetadataService = exports.verifyAssertionResponse = exports.generateAssertionOptions = exports.verifyAttestationResponse = exports.generateAttestationOptions = void 0;
/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 * @preferred
 */

const generateAttestationOptions_1 = __importDefault(require("./attestation/generateAttestationOptions"));

exports.generateAttestationOptions = generateAttestationOptions_1.default;

const verifyAttestationResponse_1 = __importDefault(require("./attestation/verifyAttestationResponse"));

exports.verifyAttestationResponse = verifyAttestationResponse_1.default;

const generateAssertionOptions_1 = __importDefault(require("./assertion/generateAssertionOptions"));

exports.generateAssertionOptions = generateAssertionOptions_1.default;

const verifyAssertionResponse_1 = __importDefault(require("./assertion/verifyAssertionResponse"));

exports.verifyAssertionResponse = verifyAssertionResponse_1.default;

const metadataService_1 = __importDefault(require("./metadata/metadataService"));

exports.MetadataService = metadataService_1.default;