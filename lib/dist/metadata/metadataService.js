"use strict";

require("core-js/modules/es.promise");

require("core-js/modules/es.regexp.to-string");

require("core-js/modules/es.string.split");

require("core-js/modules/web.dom-collections.iterator");

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

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

const node_fetch_1 = __importDefault(require("node-fetch"));

const jsrsasign_1 = require("jsrsasign");

const base64url_1 = __importDefault(require("base64url"));

const toHash_1 = __importDefault(require("../helpers/toHash"));

const validateCertificatePath_1 = __importDefault(require("../helpers/validateCertificatePath"));

const convertX509CertToPEM_1 = __importDefault(require("../helpers/convertX509CertToPEM"));

const convertAAGUIDToString_1 = __importDefault(require("../helpers/convertAAGUIDToString"));

const parseJWT_1 = __importDefault(require("./parseJWT"));

var SERVICE_STATE;

(function (SERVICE_STATE) {
  SERVICE_STATE[SERVICE_STATE["DISABLED"] = 0] = "DISABLED";
  SERVICE_STATE[SERVICE_STATE["REFRESHING"] = 1] = "REFRESHING";
  SERVICE_STATE[SERVICE_STATE["READY"] = 2] = "READY";
})(SERVICE_STATE || (SERVICE_STATE = {}));
/**
 * A basic service for coordinating interactions with the FIDO Metadata Service. This includes TOC
 * download and parsing, and on-demand requesting and caching of individual metadata statements.
 *
 * https://fidoalliance.org/metadata/
 */


class MetadataService {
  constructor() {
    this.mdsCache = {};
    this.statementCache = {};
    this.state = SERVICE_STATE.DISABLED;
  }
  /**
   * Prepare the service to handle remote MDS servers and/or cache local metadata statements.
   */


  initialize(opts) {
    var _this = this;

    return _asyncToGenerator(function* () {
      if (!opts) {
        throw new Error('MetadataService initialization options are missing');
      }

      const {
        mdsServers,
        statements
      } = opts;
      _this.state = SERVICE_STATE.REFRESHING; // If metadata statements are provided, load them into the cache first

      if (statements === null || statements === void 0 ? void 0 : statements.length) {
        statements.forEach(statement => {
          // Only cache statements that are for FIDO2-compatible authenticators
          if (statement.aaguid) {
            _this.statementCache[statement.aaguid] = {
              url: '',
              hash: '',
              statement,
              statusReports: []
            };
          }
        });
      }

      if (!mdsServers.length) {
        throw new Error('MetadataService must be initialized with at least one MDS server');
      } // If MDS servers are provided, then process them and add their statements to the cache


      if (mdsServers === null || mdsServers === void 0 ? void 0 : mdsServers.length) {
        for (const server of mdsServers) {
          try {
            yield _this.downloadTOC({
              url: server.url,
              rootCertURL: server.rootCertURL,
              metadataURLSuffix: server.metadataURLSuffix,
              alg: '',
              no: 0,
              nextUpdate: new Date(0)
            });
          } catch (err) {// Notify of the error and move on
          }
        }
      }

      _this.state = SERVICE_STATE.READY;
    })();
  }
  /**
   * Get a metadata statement for a given aaguid. Defaults to returning a cached statement.
   *
   * This method will coordinate updating the TOC as per the `nextUpdate` property in the initial
   * TOC download.
   */


  getStatement(aaguid) {
    var _this2 = this;

    return _asyncToGenerator(function* () {
      if (_this2.state === SERVICE_STATE.DISABLED) {
        return;
      }

      if (!aaguid) {
        return;
      }

      if (aaguid instanceof Buffer) {
        aaguid = convertAAGUIDToString_1.default(aaguid);
      } // If a TOC refresh is in progress then pause this until the service is ready


      yield _this2.pauseUntilReady(); // Try to grab a cached statement

      const cachedStatement = _this2.statementCache[aaguid];

      if (!cachedStatement) {
        // TODO: FIDO conformance requires this, but it seems excessive for WebAuthn. Investigate
        // later
        throw new Error("Unlisted aaguid \"".concat(aaguid, "\" in TOC"));
      } // If the statement points to an MDS API, check the MDS' nextUpdate to see if we need to refresh


      if (cachedStatement.tocURL) {
        const mds = _this2.mdsCache[cachedStatement.tocURL];
        const now = new Date();

        if (now > mds.nextUpdate) {
          try {
            _this2.state = SERVICE_STATE.REFRESHING;
            yield _this2.downloadTOC(mds);
          } finally {
            _this2.state = SERVICE_STATE.READY;
          }
        }
      } // Check to see if the this aaguid has a status report with a "compromised" status


      for (const report of cachedStatement.statusReports) {
        const {
          status
        } = report;

        if (status === 'USER_VERIFICATION_BYPASS' || status === 'ATTESTATION_KEY_COMPROMISE' || status === 'USER_KEY_REMOTE_COMPROMISE' || status === 'USER_KEY_PHYSICAL_COMPROMISE') {
          throw new Error("Detected compromised aaguid \"".concat(aaguid, "\""));
        }
      } // If the statement hasn't been cached but came from an MDS TOC, then download it


      if (!cachedStatement.statement && cachedStatement.tocURL) {
        // Download the metadata statement if it's not been cached
        const resp = yield node_fetch_1.default(cachedStatement.url);
        const data = yield resp.text();
        const statement = JSON.parse(Buffer.from(data, 'base64').toString('utf-8'));
        const mds = _this2.mdsCache[cachedStatement.tocURL];
        const hashAlg = (mds === null || mds === void 0 ? void 0 : mds.alg) === 'ES256' ? 'SHA256' : undefined;
        const calculatedHash = base64url_1.default.encode(toHash_1.default(data, hashAlg));

        if (calculatedHash === cachedStatement.hash) {
          // Update the cached entry with the latest statement
          cachedStatement.statement = statement;
        } else {
          // From FIDO MDS docs: "Ignore the downloaded metadata statement if the hash value doesn't
          // match."
          cachedStatement.statement = undefined;
          throw new Error("Downloaded metadata for aaguid \"".concat(aaguid, "\" but hash did not match"));
        }
      }

      return cachedStatement.statement;
    })();
  }
  /**
   * Download and process the latest TOC from MDS
   */


  downloadTOC(mds) {
    var _this3 = this;

    return _asyncToGenerator(function* () {
      const {
        url,
        no,
        rootCertURL,
        metadataURLSuffix
      } = mds; // Query MDS for the latest TOC

      const respTOC = yield node_fetch_1.default(url);
      const data = yield respTOC.text(); // Break apart the JWT we get back

      const parsedJWT = parseJWT_1.default(data);
      const header = parsedJWT[0];
      const payload = parsedJWT[1];

      if (payload.no <= no) {
        // From FIDO MDS docs: "also ignore the file if its number (no) is less or equal to the
        // number of the last Metadata TOC object cached locally."
        throw new Error("Latest TOC no. \"".concat(payload.no, "\" is not greater than previous ").concat(no));
      }

      let fullCertPath = header.x5c.map(convertX509CertToPEM_1.default);

      if (rootCertURL.length > 0) {
        // Download FIDO the root certificate and append it to the TOC certs
        const respFIDORootCert = yield node_fetch_1.default(rootCertURL);
        const fidoRootCert = yield respFIDORootCert.text();
        fullCertPath = fullCertPath.concat(fidoRootCert);
      }

      try {
        // Validate the certificate chain
        yield validateCertificatePath_1.default(fullCertPath);
      } catch (err) {
        // From FIDO MDS docs: "ignore the file if the chain cannot be verified or if one of the
        // chain certificates is revoked"
        throw new Error("TOC certificate path could not be validated: ".concat(err.message));
      } // Verify the TOC JWT signature


      const leafCert = fullCertPath[0];
      const verified = jsrsasign_1.KJUR.jws.JWS.verifyJWT(data, leafCert, {
        alg: [header.alg],
        // Empty values to appease TypeScript and this library's subtly mis-typed @types definitions
        aud: [],
        iss: [],
        sub: []
      });

      if (!verified) {
        // From FIDO MDS docs: "The FIDO Server SHOULD ignore the file if the signature is invalid."
        throw new Error('TOC signature could not be verified');
      } // Prepare the in-memory cache of statements.


      for (const entry of payload.entries) {
        // Only cache entries with an `aaguid`
        if (entry.aaguid) {
          const _entry = entry;
          const cached = {
            url: "".concat(entry.url).concat(metadataURLSuffix),
            hash: entry.hash,
            statusReports: entry.statusReports,
            // An easy way for us to link back to a cached MDS API entry
            tocURL: url
          };
          _this3.statementCache[_entry.aaguid] = cached;
        }
      } // Cache this MDS API


      const [year, month, day] = payload.nextUpdate.split('-');
      _this3.mdsCache[url] = _objectSpread(_objectSpread({}, mds), {}, {
        // Store the header `alg` so we know what to use when verifying metadata statement hashes
        alg: header.alg,
        // Store the payload `no` to make sure we're getting the next TOC in the sequence
        no: payload.no,
        // Convert the nextUpdate property into a Date so we can determine when to re-download
        nextUpdate: new Date(parseInt(year, 10), // Months need to be zero-indexed
        parseInt(month, 10) - 1, parseInt(day, 10))
      });
    })();
  }
  /**
   * A helper method to pause execution until the service is ready
   */


  pauseUntilReady() {
    var _this4 = this;

    return _asyncToGenerator(function* () {
      if (_this4.state === SERVICE_STATE.READY) {
        return;
      } // State isn't ready, so set up polling


      const readyPromise = new Promise((resolve, reject) => {
        const totalTimeoutMS = 70000;
        const intervalMS = 100;
        let iterations = totalTimeoutMS / intervalMS; // Check service state every `intervalMS` milliseconds

        const intervalID = global.setInterval(() => {
          if (iterations < 1) {
            clearInterval(intervalID);
            reject("State did not become ready in ".concat(totalTimeoutMS / 1000, " seconds"));
          } else if (_this4.state === SERVICE_STATE.READY) {
            clearInterval(intervalID);
            resolve();
          }

          iterations -= 1;
        }, intervalMS);
      });
      return readyPromise;
    })();
  }

}

const metadataService = new MetadataService();
exports.default = metadataService;