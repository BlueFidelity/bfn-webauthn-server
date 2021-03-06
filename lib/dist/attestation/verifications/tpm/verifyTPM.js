"use strict";

require("core-js/modules/es.promise");

require("core-js/modules/es.regexp.to-string");

require("core-js/modules/es.string.replace");

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

const asn1_schema_1 = require("@peculiar/asn1-schema");

const asn1_x509_1 = require("@peculiar/asn1-x509");

const decodeCredentialPublicKey_1 = __importDefault(require("../../../helpers/decodeCredentialPublicKey"));

const convertCOSEtoPKCS_1 = require("../../../helpers/convertCOSEtoPKCS");

const toHash_1 = __importDefault(require("../../../helpers/toHash"));

const convertX509CertToPEM_1 = __importDefault(require("../../../helpers/convertX509CertToPEM"));

const getCertificateInfo_1 = __importDefault(require("../../../helpers/getCertificateInfo"));

const verifySignature_1 = __importDefault(require("../../../helpers/verifySignature"));

const metadataService_1 = __importDefault(require("../../../metadata/metadataService"));

const verifyAttestationWithMetadata_1 = __importDefault(require("../../../metadata/verifyAttestationWithMetadata"));

const constants_1 = require("./constants");

const parseCertInfo_1 = __importDefault(require("./parseCertInfo"));

const parsePubArea_1 = __importDefault(require("./parsePubArea"));

function verifyTPM(_x) {
  return _verifyTPM.apply(this, arguments);
}

function _verifyTPM() {
  _verifyTPM = _asyncToGenerator(function* (options) {
    var _a;

    const {
      aaguid,
      attStmt,
      authData,
      credentialPublicKey,
      clientDataHash
    } = options;
    const {
      ver,
      sig,
      alg,
      x5c,
      pubArea,
      certInfo
    } = attStmt;
    /**
     * Verify structures
     */

    if (ver !== '2.0') {
      throw new Error("Unexpected ver \"".concat(ver, "\", expected \"2.0\" (TPM)"));
    }

    if (!sig) {
      throw new Error('No attestation signature provided in attestation statement (TPM)');
    }

    if (!alg) {
      throw new Error("Attestation statement did not contain alg (TPM)");
    }

    if (!x5c) {
      throw new Error('No attestation certificate provided in attestation statement (TPM)');
    }

    if (!pubArea) {
      throw new Error('Attestation statement did not contain pubArea (TPM)');
    }

    if (!certInfo) {
      throw new Error('Attestation statement did not contain certInfo (TPM)');
    }

    const parsedPubArea = parsePubArea_1.default(pubArea);
    const {
      unique,
      type: pubType,
      parameters
    } = parsedPubArea; // Verify that the public key specified by the parameters and unique fields of pubArea is
    // identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.

    const cosePublicKey = decodeCredentialPublicKey_1.default(credentialPublicKey);

    if (pubType === 'TPM_ALG_RSA') {
      const n = cosePublicKey.get(convertCOSEtoPKCS_1.COSEKEYS.n);
      const e = cosePublicKey.get(convertCOSEtoPKCS_1.COSEKEYS.e);

      if (!n) {
        throw new Error('COSE public key missing n (TPM|RSA)');
      }

      if (!e) {
        throw new Error('COSE public key missing e (TPM|RSA)');
      }

      if (!unique.equals(n)) {
        throw new Error('PubArea unique is not same as credentialPublicKey (TPM|RSA)');
      }

      if (!parameters.rsa) {
        throw new Error("Parsed pubArea type is RSA, but missing parameters.rsa (TPM|RSA)");
      }

      const eBuffer = e; // If `exponent` is equal to 0x00, then exponent is the default RSA exponent of 2^16+1 (65537)

      const pubAreaExponent = parameters.rsa.exponent || 65537; // Do some bit shifting to get to an integer

      const eSum = eBuffer[0] + (eBuffer[1] << 8) + (eBuffer[2] << 16);

      if (pubAreaExponent !== eSum) {
        throw new Error("Unexpected public key exp ".concat(eSum, ", expected ").concat(pubAreaExponent, " (TPM|RSA)"));
      }
    } else if (pubType === 'TPM_ALG_ECC') {
      /**
       * TODO: Confirm this all works fine. Conformance tools v1.3.4 don't currently test ECC so I
       * had to eyeball it based on the **duo-labs/webauthn** library
       */
      const crv = cosePublicKey.get(convertCOSEtoPKCS_1.COSEKEYS.crv);
      const x = cosePublicKey.get(convertCOSEtoPKCS_1.COSEKEYS.x);
      const y = cosePublicKey.get(convertCOSEtoPKCS_1.COSEKEYS.y);

      if (!crv) {
        throw new Error('COSE public key missing crv (TPM|ECC)');
      }

      if (!x) {
        throw new Error('COSE public key missing x (TPM|ECC)');
      }

      if (!y) {
        throw new Error('COSE public key missing y (TPM|ECC)');
      }

      if (!unique.equals(Buffer.concat([x, y]))) {
        throw new Error('PubArea unique is not same as public key x and y (TPM|ECC)');
      }

      if (!parameters.ecc) {
        throw new Error("Parsed pubArea type is ECC, but missing parameters.ecc (TPM|ECC)");
      }

      const pubAreaCurveID = parameters.ecc.curveID;
      const pubKeyCurveID = constants_1.TPM_ECC_CURVE[crv.readUInt16BE(0)];

      if (pubAreaCurveID !== pubKeyCurveID) {
        throw new Error("Unexpected public key curve ID \"".concat(pubKeyCurveID, "\", expected \"").concat(pubAreaCurveID, "\" (TPM|ECC)"));
      }
    } else {
      throw new Error("Unsupported pubArea.type \"".concat(pubType, "\""));
    }

    const parsedCertInfo = parseCertInfo_1.default(certInfo);
    const {
      magic,
      type: certType,
      attested,
      extraData
    } = parsedCertInfo;

    if (magic !== 0xff544347) {
      throw new Error("Unexpected magic value \"".concat(magic, "\", expected \"0xff544347\" (TPM)"));
    }

    if (certType !== 'TPM_ST_ATTEST_CERTIFY') {
      throw new Error("Unexpected type \"".concat(certType, "\", expected \"TPM_ST_ATTEST_CERTIFY\" (TPM)"));
    } // Hash pubArea to create pubAreaHash using the nameAlg in attested


    const pubAreaHash = toHash_1.default(pubArea, attested.nameAlg.replace('TPM_ALG_', '')); // Concatenate attested.nameAlg and pubAreaHash to create attestedName.

    const attestedName = Buffer.concat([attested.nameAlgBuffer, pubAreaHash]); // Check that certInfo.attested.name is equals to attestedName.

    if (!attested.name.equals(attestedName)) {
      throw new Error("Attested name comparison failed (TPM)");
    } // Concatenate authData with clientDataHash to create attToBeSigned


    const attToBeSigned = Buffer.concat([authData, clientDataHash]); // Hash attToBeSigned using the algorithm specified in attStmt.alg to create attToBeSignedHash

    const hashAlg = convertCOSEtoPKCS_1.COSEALGHASH[alg];
    const attToBeSignedHash = toHash_1.default(attToBeSigned, hashAlg); // Check that certInfo.extraData is equals to attToBeSignedHash.

    if (!extraData.equals(attToBeSignedHash)) {
      throw new Error('CertInfo extra data did not equal hashed attestation (TPM)');
    }
    /**
     * Verify signature
     */


    if (x5c.length < 1) {
      throw new Error('No certificates present in x5c array (TPM)');
    } // Pick a leaf AIK certificate of the x5c array and parse it.


    const leafCertPEM = convertX509CertToPEM_1.default(x5c[0]);
    const leafCertInfo = getCertificateInfo_1.default(leafCertPEM);
    const {
      basicConstraintsCA,
      version,
      subject,
      notAfter,
      notBefore
    } = leafCertInfo;

    if (basicConstraintsCA) {
      throw new Error('Certificate basic constraints CA was not `false` (TPM)');
    } // Check that certificate is of version 3 (value must be set to 2).


    if (version !== 3) {
      throw new Error('Certificate version was not `3` (ASN.1 value of 2) (TPM)');
    } // Check that Subject sequence is empty.


    if (Object.keys(subject).length > 0) {
      throw new Error('Certificate subject was not empty (TPM)');
    } // Check that certificate is currently valid


    let now = new Date();

    if (notBefore > now) {
      throw new Error("Certificate not good before \"".concat(notBefore.toString(), "\" (TPM)"));
    } // Check that certificate has not expired


    now = new Date();

    if (notAfter < now) {
      throw new Error("Certificate not good after \"".concat(notAfter.toString(), "\" (TPM)"));
    }
    /**
     * Plumb the depths of the certificate's ASN.1-formatted data for some values we need to verify
     */


    const parsedCert = asn1_schema_1.AsnParser.parse(x5c[0], asn1_x509_1.Certificate);

    if (!parsedCert.tbsCertificate.extensions) {
      throw new Error('Certificate was missing extensions (TPM)');
    }

    let subjectAltNamePresent;
    let extKeyUsage;
    parsedCert.tbsCertificate.extensions.forEach(ext => {
      if (ext.extnID === asn1_x509_1.id_ce_subjectAltName) {
        subjectAltNamePresent = asn1_schema_1.AsnParser.parse(ext.extnValue, asn1_x509_1.SubjectAlternativeName);
      } else if (ext.extnID === asn1_x509_1.id_ce_extKeyUsage) {
        extKeyUsage = asn1_schema_1.AsnParser.parse(ext.extnValue, asn1_x509_1.ExtendedKeyUsage);
      }
    }); // Check that certificate contains subjectAltName (2.5.29.17) extension,

    if (!subjectAltNamePresent) {
      throw new Error('Certificate did not contain subjectAltName extension (TPM)');
    } // TPM-specific values are buried within `directoryName`, so first make sure there are values
    // there.


    if (!((_a = subjectAltNamePresent[0].directoryName) === null || _a === void 0 ? void 0 : _a[0].length)) {
      throw new Error('Certificate subjectAltName extension directoryName was empty (TPM)');
    }

    const {
      tcgAtTpmManufacturer,
      tcgAtTpmModel,
      tcgAtTpmVersion
    } = getTcgAtTpmValues(subjectAltNamePresent[0].directoryName);

    if (!tcgAtTpmManufacturer || !tcgAtTpmModel || !tcgAtTpmVersion) {
      throw new Error('Certificate contained incomplete subjectAltName data (TPM)');
    }

    if (!extKeyUsage) {
      throw new Error('Certificate did not contain ExtendedKeyUsage extension (TPM)');
    } // Check that tcpaTpmManufacturer (2.23.133.2.1) field is set to a valid manufacturer ID.


    if (!constants_1.TPM_MANUFACTURERS[tcgAtTpmManufacturer]) {
      throw new Error("Could not match TPM manufacturer \"".concat(tcgAtTpmManufacturer, "\" (TPM)"));
    } // Check that certificate contains extKeyUsage (2.5.29.37) extension and it must contain
    // tcg-kp-AIKCertificate (2.23.133.8.3) OID.


    if (extKeyUsage[0] !== '2.23.133.8.3') {
      throw new Error("Unexpected extKeyUsage \"".concat(extKeyUsage[0], "\", expected \"2.23.133.8.3\" (TPM)"));
    } // TODO: If certificate contains id-fido-gen-ce-aaguid(1.3.6.1.4.1.45724.1.1.4) extension, check
    // that it’s value is set to the same AAGUID as in authData.
    // Run some metadata checks if a statement exists for this authenticator


    const statement = yield metadataService_1.default.getStatement(aaguid);

    if (statement) {
      try {
        yield verifyAttestationWithMetadata_1.default(statement, alg, x5c);
      } catch (err) {
        throw new Error("".concat(err.message, " (TPM)"));
      }
    } // Verify signature over certInfo with the public key extracted from AIK certificate.
    // In the wise words of Yuriy Ackermann: "Get Martini friend, you are done!"


    return verifySignature_1.default(sig, certInfo, leafCertPEM, hashAlg);
  });
  return _verifyTPM.apply(this, arguments);
}

exports.default = verifyTPM;
/**
 * Contain logic for pulling TPM-specific values out of subjectAlternativeName extension
 */

function getTcgAtTpmValues(root) {
  const oidManufacturer = '2.23.133.2.1';
  const oidModel = '2.23.133.2.2';
  const oidVersion = '2.23.133.2.3';
  let tcgAtTpmManufacturer;
  let tcgAtTpmModel;
  let tcgAtTpmVersion;
  /**
   * Iterate through the following potential structures:
   *
   * (Good, follows the spec)
   * https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p3_r2_pub.pdf (page 33)
   * Name [
   *   RelativeDistinguishedName [
   *     AttributeTypeAndValue { type, value }
   *   ]
   *   RelativeDistinguishedName [
   *     AttributeTypeAndValue { type, value }
   *   ]
   *   RelativeDistinguishedName [
   *     AttributeTypeAndValue { type, value }
   *   ]
   * ]
   *
   * (Bad, does not follow the spec)
   * Name [
   *   RelativeDistinguishedName [
   *     AttributeTypeAndValue { type, value }
   *     AttributeTypeAndValue { type, value }
   *     AttributeTypeAndValue { type, value }
   *   ]
   * ]
   *
   * Both structures have been seen in the wild and need to be supported
   */

  root.forEach(relName => {
    relName.forEach(attr => {
      if (attr.type === oidManufacturer) {
        tcgAtTpmManufacturer = attr.value.toString();
      } else if (attr.type === oidModel) {
        tcgAtTpmModel = attr.value.toString();
      } else if (attr.type === oidVersion) {
        tcgAtTpmVersion = attr.value.toString();
      }
    });
  });
  return {
    tcgAtTpmManufacturer,
    tcgAtTpmModel,
    tcgAtTpmVersion
  };
}