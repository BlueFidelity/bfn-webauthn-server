"use strict";

require("core-js/modules/es.string.split");

require("core-js/modules/web.dom-collections.iterator");

Object.defineProperty(exports, "__esModule", {
  value: true
});

const jsrsasign_1 = require("jsrsasign");
/**
 * Extract PEM certificate info
 *
 * @param pemCertificate Result from call to `convertASN1toPEM(x5c[0])`
 */


function getCertificateInfo(pemCertificate) {
  var _a;

  const subjectCert = new jsrsasign_1.X509();
  subjectCert.readCertPEM(pemCertificate); // Break apart the Issuer

  const issuerString = subjectCert.getIssuerString();
  const issuerParts = issuerString.slice(1).split('/');
  const issuer = {};
  issuerParts.forEach(field => {
    const [key, val] = field.split('=');
    issuer[key] = val;
  }); // Break apart the Subject

  let subjectRaw = '/';

  try {
    subjectRaw = subjectCert.getSubjectString();
  } catch (err) {
    // Don't throw on an error that indicates an empty subject
    if (err !== 'malformed RDN') {
      throw err;
    }
  }

  const subjectParts = subjectRaw.slice(1).split('/');
  const subject = {};
  subjectParts.forEach(field => {
    if (field) {
      const [key, val] = field.split('=');
      subject[key] = val;
    }
  });
  const {
    version
  } = subjectCert;
  const basicConstraintsCA = !!((_a = subjectCert.getExtBasicConstraints()) === null || _a === void 0 ? void 0 : _a.cA);
  return {
    issuer,
    subject,
    version,
    basicConstraintsCA,
    notBefore: jsrsasign_1.zulutodate(subjectCert.getNotBefore()),
    notAfter: jsrsasign_1.zulutodate(subjectCert.getNotAfter())
  };
}

exports.default = getCertificateInfo;