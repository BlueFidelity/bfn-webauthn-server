# bfn-webauthn-server

> Boot Fidelity Webauthn Server

[![NPM Version][npm-image]][npm-url]

## Overview

Fork of [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/server) that works in Node V6.

## Install

```
$ npm install --save bfn-webauthn-server
```

## Example

**Verify Attestation Response:**
``` js
var simpleWebAuthn = require('bfn-webauthn-server');

var exampleAttestationResponse = {
	credential: {
		"id": "csR4ANRLKorPuJENvQQW8egUJYh-8ZWIqiGloO032Oc",
		"type": "public-key",
		"rawId": "csR4ANRLKorPuJENvQQW8egUJYh-8ZWIqiGloO032Oc",
		"response": {
			"clientDataJSON": "eyJjaGFsbGVuZ2UiOiI3YjFtNm4yS2dNQ......IsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
			"attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0...DvLFRA5Bn3dGgzy"
		}
	},
	expectedChallenge: "58dCluFFQKrmrJzbPt_O5VNWUBoHoW4gY01eZ_M2PjRYLZMgiUE86Krd7Jc",
	expectedOrigin: "https://example.com",
	expectedRPID: "example.com",
};

simpleWebAuthn.verifyAttestationResponse(exampleAttestationResponse).then(function(verification){
	if (!verification || !verification.verified || !verification.authenticatorInfo || !verification.authenticatorInfo.base64CredentialID || !verification.authenticatorInfo.base64PublicKey || typeof verification.authenticatorInfo.counter !== 'number') {
		console.log('not verified');
	} else {
		console.log('verified');
	}
}).catch(function(e){
	console.log('Error', e);
});
```

**Verify Assertion Response:**
``` js
var simpleWebAuthn = require('bfn-webauthn-server');

var exampleAssertionResponse = {
	"id": "csR4ANRLKorPuJENvQQW8egUJYh-8ZWIqiGloO032Oc",
	"rawId": "csR4ANRLKorPuJENvQQW8egUJYh-8ZWIqiGloO032Oc",
	"response": {
		"clientDataJSON": "eyJjaGFsbGVuZ2UiOiI3YjFtNm4yS2dNQ......IsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
		"signature": "IQLxgOSZP3npllWWth8Yj......JkuZXhoCP3NifZw",
		"authenticatorData": "o2NmbXRmcGFja2VkZ2F0dFN0...DvLFRA5Bn3dGgzy"
	},
	"type": "public-key"
};

var err, verification;

try {
	verification = simpleWebAuthn.verifyAssertionResponse(exampleAssertionResponse);
} catch (e) {
	err = e;
	verification = false;
}

if (err) {
	console.log('Error', e);
} else if (!verification || !verification.verified || !verification.authenticatorInfo || !verification.authenticatorInfo.base64CredentialID || typeof verification.authenticatorInfo.counter !== 'number') {
	console.log('not verified');
} else {
	console.log('verified');
}
```

## Supported Attestation Formats

Supports [all six WebAuthn attestation formats](https://w3c.github.io/webauthn/#sctn-defined-attestation-formats), including:

- **Packed**
- **TPM**
- **Android Key**
- **Android SafetyNet**
- **FIDO U2F**
- **None**

## Supported Node Version

* 6.17.1

## License

[MIT](LICENSE)

[npm-image]: https://img.shields.io/npm/v/bfn-webauthn-server.svg
[npm-url]: https://npmjs.org/package/bfn-webauthn-server
