"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RequestSignature = void 0;
const crypto_js_1 = require("crypto-js");
class RequestSignature {
    static getFingerprint(fingerprintData) {
        const contentToHash = `${fingerprintData.method}\n${fingerprintData.url}\n${fingerprintData.body}\n${fingerprintData.authorization}\n${fingerprintData.date}`;
        const output = crypto_js_1.SHA256(contentToHash).toString();
        return 'v1=' + output;
    }
    static getSignature(signatureData) {
        const contentToSign = `${signatureData.fingerprint}${signatureData.authorization}${signatureData.date}`;
        const output = crypto_js_1.HmacSHA256(contentToSign, signatureData.secret).toString();
        return 'v1=' + output;
    }
    static getHeaders(headerData) {
        const date = new Date();
        const isoDate = date.toISOString().split('.')[0] + 'Z';
        const fingerprint = this.getFingerprint({
            authorization: headerData.authorization,
            date: isoDate,
            method: headerData.method,
            url: headerData.url,
            body: headerData.body
        });
        const signature = this.getSignature({
            authorization: headerData.authorization,
            date: isoDate,
            fingerprint: fingerprint,
            secret: headerData.secret
        });
        return {
            'Ezmax-Date': isoDate,
            'Ezmax-Fingerprint': fingerprint,
            'Ezmax-Signature': signature
        };
    }
}
exports.RequestSignature = RequestSignature;
