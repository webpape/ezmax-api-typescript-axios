import sha256 from 'crypto-js/sha256';
import hmacSHA256 from 'crypto-js/hmac-sha256';
  
export interface IFingerprintData {
  authorization: string
  date: string
  method: string
  url: string
  body: string
}

export interface ISignatureData {
  authorization: string
  date: string
  fingerprint: string
  secret: string
}

export interface IHeadersData {
  authorization: string
  secret: string
  method: string
  url: string
  body: string
}

export class RequestSignature {
  public static getFingerprint(fingerprintData: IFingerprintData): string {
    const contentToHash = `${fingerprintData.method}\n${fingerprintData.url}\n${fingerprintData.body}\n${fingerprintData.authorization}\n${fingerprintData.date}`
    const output = sha256(contentToHash).toString()
    return 'v1=' + output
  }

  public static getSignature(signatureData: ISignatureData): string {
    const contentToSign = `${signatureData.fingerprint}${signatureData.authorization}${signatureData.date}`
    const output = hmacSHA256(contentToSign, signatureData.secret).toString();

    return 'v1=' + output
  }

  public static getHeaders(headerData: IHeadersData) {
    const date = new Date()
    const isoDate = date.toISOString().split('.')[0] + 'Z'

    const fingerprint: string = this.getFingerprint({
      authorization: headerData.authorization,
      date: isoDate,
      method: headerData.method,
      url: headerData.url,
      body: headerData.body
    })

    const signature: string = this.getSignature({
      authorization: headerData.authorization,
      date: isoDate,
      fingerprint: fingerprint,
      secret: headerData.secret
    })

    return {
      'Ezmax-Date': isoDate,
      'Ezmax-Fingerprint': fingerprint,
      'Ezmax-Signature': signature
    }
  }
}
