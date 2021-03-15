/* tslint:disable */
/* eslint-disable */
import forge from 'node-forge'

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

// Ezmax-Date: 2021-12-31T23:59:59Z
// Ezmax-Fingerprint: v1=9143277832f2905403c1245ce462ccf5ae23266bcb93f1f072d87394cec7d3a5
// Ezmax-Signature: v1=071f141083f28003ef601cfe71c5e85f244dd9001df684befe55b5b6b2ecbd94

export class RequestSignatureApi {
  public static getFingerprint(fingerprintData: IFingerprintData): string {
    const contentToHash = `${fingerprintData.method}\n${fingerprintData.url}\n${fingerprintData.body}\n${fingerprintData.authorization}\n${fingerprintData.date}`
    const output: string = forge.md.sha256.create().update(contentToHash).digest().toHex()
    return 'v1=' + output
  }

  public static getSignature(signatureData: ISignatureData): string {
    const contentToSign = `${signatureData.fingerprint}${signatureData.authorization}${signatureData.date}`

    const hmac = forge.hmac.create()
    hmac.start('sha512/256', signatureData.secret)
    hmac.update(contentToSign)

    const output: string = hmac.digest().toHex()

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
