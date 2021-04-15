export interface IFingerprintData {
    authorization: string;
    date: string;
    method: string;
    url: string;
    body: string;
}
export interface ISignatureData {
    authorization: string;
    date: string;
    fingerprint: string;
    secret: string;
}
export interface IHeadersData {
    authorization: string;
    secret: string;
    method: string;
    url: string;
    body: string;
}
export declare class RequestSignature {
    static getFingerprint(fingerprintData: IFingerprintData): string;
    static getSignature(signatureData: ISignatureData): string;
    static getHeaders(headerData: IHeadersData): {
        'Ezmax-Date': string;
        'Ezmax-Fingerprint': string;
        'Ezmax-Signature': string;
    };
}
