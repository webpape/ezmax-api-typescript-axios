/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.  # Authentication  <!-- ReDoc-Inject: <security-definitions> -->
 *
 * The version of the OpenAPI document: 1.0.31
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Payload for the /1/object/ezsigndocument/{pkiEzsigndocument}/getDownloadUrl API Request
 * @export
 * @interface EzsigndocumentGetDownloadUrlV1ResponseMPayload
 */
export interface EzsigndocumentGetDownloadUrlV1ResponseMPayload {
    /**
     * The Url to the requested document.  Url will expire after 5 minutes.
     * @type {string}
     * @memberof EzsigndocumentGetDownloadUrlV1ResponseMPayload
     */
    sDownloadUrl: string;
}


