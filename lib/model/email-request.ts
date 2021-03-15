/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.  # Authentication  <!-- ReDoc-Inject: <security-definitions> -->
 *
 * The version of the OpenAPI document: 1.0.32
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Contact Object
 * @export
 * @interface EmailRequest
 */
export interface EmailRequest {
    /**
     * The unique ID of the Emailtype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home|
     * @type {number}
     * @memberof EmailRequest
     */
    fkiEmailtypeID: number;
    /**
     * The email address.
     * @type {string}
     * @memberof EmailRequest
     */
    sEmailAddress: string;
}


