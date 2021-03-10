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


import { FieldEUserTypeSSPR } from './field-euser-type-sspr';

/**
 * Request for the /1/module/sspr/resetPasswordRequest API Request
 * @export
 * @interface SsprResetPasswordRequestV1Request
 */
export interface SsprResetPasswordRequestV1Request {
    /**
     * The customer code assigned to your account
     * @type {string}
     * @memberof SsprResetPasswordRequestV1Request
     */
    pksCustomerCode: string;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof SsprResetPasswordRequestV1Request
     */
    fkiLanguageID: number;
    /**
     * 
     * @type {FieldEUserTypeSSPR}
     * @memberof SsprResetPasswordRequestV1Request
     */
    eUserTypeSSPR: FieldEUserTypeSSPR;
    /**
     * The email address.
     * @type {string}
     * @memberof SsprResetPasswordRequestV1Request
     */
    sEmailAddress?: string;
    /**
     * The Login name of the User.
     * @type {string}
     * @memberof SsprResetPasswordRequestV1Request
     */
    sUserLoginname?: string;
}


