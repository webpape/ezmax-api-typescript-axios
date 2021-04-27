/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.42
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
import Joi from 'joi';
import { ModelSchema } from '../base';
/**
 * Payload for the /1/module/user/createEzsignuser API Request
 * @export
 * @interface UserCreateEzsignuserV1ResponseMPayload
 */
export interface UserCreateEzsignuserV1ResponseMPayload {
    /**
     * An array of email addresses that succeeded.
     * @type {Array<string>}
     * @memberof UserCreateEzsignuserV1ResponseMPayload
     */
    a_sEmailAddressSuccess: Array<string>;
    /**
     * An array of email addresses that failed.
     * @type {Array<string>}
     * @memberof UserCreateEzsignuserV1ResponseMPayload
     */
    a_sEmailAddressFailure: Array<string>;
}
/**
 * A UserCreateEzsignuserV1ResponseMPayload Schema
 * @export
 * @class UserCreateEzsignuserV1ResponseMPayloadSchema
 */
export declare class UserCreateEzsignuserV1ResponseMPayloadSchema extends ModelSchema {
    schema: {
        a_sEmailAddressSuccess: Joi.AnySchema;
        a_sEmailAddressFailure: Joi.AnySchema;
    };
}
