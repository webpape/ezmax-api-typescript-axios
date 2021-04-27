/* tslint:disable */
/* eslint-disable */
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


import { ApikeyResponse } from './apikey-response';


import Joi from 'joi';
import { ModelSchema } from '../base'

/**
 * Payload for the /1/object/apikey/createObject API Request
 * @export
 * @interface ApikeyCreateObjectV1ResponseMPayload
 */
export interface ApikeyCreateObjectV1ResponseMPayload {
    /**
     * 
     * @type {Array<ApikeyResponse>}
     * @memberof ApikeyCreateObjectV1ResponseMPayload
     */
    a_objApikey: Array<ApikeyResponse>;
}

/**
 * A ApikeyCreateObjectV1ResponseMPayload Schema
 * @export
 * @class ApikeyCreateObjectV1ResponseMPayloadSchema
 */
export class ApikeyCreateObjectV1ResponseMPayloadSchema extends ModelSchema {
    schema = {
        a_objApikey: Joi.any().required(),
    }
}



