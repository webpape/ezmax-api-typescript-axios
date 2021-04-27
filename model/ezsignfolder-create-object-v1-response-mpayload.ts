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




import Joi from 'joi';
import { ModelSchema } from '../base'

/**
 * Payload for the /1/object/ezsignfolder/createObject API Request
 * @export
 * @interface EzsignfolderCreateObjectV1ResponseMPayload
 */
export interface EzsignfolderCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsignfolderCreateObjectV1ResponseMPayload
     */
    a_pkiEzsignfolderID: Array<number>;
}

/**
 * A EzsignfolderCreateObjectV1ResponseMPayload Schema
 * @export
 * @class EzsignfolderCreateObjectV1ResponseMPayloadSchema
 */
export class EzsignfolderCreateObjectV1ResponseMPayloadSchema extends ModelSchema {
    schema = {
        a_pkiEzsignfolderID: Joi.any().required(),
    }
}



