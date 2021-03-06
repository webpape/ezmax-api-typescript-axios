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


import { EzsignsignatureRequest } from './ezsignsignature-request';
import { EzsignsignatureRequestCompound } from './ezsignsignature-request-compound';


import Joi from 'joi';
import { ModelSchema } from '../base'

/**
 * Request for the /1/object/ezsignsignature/createObject API Request
 * @export
 * @interface EzsignsignatureCreateObjectV1Request
 */
export interface EzsignsignatureCreateObjectV1Request {
    /**
     * 
     * @type {EzsignsignatureRequest}
     * @memberof EzsignsignatureCreateObjectV1Request
     */
    objEzsignsignature?: EzsignsignatureRequest;
    /**
     * 
     * @type {EzsignsignatureRequestCompound}
     * @memberof EzsignsignatureCreateObjectV1Request
     */
    objEzsignsignatureCompound?: EzsignsignatureRequestCompound;
}

/**
 * A EzsignsignatureCreateObjectV1Request Schema
 * @export
 * @class EzsignsignatureCreateObjectV1RequestSchema
 */
export class EzsignsignatureCreateObjectV1RequestSchema extends ModelSchema {
    schema = {
        objEzsignsignature: Joi.any(),
        objEzsignsignatureCompound: Joi.any(),
    }
}



