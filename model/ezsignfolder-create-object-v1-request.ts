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


import { EzsignfolderRequest } from './ezsignfolder-request';
import { EzsignfolderRequestCompound } from './ezsignfolder-request-compound';


import Joi from 'joi';
import { ModelSchema } from '../base'

/**
 * Request for the /1/object/ezsignfolder/createObject API Request
 * @export
 * @interface EzsignfolderCreateObjectV1Request
 */
export interface EzsignfolderCreateObjectV1Request {
    /**
     * 
     * @type {EzsignfolderRequest}
     * @memberof EzsignfolderCreateObjectV1Request
     */
    objEzsignfolder?: EzsignfolderRequest;
    /**
     * 
     * @type {EzsignfolderRequestCompound}
     * @memberof EzsignfolderCreateObjectV1Request
     */
    objEzsignfolderCompound?: EzsignfolderRequestCompound;
}

/**
 * A EzsignfolderCreateObjectV1Request Schema
 * @export
 * @class EzsignfolderCreateObjectV1RequestSchema
 */
export class EzsignfolderCreateObjectV1RequestSchema extends ModelSchema {
    schema = {
        objEzsignfolder: Joi.any(),
        objEzsignfolderCompound: Joi.any(),
    }
}



