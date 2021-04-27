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


import Joi from 'joi';
import { ModelSchema } from '../base'

/**
 * Request for the /1/object/ezsignfolder/editObject API Request
 * @export
 * @interface UNUSEDEzsignfolderEditObjectV1Request
 */
export interface UNUSEDEzsignfolderEditObjectV1Request {
    /**
     * 
     * @type {EzsignfolderRequest}
     * @memberof UNUSEDEzsignfolderEditObjectV1Request
     */
    objEzsignfolder?: EzsignfolderRequest;
}

/**
 * A UNUSEDEzsignfolderEditObjectV1Request Schema
 * @export
 * @class UNUSEDEzsignfolderEditObjectV1RequestSchema
 */
export class UNUSEDEzsignfolderEditObjectV1RequestSchema extends ModelSchema {
    schema = {
        objEzsignfolder: Joi.any(),
    }
}



