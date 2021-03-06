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
 * Description of the API Key
 * @export
 * @interface MultilingualApikeyDescription
 */
export interface MultilingualApikeyDescription {
    /**
     * Value in French
     * @type {string}
     * @memberof MultilingualApikeyDescription
     */
    sApikeyDescription1?: string;
    /**
     * Value in English
     * @type {string}
     * @memberof MultilingualApikeyDescription
     */
    sApikeyDescription2?: string;
}
/**
 * A MultilingualApikeyDescription Schema
 * @export
 * @class MultilingualApikeyDescriptionSchema
 */
export declare class MultilingualApikeyDescriptionSchema extends ModelSchema {
    schema: {
        sApikeyDescription1: Joi.StringSchema;
        sApikeyDescription2: Joi.StringSchema;
    };
}
