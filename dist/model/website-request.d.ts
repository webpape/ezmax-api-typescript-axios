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
 * A Website Object
 * @export
 * @interface WebsiteRequest
 */
export interface WebsiteRequest {
    /**
     * The unique ID of the Websitetype.  Valid values:  |Value|Description| |-|-| |1|Website| |2|Twitter| |3|Facebook| |4|Survey|
     * @type {number}
     * @memberof WebsiteRequest
     */
    fkiWebsitetypeID: number;
    /**
     * The URL of the website.
     * @type {string}
     * @memberof WebsiteRequest
     */
    sWebsiteAddress: string;
}
/**
 * A WebsiteRequest Schema
 * @export
 * @class WebsiteRequestSchema
 */
export declare class WebsiteRequestSchema extends ModelSchema {
    schema: {
        fkiWebsitetypeID: Joi.NumberSchema;
        sWebsiteAddress: Joi.StringSchema;
    };
}
