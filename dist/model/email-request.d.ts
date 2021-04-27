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
/**
 * A EmailRequest Schema
 * @export
 * @class EmailRequestSchema
 */
export declare class EmailRequestSchema extends ModelSchema {
    schema: {
        fkiEmailtypeID: Joi.NumberSchema;
        sEmailAddress: Joi.StringSchema;
    };
}
