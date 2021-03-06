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
import { EzsignfolderResponse } from './ezsignfolder-response';
import Joi from 'joi';
import { ModelSchema } from '../base';
/**
 *
 * @export
 * @interface WebhookEzsignFolderCompletedAllOf
 */
export interface WebhookEzsignFolderCompletedAllOf {
    /**
     *
     * @type {EzsignfolderResponse}
     * @memberof WebhookEzsignFolderCompletedAllOf
     */
    objEzsignfolder: EzsignfolderResponse;
}
/**
 * A WebhookEzsignFolderCompletedAllOf Schema
 * @export
 * @class WebhookEzsignFolderCompletedAllOfSchema
 */
export declare class WebhookEzsignFolderCompletedAllOfSchema extends ModelSchema {
    schema: {
        objEzsignfolder: Joi.AnySchema;
    };
}
