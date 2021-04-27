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


import { UserResponse } from './user-response';


import Joi from 'joi';
import { ModelSchema } from '../base'

/**
 * 
 * @export
 * @interface WebhookUserUserCreatedAllOf
 */
export interface WebhookUserUserCreatedAllOf {
    /**
     * 
     * @type {UserResponse}
     * @memberof WebhookUserUserCreatedAllOf
     */
    objUser: UserResponse;
}

/**
 * A WebhookUserUserCreatedAllOf Schema
 * @export
 * @class WebhookUserUserCreatedAllOfSchema
 */
export class WebhookUserUserCreatedAllOfSchema extends ModelSchema {
    schema = {
        objUser: Joi.any().required(),
    }
}


