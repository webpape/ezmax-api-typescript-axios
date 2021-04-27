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
 * @interface ContactRequest
 */
export interface ContactRequest {
    /**
     * The unique ID of the Contacttitle.  Valid values:  |Value|Description| |-|-| |1|Ms.| |2|Mr.| |4|(Blank)| |5|Me (For Notaries)|
     * @type {number}
     * @memberof ContactRequest
     */
    fkiContacttitleID: number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof ContactRequest
     */
    fkiLanguageID: number;
    /**
     * The First name of the contact
     * @type {string}
     * @memberof ContactRequest
     */
    sContactFirstname: string;
    /**
     * The Last name of the contact
     * @type {string}
     * @memberof ContactRequest
     */
    sContactLastname: string;
    /**
     * The Company name of the contact
     * @type {string}
     * @memberof ContactRequest
     */
    sContactCompany: string;
    /**
     * The Birth Date of the contact
     * @type {string}
     * @memberof ContactRequest
     */
    dtContactBirthdate?: string;
}
/**
 * A ContactRequest Schema
 * @export
 * @class ContactRequestSchema
 */
export declare class ContactRequestSchema extends ModelSchema {
    schema: {
        fkiContacttitleID: Joi.NumberSchema;
        fkiLanguageID: Joi.NumberSchema;
        sContactFirstname: Joi.StringSchema;
        sContactLastname: Joi.StringSchema;
        sContactCompany: Joi.StringSchema;
        dtContactBirthdate: Joi.StringSchema;
    };
}
