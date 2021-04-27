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


import { CommonAudit } from './common-audit';
import { FieldEEzsignfolderSendreminderfrequency } from './field-eezsignfolder-sendreminderfrequency';
import { FieldEEzsignfolderStep } from './field-eezsignfolder-step';


import Joi from 'joi';
import { ModelSchema } from '../base'

/**
 * 
 * @export
 * @interface EzsignfolderResponseAllOf
 */
export interface EzsignfolderResponseAllOf {
    /**
     * The unique ID of the Ezsignfoldertype.    This value can be queried by the API and is also visible in the admin interface.    There are two types of Ezsignfoldertype. **User** and **Shared**. **User** can only be seen by the user who created the folder or its assistants. Access to **Shared** folders are configurable for access and email delivery. You should typically choose a **Shared** type here.
     * @type {number}
     * @memberof EzsignfolderResponseAllOf
     */
    fkiEzsignfoldertypeID: number;
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsignfolderResponseAllOf
     */
    fkiEzsigntsarequirementID: number;
    /**
     * The description of the Ezsign Folder
     * @type {string}
     * @memberof EzsignfolderResponseAllOf
     */
    sEzsignfolderDescription: string;
    /**
     * Somes extra notes about the eZsign Folder
     * @type {string}
     * @memberof EzsignfolderResponseAllOf
     */
    tEzsignfolderNote: string;
    /**
     * 
     * @type {FieldEEzsignfolderSendreminderfrequency}
     * @memberof EzsignfolderResponseAllOf
     */
    eEzsignfolderSendreminderfrequency: FieldEEzsignfolderSendreminderfrequency;
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfolderResponseAllOf
     */
    pkiEzsignfolderID: number;
    /**
     * The date and time at which the Ezsign folder was sent the last time.
     * @type {string}
     * @memberof EzsignfolderResponseAllOf
     */
    dtEzsignfolderSentdate: string;
    /**
     * 
     * @type {FieldEEzsignfolderStep}
     * @memberof EzsignfolderResponseAllOf
     */
    eEzsignfolderStep: FieldEEzsignfolderStep;
    /**
     * The date and time at which the folder was closed. Either by applying the last signature or by completing it prematurely.
     * @type {string}
     * @memberof EzsignfolderResponseAllOf
     */
    dtEzsignfolderClose: string;
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsignfolderResponseAllOf
     */
    objAudit: CommonAudit;
}

/**
 * A EzsignfolderResponseAllOf Schema
 * @export
 * @class EzsignfolderResponseAllOfSchema
 */
export class EzsignfolderResponseAllOfSchema extends ModelSchema {
    schema = {
        fkiEzsignfoldertypeID: Joi.number().required(),
        fkiEzsigntsarequirementID: Joi.number().required(),
        sEzsignfolderDescription: Joi.string().required(),
        tEzsignfolderNote: Joi.string().required(),
        eEzsignfolderSendreminderfrequency: Joi.any().required(),
        pkiEzsignfolderID: Joi.number().required(),
        dtEzsignfolderSentdate: Joi.string().required(),
        eEzsignfolderStep: Joi.any().required(),
        dtEzsignfolderClose: Joi.string().required(),
        objAudit: Joi.any().required(),
    }
}



