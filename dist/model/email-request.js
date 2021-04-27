"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.EmailRequestSchema = void 0;
const joi_1 = require("joi");
const base_1 = require("../base");
/**
 * A EmailRequest Schema
 * @export
 * @class EmailRequestSchema
 */
class EmailRequestSchema extends base_1.ModelSchema {
    constructor() {
        super(...arguments);
        this.schema = {
            fkiEmailtypeID: joi_1.default.number().required(),
            sEmailAddress: joi_1.default.string().required(),
        };
    }
}
exports.EmailRequestSchema = EmailRequestSchema;
