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
exports.CommonGetAutocompleteV1ResponseMPayloadSchema = void 0;
const joi_1 = require("joi");
const base_1 = require("../base");
/**
 * A CommonGetAutocompleteV1ResponseMPayload Schema
 * @export
 * @class CommonGetAutocompleteV1ResponseMPayloadSchema
 */
class CommonGetAutocompleteV1ResponseMPayloadSchema extends base_1.ModelSchema {
    constructor() {
        super(...arguments);
        this.schema = {
            group: joi_1.default.string().required(),
            id: joi_1.default.string().required(),
            option: joi_1.default.string().required(),
        };
    }
}
exports.CommonGetAutocompleteV1ResponseMPayloadSchema = CommonGetAutocompleteV1ResponseMPayloadSchema;
