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
exports.EzsigndocumentApplyEzsigntemplateV1RequestSchema = void 0;
const joi_1 = require("joi");
const base_1 = require("../base");
/**
 * A EzsigndocumentApplyEzsigntemplateV1Request Schema
 * @export
 * @class EzsigndocumentApplyEzsigntemplateV1RequestSchema
 */
class EzsigndocumentApplyEzsigntemplateV1RequestSchema extends base_1.ModelSchema {
    constructor() {
        super(...arguments);
        this.schema = {
            fkiEzsigntemplateID: joi_1.default.number().required(),
            a_sEzsigntemplatesigner: joi_1.default.any().required(),
            a_pkiEzsignfoldersignerassociationID: joi_1.default.any().required(),
        };
    }
}
exports.EzsigndocumentApplyEzsigntemplateV1RequestSchema = EzsigndocumentApplyEzsigntemplateV1RequestSchema;
