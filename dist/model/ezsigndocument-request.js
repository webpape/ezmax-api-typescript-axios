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
exports.EzsigndocumentRequestSchema = exports.EzsigndocumentRequestEEzsigndocumentFormatEnum = exports.EzsigndocumentRequestEEzsigndocumentSourceEnum = void 0;
const joi_1 = require("joi");
const base_1 = require("../base");
/**
    * @export
    * @enum {string}
    */
var EzsigndocumentRequestEEzsigndocumentSourceEnum;
(function (EzsigndocumentRequestEEzsigndocumentSourceEnum) {
    EzsigndocumentRequestEEzsigndocumentSourceEnum["Base64"] = "Base64";
})(EzsigndocumentRequestEEzsigndocumentSourceEnum = exports.EzsigndocumentRequestEEzsigndocumentSourceEnum || (exports.EzsigndocumentRequestEEzsigndocumentSourceEnum = {}));
/**
    * @export
    * @enum {string}
    */
var EzsigndocumentRequestEEzsigndocumentFormatEnum;
(function (EzsigndocumentRequestEEzsigndocumentFormatEnum) {
    EzsigndocumentRequestEEzsigndocumentFormatEnum["Pdf"] = "Pdf";
})(EzsigndocumentRequestEEzsigndocumentFormatEnum = exports.EzsigndocumentRequestEEzsigndocumentFormatEnum || (exports.EzsigndocumentRequestEEzsigndocumentFormatEnum = {}));
/**
 * A EzsigndocumentRequest Schema
 * @export
 * @class EzsigndocumentRequestSchema
 */
class EzsigndocumentRequestSchema extends base_1.ModelSchema {
    constructor() {
        super(...arguments);
        this.schema = {
            eEzsigndocumentSource: joi_1.default.string().required(),
            eEzsigndocumentFormat: joi_1.default.string().required(),
            sEzsigndocumentBase64: joi_1.default.string(),
            fkiEzsignfolderID: joi_1.default.number().required(),
            dtEzsigndocumentDuedate: joi_1.default.string().required(),
            fkiLanguageID: joi_1.default.number().required(),
            sEzsigndocumentName: joi_1.default.string().required(),
        };
    }
}
exports.EzsigndocumentRequestSchema = EzsigndocumentRequestSchema;
