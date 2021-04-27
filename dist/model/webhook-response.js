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
exports.WebhookResponseSchema = exports.WebhookResponseEWebhookManagementeventEnum = exports.WebhookResponseEWebhookEzsigneventEnum = exports.WebhookResponseEWebhookModuleEnum = void 0;
const joi_1 = require("joi");
const base_1 = require("../base");
/**
    * @export
    * @enum {string}
    */
var WebhookResponseEWebhookModuleEnum;
(function (WebhookResponseEWebhookModuleEnum) {
    WebhookResponseEWebhookModuleEnum["Ezsign"] = "Ezsign";
    WebhookResponseEWebhookModuleEnum["Management"] = "Management";
})(WebhookResponseEWebhookModuleEnum = exports.WebhookResponseEWebhookModuleEnum || (exports.WebhookResponseEWebhookModuleEnum = {}));
/**
    * @export
    * @enum {string}
    */
var WebhookResponseEWebhookEzsigneventEnum;
(function (WebhookResponseEWebhookEzsigneventEnum) {
    WebhookResponseEWebhookEzsigneventEnum["DocumentCompleted"] = "DocumentCompleted";
    WebhookResponseEWebhookEzsigneventEnum["FolderCompleted"] = "FolderCompleted";
})(WebhookResponseEWebhookEzsigneventEnum = exports.WebhookResponseEWebhookEzsigneventEnum || (exports.WebhookResponseEWebhookEzsigneventEnum = {}));
/**
    * @export
    * @enum {string}
    */
var WebhookResponseEWebhookManagementeventEnum;
(function (WebhookResponseEWebhookManagementeventEnum) {
    WebhookResponseEWebhookManagementeventEnum["UserCreated"] = "UserCreated";
})(WebhookResponseEWebhookManagementeventEnum = exports.WebhookResponseEWebhookManagementeventEnum || (exports.WebhookResponseEWebhookManagementeventEnum = {}));
/**
 * A WebhookResponse Schema
 * @export
 * @class WebhookResponseSchema
 */
class WebhookResponseSchema extends base_1.ModelSchema {
    constructor() {
        super(...arguments);
        this.schema = {
            pkiWebhookID: joi_1.default.number().required(),
            eWebhookModule: joi_1.default.string().required(),
            eWebhookEzsignevent: joi_1.default.string(),
            pksCustomerCode: joi_1.default.string().required().max(6).min(2),
            sWebhookUrl: joi_1.default.string().required(),
            sWebhookEmailfailed: joi_1.default.string().required(),
            eWebhookManagementevent: joi_1.default.string(),
        };
    }
}
exports.WebhookResponseSchema = WebhookResponseSchema;
