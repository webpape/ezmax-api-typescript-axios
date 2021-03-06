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
exports.ModelSchema = exports.RequiredError = exports.BaseAPI = exports.COLLECTION_FORMATS = exports.BASE_PATH = void 0;
// Some imports not used depending on template conditions
// @ts-ignore
const axios_1 = require("axios");
const joi_1 = require("joi");
exports.BASE_PATH = "https://prod.api.appcluster01.ca-central-1.ezmax.com/rest".replace(/\/+$/, "");
/**
 *
 * @export
 */
exports.COLLECTION_FORMATS = {
    csv: ",",
    ssv: " ",
    tsv: "\t",
    pipes: "|",
};
/**
 *
 * @export
 * @class BaseAPI
 */
class BaseAPI {
    constructor(configuration, basePath = exports.BASE_PATH, axios = axios_1.default) {
        this.basePath = basePath;
        this.axios = axios;
        if (configuration) {
            this.configuration = configuration;
            this.basePath = configuration.basePath || this.basePath;
        }
    }
}
exports.BaseAPI = BaseAPI;
;
/**
 *
 * @export
 * @class RequiredError
 * @extends {Error}
 */
class RequiredError extends Error {
    constructor(field, msg) {
        super(msg);
        this.field = field;
        this.name = "RequiredError";
    }
}
exports.RequiredError = RequiredError;
/**
 *
 * @export
 * @class ModelSchema
 */
class ModelSchema {
    constructor() {
        this.schema = {};
    }
    create() {
        return joi_1.default.object(this.schema);
    }
    get(key) {
        return this.schema[key];
    }
    attempt(key, value) {
        return joi_1.default.attempt(value, this.schema[key]);
    }
    assert(key, value) {
        return joi_1.default.assert(value, this.schema[key]);
    }
    validate(data) {
        const schema = this.create();
        return schema.validate(data);
    }
}
exports.ModelSchema = ModelSchema;
