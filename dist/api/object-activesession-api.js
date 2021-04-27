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
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ObjectActivesessionApi = exports.ObjectActivesessionApiFactory = exports.ObjectActivesessionApiFp = exports.ObjectActivesessionApiAxiosParamCreator = void 0;
const axios_1 = require("axios");
// Some imports not used depending on template conditions
// @ts-ignore
const common_1 = require("../common");
// @ts-ignore
const base_1 = require("../base");
/**
 * ObjectActivesessionApi - axios parameter creator
 * @export
 */
const ObjectActivesessionApiAxiosParamCreator = function (configuration) {
    return {
        /**
         * Retrieve the details about the current activesession
         * @summary Get Current Activesession
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        activesessionGetCurrentV1: (options = {}) => __awaiter(this, void 0, void 0, function* () {
            const localVarPath = `/1/object/activesession/getCurrent`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, common_1.DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }
            const localVarRequestOptions = Object.assign(Object.assign({ method: 'GET' }, baseOptions), options);
            const localVarHeaderParameter = {};
            const localVarQueryParameter = {};
            // authentication Authorization required
            yield common_1.setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration);
            common_1.setSearchParams(localVarUrlObj, localVarQueryParameter, options.query);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = Object.assign(Object.assign(Object.assign({}, localVarHeaderParameter), headersFromBaseOptions), options.headers);
            return {
                url: common_1.toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        }),
    };
};
exports.ObjectActivesessionApiAxiosParamCreator = ObjectActivesessionApiAxiosParamCreator;
/**
 * ObjectActivesessionApi - functional programming interface
 * @export
 */
const ObjectActivesessionApiFp = function (configuration) {
    const localVarAxiosParamCreator = exports.ObjectActivesessionApiAxiosParamCreator(configuration);
    return {
        /**
         * Retrieve the details about the current activesession
         * @summary Get Current Activesession
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        activesessionGetCurrentV1(options) {
            return __awaiter(this, void 0, void 0, function* () {
                const localVarAxiosArgs = yield localVarAxiosParamCreator.activesessionGetCurrentV1(options);
                return common_1.createRequestFunction(localVarAxiosArgs, axios_1.default, base_1.BASE_PATH, configuration);
            });
        },
    };
};
exports.ObjectActivesessionApiFp = ObjectActivesessionApiFp;
/**
 * ObjectActivesessionApi - factory interface
 * @export
 */
const ObjectActivesessionApiFactory = function (configuration, basePath, axios) {
    const localVarFp = exports.ObjectActivesessionApiFp(configuration);
    return {
        /**
         * Retrieve the details about the current activesession
         * @summary Get Current Activesession
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        activesessionGetCurrentV1(options) {
            return localVarFp.activesessionGetCurrentV1(options).then((request) => request(axios, basePath));
        },
    };
};
exports.ObjectActivesessionApiFactory = ObjectActivesessionApiFactory;
/**
 * ObjectActivesessionApi - object-oriented interface
 * @export
 * @class ObjectActivesessionApi
 * @extends {BaseAPI}
 */
class ObjectActivesessionApi extends base_1.BaseAPI {
    /**
     * Retrieve the details about the current activesession
     * @summary Get Current Activesession
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectActivesessionApi
     */
    activesessionGetCurrentV1(options) {
        return exports.ObjectActivesessionApiFp(this.configuration).activesessionGetCurrentV1(options).then((request) => request(this.axios, this.basePath));
    }
}
exports.ObjectActivesessionApi = ObjectActivesessionApi;
