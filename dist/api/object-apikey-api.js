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
exports.ObjectApikeyApi = exports.ObjectApikeyApiFactory = exports.ObjectApikeyApiFp = exports.ObjectApikeyApiAxiosParamCreator = void 0;
const axios_1 = require("axios");
// Some imports not used depending on template conditions
// @ts-ignore
const common_1 = require("../common");
// @ts-ignore
const base_1 = require("../base");
/**
 * ObjectApikeyApi - axios parameter creator
 * @export
 */
const ObjectApikeyApiAxiosParamCreator = function (configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Apikey
         * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyCreateObjectV1: (apikeyCreateObjectV1Request, options = {}) => __awaiter(this, void 0, void 0, function* () {
            // verify required parameter 'apikeyCreateObjectV1Request' is not null or undefined
            common_1.assertParamExists('apikeyCreateObjectV1', 'apikeyCreateObjectV1Request', apikeyCreateObjectV1Request);
            const localVarPath = `/1/object/apikey`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, common_1.DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }
            const localVarRequestOptions = Object.assign(Object.assign({ method: 'POST' }, baseOptions), options);
            const localVarHeaderParameter = {};
            const localVarQueryParameter = {};
            // authentication Authorization required
            yield common_1.setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration);
            localVarHeaderParameter['Content-Type'] = 'application/json';
            common_1.setSearchParams(localVarUrlObj, localVarQueryParameter, options.query);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = Object.assign(Object.assign(Object.assign({}, localVarHeaderParameter), headersFromBaseOptions), options.headers);
            localVarRequestOptions.data = common_1.serializeDataIfNeeded(apikeyCreateObjectV1Request, localVarRequestOptions, configuration);
            return {
                url: common_1.toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        }),
    };
};
exports.ObjectApikeyApiAxiosParamCreator = ObjectApikeyApiAxiosParamCreator;
/**
 * ObjectApikeyApi - functional programming interface
 * @export
 */
const ObjectApikeyApiFp = function (configuration) {
    const localVarAxiosParamCreator = exports.ObjectApikeyApiAxiosParamCreator(configuration);
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Apikey
         * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyCreateObjectV1(apikeyCreateObjectV1Request, options) {
            return __awaiter(this, void 0, void 0, function* () {
                const localVarAxiosArgs = yield localVarAxiosParamCreator.apikeyCreateObjectV1(apikeyCreateObjectV1Request, options);
                return common_1.createRequestFunction(localVarAxiosArgs, axios_1.default, base_1.BASE_PATH, configuration);
            });
        },
    };
};
exports.ObjectApikeyApiFp = ObjectApikeyApiFp;
/**
 * ObjectApikeyApi - factory interface
 * @export
 */
const ObjectApikeyApiFactory = function (configuration, basePath, axios) {
    const localVarFp = exports.ObjectApikeyApiFp(configuration);
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Apikey
         * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyCreateObjectV1(apikeyCreateObjectV1Request, options) {
            return localVarFp.apikeyCreateObjectV1(apikeyCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
    };
};
exports.ObjectApikeyApiFactory = ObjectApikeyApiFactory;
/**
 * ObjectApikeyApi - object-oriented interface
 * @export
 * @class ObjectApikeyApi
 * @extends {BaseAPI}
 */
class ObjectApikeyApi extends base_1.BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
     * @summary Create a new Apikey
     * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectApikeyApi
     */
    apikeyCreateObjectV1(apikeyCreateObjectV1Request, options) {
        return exports.ObjectApikeyApiFp(this.configuration).apikeyCreateObjectV1(apikeyCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }
}
exports.ObjectApikeyApi = ObjectApikeyApi;
