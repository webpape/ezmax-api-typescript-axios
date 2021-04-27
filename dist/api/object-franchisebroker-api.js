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
exports.ObjectFranchisebrokerApi = exports.ObjectFranchisebrokerApiFactory = exports.ObjectFranchisebrokerApiFp = exports.ObjectFranchisebrokerApiAxiosParamCreator = void 0;
const axios_1 = require("axios");
// Some imports not used depending on template conditions
// @ts-ignore
const common_1 = require("../common");
// @ts-ignore
const base_1 = require("../base");
/**
 * ObjectFranchisebrokerApi - axios parameter creator
 * @export
 */
const ObjectFranchisebrokerApiAxiosParamCreator = function (configuration) {
    return {
        /**
         * Get the list of Franchisebrokers to be used in a dropdown or autocomplete control.
         * @summary Retrieve Franchisebrokers and IDs
         * @param {'Active' | 'All'} sSelector The type of Franchisebrokers to return
         * @param {string} [sQuery] Allow to filter on the option value
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        franchisebrokerGetAutocompleteV1: (sSelector, sQuery, options = {}) => __awaiter(this, void 0, void 0, function* () {
            // verify required parameter 'sSelector' is not null or undefined
            common_1.assertParamExists('franchisebrokerGetAutocompleteV1', 'sSelector', sSelector);
            const localVarPath = `/1/object/franchisebroker/getAutocomplete/{sSelector}`
                .replace(`{${"sSelector"}}`, encodeURIComponent(String(sSelector)));
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
            if (sQuery !== undefined) {
                localVarQueryParameter['sQuery'] = sQuery;
            }
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
exports.ObjectFranchisebrokerApiAxiosParamCreator = ObjectFranchisebrokerApiAxiosParamCreator;
/**
 * ObjectFranchisebrokerApi - functional programming interface
 * @export
 */
const ObjectFranchisebrokerApiFp = function (configuration) {
    const localVarAxiosParamCreator = exports.ObjectFranchisebrokerApiAxiosParamCreator(configuration);
    return {
        /**
         * Get the list of Franchisebrokers to be used in a dropdown or autocomplete control.
         * @summary Retrieve Franchisebrokers and IDs
         * @param {'Active' | 'All'} sSelector The type of Franchisebrokers to return
         * @param {string} [sQuery] Allow to filter on the option value
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        franchisebrokerGetAutocompleteV1(sSelector, sQuery, options) {
            return __awaiter(this, void 0, void 0, function* () {
                const localVarAxiosArgs = yield localVarAxiosParamCreator.franchisebrokerGetAutocompleteV1(sSelector, sQuery, options);
                return common_1.createRequestFunction(localVarAxiosArgs, axios_1.default, base_1.BASE_PATH, configuration);
            });
        },
    };
};
exports.ObjectFranchisebrokerApiFp = ObjectFranchisebrokerApiFp;
/**
 * ObjectFranchisebrokerApi - factory interface
 * @export
 */
const ObjectFranchisebrokerApiFactory = function (configuration, basePath, axios) {
    const localVarFp = exports.ObjectFranchisebrokerApiFp(configuration);
    return {
        /**
         * Get the list of Franchisebrokers to be used in a dropdown or autocomplete control.
         * @summary Retrieve Franchisebrokers and IDs
         * @param {'Active' | 'All'} sSelector The type of Franchisebrokers to return
         * @param {string} [sQuery] Allow to filter on the option value
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        franchisebrokerGetAutocompleteV1(sSelector, sQuery, options) {
            return localVarFp.franchisebrokerGetAutocompleteV1(sSelector, sQuery, options).then((request) => request(axios, basePath));
        },
    };
};
exports.ObjectFranchisebrokerApiFactory = ObjectFranchisebrokerApiFactory;
/**
 * ObjectFranchisebrokerApi - object-oriented interface
 * @export
 * @class ObjectFranchisebrokerApi
 * @extends {BaseAPI}
 */
class ObjectFranchisebrokerApi extends base_1.BaseAPI {
    /**
     * Get the list of Franchisebrokers to be used in a dropdown or autocomplete control.
     * @summary Retrieve Franchisebrokers and IDs
     * @param {'Active' | 'All'} sSelector The type of Franchisebrokers to return
     * @param {string} [sQuery] Allow to filter on the option value
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectFranchisebrokerApi
     */
    franchisebrokerGetAutocompleteV1(sSelector, sQuery, options) {
        return exports.ObjectFranchisebrokerApiFp(this.configuration).franchisebrokerGetAutocompleteV1(sSelector, sQuery, options).then((request) => request(this.axios, this.basePath));
    }
}
exports.ObjectFranchisebrokerApi = ObjectFranchisebrokerApi;
