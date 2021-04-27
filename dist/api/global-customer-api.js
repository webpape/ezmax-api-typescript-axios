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
exports.GlobalCustomerApi = exports.GlobalCustomerApiFactory = exports.GlobalCustomerApiFp = exports.GlobalCustomerApiAxiosParamCreator = void 0;
const axios_1 = require("axios");
// Some imports not used depending on template conditions
// @ts-ignore
const common_1 = require("../common");
// @ts-ignore
const base_1 = require("../base");
/**
 * GlobalCustomerApi - axios parameter creator
 * @export
 */
const GlobalCustomerApiAxiosParamCreator = function (configuration) {
    return {
        /**
         * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
         * @summary Get customer endpoint
         * @param {string} pksCustomerCode The customer code assigned to your account
         * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        globalCustomerGetEndpointV1: (pksCustomerCode, sInfrastructureproductCode, options = {}) => __awaiter(this, void 0, void 0, function* () {
            // verify required parameter 'pksCustomerCode' is not null or undefined
            common_1.assertParamExists('globalCustomerGetEndpointV1', 'pksCustomerCode', pksCustomerCode);
            const localVarPath = `/1/customer/{pksCustomerCode}/endpoint`
                .replace(`{${"pksCustomerCode"}}`, encodeURIComponent(String(pksCustomerCode)));
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
            if (sInfrastructureproductCode !== undefined) {
                localVarQueryParameter['sInfrastructureproductCode'] = sInfrastructureproductCode;
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
exports.GlobalCustomerApiAxiosParamCreator = GlobalCustomerApiAxiosParamCreator;
/**
 * GlobalCustomerApi - functional programming interface
 * @export
 */
const GlobalCustomerApiFp = function (configuration) {
    const localVarAxiosParamCreator = exports.GlobalCustomerApiAxiosParamCreator(configuration);
    return {
        /**
         * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
         * @summary Get customer endpoint
         * @param {string} pksCustomerCode The customer code assigned to your account
         * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options) {
            return __awaiter(this, void 0, void 0, function* () {
                const localVarAxiosArgs = yield localVarAxiosParamCreator.globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options);
                return common_1.createRequestFunction(localVarAxiosArgs, axios_1.default, base_1.BASE_PATH, configuration);
            });
        },
    };
};
exports.GlobalCustomerApiFp = GlobalCustomerApiFp;
/**
 * GlobalCustomerApi - factory interface
 * @export
 */
const GlobalCustomerApiFactory = function (configuration, basePath, axios) {
    const localVarFp = exports.GlobalCustomerApiFp(configuration);
    return {
        /**
         * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
         * @summary Get customer endpoint
         * @param {string} pksCustomerCode The customer code assigned to your account
         * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options) {
            return localVarFp.globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options).then((request) => request(axios, basePath));
        },
    };
};
exports.GlobalCustomerApiFactory = GlobalCustomerApiFactory;
/**
 * GlobalCustomerApi - object-oriented interface
 * @export
 * @class GlobalCustomerApi
 * @extends {BaseAPI}
 */
class GlobalCustomerApi extends base_1.BaseAPI {
    /**
     * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
     * @summary Get customer endpoint
     * @param {string} pksCustomerCode The customer code assigned to your account
     * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof GlobalCustomerApi
     */
    globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options) {
        return exports.GlobalCustomerApiFp(this.configuration).globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options).then((request) => request(this.axios, this.basePath));
    }
}
exports.GlobalCustomerApi = GlobalCustomerApi;
