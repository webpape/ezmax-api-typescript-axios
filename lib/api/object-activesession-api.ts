/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.  # Authentication  <!-- ReDoc-Inject: <security-definitions> -->
 *
 * The version of the OpenAPI document: 1.0.32
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import globalAxios, { AxiosPromise, AxiosInstance } from 'axios';
import { Configuration } from '../configuration';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { ActivesessionGetCurrentV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectActivesessionApi - axios parameter creator
 * @export
 */
export const ObjectActivesessionApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Retrieve the details about the current activesession
         * @summary Get Current Activesession
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        activesessionGetCurrentV1: async (options: any = {}): Promise<RequestArgs> => {
            const localVarPath = `/1/object/activesession/getCurrent`;
            
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'GET', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            setSearchParams(localVarUrlObj, localVarQueryParameter, options.query);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'GET' as string,
                        url: basePath + localVarPath as string,
                        body: localVarRequestOptions.data as string
                    }
                    const signatureHeaders = RequestSignature.getHeaders(headers)
                    localVarRequestOptions.headers = { ...localVarRequestOptions.headers, ...signatureHeaders }
                } 
            }

            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
    }
};

/**
 * ObjectActivesessionApi - functional programming interface
 * @export
 */
export const ObjectActivesessionApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectActivesessionApiAxiosParamCreator(configuration)
    return {
        /**
         * Retrieve the details about the current activesession
         * @summary Get Current Activesession
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async activesessionGetCurrentV1(options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ActivesessionGetCurrentV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.activesessionGetCurrentV1(options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectActivesessionApi - factory interface
 * @export
 */
export const ObjectActivesessionApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectActivesessionApiFp(configuration)
    return {
        /**
         * Retrieve the details about the current activesession
         * @summary Get Current Activesession
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        activesessionGetCurrentV1(options?: any): AxiosPromise<ActivesessionGetCurrentV1Response> {
            return localVarFp.activesessionGetCurrentV1(options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectActivesessionApi - object-oriented interface
 * @export
 * @class ObjectActivesessionApi
 * @extends {BaseAPI}
 */
export class ObjectActivesessionApi extends BaseAPI {
    /**
     * Retrieve the details about the current activesession
     * @summary Get Current Activesession
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectActivesessionApi
     */
    public activesessionGetCurrentV1(options?: any) {
        return ObjectActivesessionApiFp(this.configuration).activesessionGetCurrentV1(options).then((request) => request(this.axios, this.basePath));
    }
}
