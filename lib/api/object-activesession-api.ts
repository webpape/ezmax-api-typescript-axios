/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.  # Authentication  <!-- ReDoc-Inject: <security-definitions> -->
 *
 * The version of the OpenAPI document: 1.0.31
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
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { ActivesessionGetCurrentV1Response } from '../model';
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
            const localVarUrlObj = new URL(localVarPath, 'https://example.com');
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'GET', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            if (configuration && configuration.apiKey) {
                const localVarApiKeyValue = typeof configuration.apiKey === 'function'
                    ? await configuration.apiKey("Authorization")
                    : await configuration.apiKey;
                localVarHeaderParameter["Authorization"] = localVarApiKeyValue;
            }
    

    
            const queryParameters = new URLSearchParams(localVarUrlObj.search);
            for (const key in localVarQueryParameter) {
                queryParameters.set(key, localVarQueryParameter[key]);
            }
            for (const key in options.query) {
                queryParameters.set(key, options.query[key]);
            }
            localVarUrlObj.search = (new URLSearchParams(queryParameters)).toString();
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};

            // Add Signature to Header
            let signatureHeaders: any
            if (configuration.apiKey !== null) {
                const secret = configuration.getSecret()
                if (secret !== '') {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'GET' as string,
                        url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash as string,
                        body: options.body || '' as string
                    }
                    signatureHeaders = RequestSignatureApi.getHeaders(headers)
                } 
            }

            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers, ...signatureHeaders};

            

            return {
                url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash,
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
    return {
        /**
         * Retrieve the details about the current activesession
         * @summary Get Current Activesession
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async activesessionGetCurrentV1(options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ActivesessionGetCurrentV1Response>> {
            const localVarAxiosArgs = await ObjectActivesessionApiAxiosParamCreator(configuration).activesessionGetCurrentV1(options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * ObjectActivesessionApi - factory interface
 * @export
 */
export const ObjectActivesessionApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    return {
        /**
         * Retrieve the details about the current activesession
         * @summary Get Current Activesession
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        activesessionGetCurrentV1(options?: any): AxiosPromise<ActivesessionGetCurrentV1Response> {
            return ObjectActivesessionApiFp(configuration).activesessionGetCurrentV1(options).then((request) => request(axios, basePath));
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
