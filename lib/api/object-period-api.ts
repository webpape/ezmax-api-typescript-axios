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
import { CommonGetAutocompleteV1Response } from '../model';
/**
 * ObjectPeriodApi - axios parameter creator
 * @export
 */
export const ObjectPeriodApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Periods to be used in a dropdown or autocomplete control.
         * @summary Retrieve Periods and IDs
         * @param {'ActiveNormal' | 'ActiveNormalAndEndOfYear' | 'AllNormal' | 'AllNormalAndEndOfYear'} sSelector The types of Periods to return
         * @param {string} [sQuery] Allow to filter on the option value
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        periodGetAutocompleteV1: async (sSelector: 'ActiveNormal' | 'ActiveNormalAndEndOfYear' | 'AllNormal' | 'AllNormalAndEndOfYear', sQuery?: string, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            if (sSelector === null || sSelector === undefined) {
                throw new RequiredError('sSelector','Required parameter sSelector was null or undefined when calling periodGetAutocompleteV1.');
            }
            const localVarPath = `/1/object/period/getAutocomplete/{sSelector}`
                .replace(`{${"sSelector"}}`, encodeURIComponent(String(sSelector)));
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
    
            if (sQuery !== undefined) {
                localVarQueryParameter['sQuery'] = sQuery;
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
 * ObjectPeriodApi - functional programming interface
 * @export
 */
export const ObjectPeriodApiFp = function(configuration?: Configuration) {
    return {
        /**
         * Get the list of Periods to be used in a dropdown or autocomplete control.
         * @summary Retrieve Periods and IDs
         * @param {'ActiveNormal' | 'ActiveNormalAndEndOfYear' | 'AllNormal' | 'AllNormalAndEndOfYear'} sSelector The types of Periods to return
         * @param {string} [sQuery] Allow to filter on the option value
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async periodGetAutocompleteV1(sSelector: 'ActiveNormal' | 'ActiveNormalAndEndOfYear' | 'AllNormal' | 'AllNormalAndEndOfYear', sQuery?: string, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommonGetAutocompleteV1Response>> {
            const localVarAxiosArgs = await ObjectPeriodApiAxiosParamCreator(configuration).periodGetAutocompleteV1(sSelector, sQuery, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * ObjectPeriodApi - factory interface
 * @export
 */
export const ObjectPeriodApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    return {
        /**
         * Get the list of Periods to be used in a dropdown or autocomplete control.
         * @summary Retrieve Periods and IDs
         * @param {'ActiveNormal' | 'ActiveNormalAndEndOfYear' | 'AllNormal' | 'AllNormalAndEndOfYear'} sSelector The types of Periods to return
         * @param {string} [sQuery] Allow to filter on the option value
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        periodGetAutocompleteV1(sSelector: 'ActiveNormal' | 'ActiveNormalAndEndOfYear' | 'AllNormal' | 'AllNormalAndEndOfYear', sQuery?: string, options?: any): AxiosPromise<CommonGetAutocompleteV1Response> {
            return ObjectPeriodApiFp(configuration).periodGetAutocompleteV1(sSelector, sQuery, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectPeriodApi - object-oriented interface
 * @export
 * @class ObjectPeriodApi
 * @extends {BaseAPI}
 */
export class ObjectPeriodApi extends BaseAPI {
    /**
     * Get the list of Periods to be used in a dropdown or autocomplete control.
     * @summary Retrieve Periods and IDs
     * @param {'ActiveNormal' | 'ActiveNormalAndEndOfYear' | 'AllNormal' | 'AllNormalAndEndOfYear'} sSelector The types of Periods to return
     * @param {string} [sQuery] Allow to filter on the option value
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectPeriodApi
     */
    public periodGetAutocompleteV1(sSelector: 'ActiveNormal' | 'ActiveNormalAndEndOfYear' | 'AllNormal' | 'AllNormalAndEndOfYear', sQuery?: string, options?: any) {
        return ObjectPeriodApiFp(this.configuration).periodGetAutocompleteV1(sSelector, sQuery, options).then((request) => request(this.axios, this.basePath));
    }
}
