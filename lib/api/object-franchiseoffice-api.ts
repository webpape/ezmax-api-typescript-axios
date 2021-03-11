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
// @ts-ignore
import { RequestSignatureApi, IHeadersData } from './_request-signature-api';

/**
 * ObjectFranchiseofficeApi - axios parameter creator
 * @export
 */
export const ObjectFranchiseofficeApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Franchiseoffices to be used in a dropdown or autocomplete control.
         * @summary Retrieve Franchiseoffices and IDs
         * @param {'Active' | 'All'} sSelector The type of Franchiseoffices to return
         * @param {string} [sQuery] Allow to filter on the option value
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        franchiseofficeGetAutocompleteV1: async (sSelector: 'Active' | 'All', sQuery?: string, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            if (sSelector === null || sSelector === undefined) {
                throw new RequiredError('sSelector','Required parameter sSelector was null or undefined when calling franchiseofficeGetAutocompleteV1.');
            }
            const localVarPath = `/1/object/franchiseoffice/getAutocomplete/{sSelector}`
                .replace(`{${"sSelector"}}`, encodeURIComponent(String(sSelector)));
            
            let basePath = BASE_PATH
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
            if (configuration && configuration.apiKey !== null) {
                const secret = configuration.getSecret()
                if (secret !== '') {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'GET' as string,
                        url: localVarUrlObj.href as string,
                        body: options.headers.body || '' as string
                    }
                    signatureHeaders = RequestSignatureApi.getHeaders(headers)
                } 
            }

            if (options.headers.body) { 
                options.headers.Body = options.headers.body
                delete options.headers.body
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
 * ObjectFranchiseofficeApi - functional programming interface
 * @export
 */
export const ObjectFranchiseofficeApiFp = function(configuration?: Configuration) {
    return {
        /**
         * Get the list of Franchiseoffices to be used in a dropdown or autocomplete control.
         * @summary Retrieve Franchiseoffices and IDs
         * @param {'Active' | 'All'} sSelector The type of Franchiseoffices to return
         * @param {string} [sQuery] Allow to filter on the option value
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async franchiseofficeGetAutocompleteV1(sSelector: 'Active' | 'All', sQuery?: string, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommonGetAutocompleteV1Response>> {
            const localVarAxiosArgs = await ObjectFranchiseofficeApiAxiosParamCreator(configuration).franchiseofficeGetAutocompleteV1(sSelector, sQuery, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * ObjectFranchiseofficeApi - factory interface
 * @export
 */
export const ObjectFranchiseofficeApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    return {
        /**
         * Get the list of Franchiseoffices to be used in a dropdown or autocomplete control.
         * @summary Retrieve Franchiseoffices and IDs
         * @param {'Active' | 'All'} sSelector The type of Franchiseoffices to return
         * @param {string} [sQuery] Allow to filter on the option value
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        franchiseofficeGetAutocompleteV1(sSelector: 'Active' | 'All', sQuery?: string, options?: any): AxiosPromise<CommonGetAutocompleteV1Response> {
            return ObjectFranchiseofficeApiFp(configuration).franchiseofficeGetAutocompleteV1(sSelector, sQuery, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectFranchiseofficeApi - object-oriented interface
 * @export
 * @class ObjectFranchiseofficeApi
 * @extends {BaseAPI}
 */
export class ObjectFranchiseofficeApi extends BaseAPI {
    /**
     * Get the list of Franchiseoffices to be used in a dropdown or autocomplete control.
     * @summary Retrieve Franchiseoffices and IDs
     * @param {'Active' | 'All'} sSelector The type of Franchiseoffices to return
     * @param {string} [sQuery] Allow to filter on the option value
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectFranchiseofficeApi
     */
    public franchiseofficeGetAutocompleteV1(sSelector: 'Active' | 'All', sQuery?: string, options?: any) {
        return ObjectFranchiseofficeApiFp(this.configuration).franchiseofficeGetAutocompleteV1(sSelector, sQuery, options).then((request) => request(this.axios, this.basePath));
    }
}
