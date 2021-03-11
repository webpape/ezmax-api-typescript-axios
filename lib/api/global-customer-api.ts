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
import { CommonResponseError } from '../model';
// @ts-ignore
import { GlobalCustomerGetEndpointV1Response } from '../model';
// @ts-ignore
import { RequestSignatureApi, IHeadersData } from './_request-signature-api';

/**
 * GlobalCustomerApi - axios parameter creator
 * @export
 */
export const GlobalCustomerApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
         * @summary Get customer endpoint
         * @param {string} pksCustomerCode The customer code assigned to your account
         * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        globalCustomerGetEndpointV1: async (pksCustomerCode: string, sInfrastructureproductCode?: 'appcluster01' | 'ezsignuser', options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pksCustomerCode' is not null or undefined
            if (pksCustomerCode === null || pksCustomerCode === undefined) {
                throw new RequiredError('pksCustomerCode','Required parameter pksCustomerCode was null or undefined when calling globalCustomerGetEndpointV1.');
            }
            const localVarPath = `/1/customer/{pksCustomerCode}/endpoint`
                .replace(`{${"pksCustomerCode"}}`, encodeURIComponent(String(pksCustomerCode)));
            
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
    
            if (sInfrastructureproductCode !== undefined) {
                localVarQueryParameter['sInfrastructureproductCode'] = sInfrastructureproductCode;
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
            let headerBody = ''
            if (options.headers) {
                if (options.headers.body) { 
                    headerBody = options.headers.body
                    options.headers.Body = options.headers.body
                    delete options.headers.body
                } else if (options.headers.Body) {
                    // do nothing
                } else {
                    options.headers.Body = ''
                }
            } else {
                options.headers = {}
                // options.headers.Body = ''
            }

            let signatureHeaders: any = {}
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'GET' as string,
                        url: localVarUrlObj.href as string,
                        body: headerBody as string
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
 * GlobalCustomerApi - functional programming interface
 * @export
 */
export const GlobalCustomerApiFp = function(configuration?: Configuration) {
    return {
        /**
         * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
         * @summary Get customer endpoint
         * @param {string} pksCustomerCode The customer code assigned to your account
         * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async globalCustomerGetEndpointV1(pksCustomerCode: string, sInfrastructureproductCode?: 'appcluster01' | 'ezsignuser', options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GlobalCustomerGetEndpointV1Response>> {
            const localVarAxiosArgs = await GlobalCustomerApiAxiosParamCreator(configuration).globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * GlobalCustomerApi - factory interface
 * @export
 */
export const GlobalCustomerApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    return {
        /**
         * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
         * @summary Get customer endpoint
         * @param {string} pksCustomerCode The customer code assigned to your account
         * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        globalCustomerGetEndpointV1(pksCustomerCode: string, sInfrastructureproductCode?: 'appcluster01' | 'ezsignuser', options?: any): AxiosPromise<GlobalCustomerGetEndpointV1Response> {
            return GlobalCustomerApiFp(configuration).globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * GlobalCustomerApi - object-oriented interface
 * @export
 * @class GlobalCustomerApi
 * @extends {BaseAPI}
 */
export class GlobalCustomerApi extends BaseAPI {
    /**
     * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
     * @summary Get customer endpoint
     * @param {string} pksCustomerCode The customer code assigned to your account
     * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof GlobalCustomerApi
     */
    public globalCustomerGetEndpointV1(pksCustomerCode: string, sInfrastructureproductCode?: 'appcluster01' | 'ezsignuser', options?: any) {
        return GlobalCustomerApiFp(this.configuration).globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options).then((request) => request(this.axios, this.basePath));
    }
}
