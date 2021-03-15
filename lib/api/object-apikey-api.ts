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
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { ApikeyCreateObjectV1Request } from '../model';
// @ts-ignore
import { ApikeyCreateObjectV1Response } from '../model';
// @ts-ignore
import { RequestSignatureApi, IHeadersData } from './_request-signature-api';

/**
 * ObjectApikeyApi - axios parameter creator
 * @export
 */
export const ObjectApikeyApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Apikey
         * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyCreateObjectV1: async (apikeyCreateObjectV1Request: Array<ApikeyCreateObjectV1Request>, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'apikeyCreateObjectV1Request' is not null or undefined
            if (apikeyCreateObjectV1Request === null || apikeyCreateObjectV1Request === undefined) {
                throw new RequiredError('apikeyCreateObjectV1Request','Required parameter apikeyCreateObjectV1Request was null or undefined when calling apikeyCreateObjectV1.');
            }
            const localVarPath = `/1/object/apikey`;
            
            let basePath = BASE_PATH
            if (configuration && configuration.basePath) basePath = configuration.basePath
            
            const localVarUrlObj = new URL(localVarPath, basePath);
            
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'POST', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            if (configuration && configuration.apiKey) {
                const localVarApiKeyValue = typeof configuration.apiKey === 'function'
                    ? await configuration.apiKey("Authorization")
                    : await configuration.apiKey;
                localVarHeaderParameter["Authorization"] = localVarApiKeyValue;
            }
    

    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            const queryParameters = new URLSearchParams(localVarUrlObj.search);
            for (const key in localVarQueryParameter) {
                queryParameters.set(key, localVarQueryParameter[key]);
            }
            for (const key in options.query) {
                queryParameters.set(key, options.query[key]);
            }
            localVarUrlObj.search = (new URLSearchParams(queryParameters)).toString();
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};

            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            const nonString = typeof apikeyCreateObjectV1Request !== 'string';
            const needsSerialization = nonString && configuration && configuration.isJsonMime
                ? configuration.isJsonMime(localVarRequestOptions.headers['Content-Type'])
                : nonString;
            localVarRequestOptions.data =  needsSerialization
                ? JSON.stringify(apikeyCreateObjectV1Request !== undefined ? apikeyCreateObjectV1Request : {})
                : (apikeyCreateObjectV1Request || "");

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
                        url: basePath + localVarPath as string,
                        body: localVarRequestOptions.data as string
                    }
                    const signatureHeaders = RequestSignatureApi.getHeaders(headers)
                    localVarRequestOptions.headers = { ...localVarRequestOptions.headers, ...signatureHeaders }
                } 
            }

            return {
                url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash,
                options: localVarRequestOptions,
            };
        },
    }
};

/**
 * ObjectApikeyApi - functional programming interface
 * @export
 */
export const ObjectApikeyApiFp = function(configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Apikey
         * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async apikeyCreateObjectV1(apikeyCreateObjectV1Request: Array<ApikeyCreateObjectV1Request>, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ApikeyCreateObjectV1Response>> {
            const localVarAxiosArgs = await ObjectApikeyApiAxiosParamCreator(configuration).apikeyCreateObjectV1(apikeyCreateObjectV1Request, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * ObjectApikeyApi - factory interface
 * @export
 */
export const ObjectApikeyApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Apikey
         * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyCreateObjectV1(apikeyCreateObjectV1Request: Array<ApikeyCreateObjectV1Request>, options?: any): AxiosPromise<ApikeyCreateObjectV1Response> {
            return ObjectApikeyApiFp(configuration).apikeyCreateObjectV1(apikeyCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectApikeyApi - object-oriented interface
 * @export
 * @class ObjectApikeyApi
 * @extends {BaseAPI}
 */
export class ObjectApikeyApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
     * @summary Create a new Apikey
     * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectApikeyApi
     */
    public apikeyCreateObjectV1(apikeyCreateObjectV1Request: Array<ApikeyCreateObjectV1Request>, options?: any) {
        return ObjectApikeyApiFp(this.configuration).apikeyCreateObjectV1(apikeyCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }
}
