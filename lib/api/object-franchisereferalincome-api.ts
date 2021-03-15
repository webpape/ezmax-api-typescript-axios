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
import { FranchisereferalincomeCreateObjectV1Request } from '../model';
// @ts-ignore
import { FranchisereferalincomeCreateObjectV1Response } from '../model';
// @ts-ignore
import { RequestSignatureApi, IHeadersData } from './_request-signature-api';

/**
 * ObjectFranchisereferalincomeApi - axios parameter creator
 * @export
 */
export const ObjectFranchisereferalincomeApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Franchisereferalincome
         * @param {Array<FranchisereferalincomeCreateObjectV1Request>} franchisereferalincomeCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        franchisereferalincomeCreateObjectV1: async (franchisereferalincomeCreateObjectV1Request: Array<FranchisereferalincomeCreateObjectV1Request>, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'franchisereferalincomeCreateObjectV1Request' is not null or undefined
            if (franchisereferalincomeCreateObjectV1Request === null || franchisereferalincomeCreateObjectV1Request === undefined) {
                throw new RequiredError('franchisereferalincomeCreateObjectV1Request','Required parameter franchisereferalincomeCreateObjectV1Request was null or undefined when calling franchisereferalincomeCreateObjectV1.');
            }
            const localVarPath = `/1/object/franchisereferalincome`;
            
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
            const nonString = typeof franchisereferalincomeCreateObjectV1Request !== 'string';
            const needsSerialization = nonString && configuration && configuration.isJsonMime
                ? configuration.isJsonMime(localVarRequestOptions.headers['Content-Type'])
                : nonString;
            localVarRequestOptions.data =  needsSerialization
                ? JSON.stringify(franchisereferalincomeCreateObjectV1Request !== undefined ? franchisereferalincomeCreateObjectV1Request : {})
                : (franchisereferalincomeCreateObjectV1Request || "");

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
 * ObjectFranchisereferalincomeApi - functional programming interface
 * @export
 */
export const ObjectFranchisereferalincomeApiFp = function(configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Franchisereferalincome
         * @param {Array<FranchisereferalincomeCreateObjectV1Request>} franchisereferalincomeCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request: Array<FranchisereferalincomeCreateObjectV1Request>, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<FranchisereferalincomeCreateObjectV1Response>> {
            const localVarAxiosArgs = await ObjectFranchisereferalincomeApiAxiosParamCreator(configuration).franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * ObjectFranchisereferalincomeApi - factory interface
 * @export
 */
export const ObjectFranchisereferalincomeApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Franchisereferalincome
         * @param {Array<FranchisereferalincomeCreateObjectV1Request>} franchisereferalincomeCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request: Array<FranchisereferalincomeCreateObjectV1Request>, options?: any): AxiosPromise<FranchisereferalincomeCreateObjectV1Response> {
            return ObjectFranchisereferalincomeApiFp(configuration).franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectFranchisereferalincomeApi - object-oriented interface
 * @export
 * @class ObjectFranchisereferalincomeApi
 * @extends {BaseAPI}
 */
export class ObjectFranchisereferalincomeApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
     * @summary Create a new Franchisereferalincome
     * @param {Array<FranchisereferalincomeCreateObjectV1Request>} franchisereferalincomeCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectFranchisereferalincomeApi
     */
    public franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request: Array<FranchisereferalincomeCreateObjectV1Request>, options?: any) {
        return ObjectFranchisereferalincomeApiFp(this.configuration).franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }
}
