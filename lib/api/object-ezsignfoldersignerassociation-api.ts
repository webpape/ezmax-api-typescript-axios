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
import { EzsignfoldersignerassociationCreateObjectV1Request } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationCreateObjectV1Response } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationDeleteObjectV1Response } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationGetInPersonLoginUrlV1Response } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationGetObjectV1Response } from '../model';
// @ts-ignore
import { RequestSignatureApi, IHeadersData } from './_request-signature-api';

/**
 * ObjectEzsignfoldersignerassociationApi - axios parameter creator
 * @export
 */
export const ObjectEzsignfoldersignerassociationApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationCreateObjectV1: async (ezsignfoldersignerassociationCreateObjectV1Request: Array<EzsignfoldersignerassociationCreateObjectV1Request>, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsignfoldersignerassociationCreateObjectV1Request' is not null or undefined
            if (ezsignfoldersignerassociationCreateObjectV1Request === null || ezsignfoldersignerassociationCreateObjectV1Request === undefined) {
                throw new RequiredError('ezsignfoldersignerassociationCreateObjectV1Request','Required parameter ezsignfoldersignerassociationCreateObjectV1Request was null or undefined when calling ezsignfoldersignerassociationCreateObjectV1.');
            }
            const localVarPath = `/1/object/ezsignfoldersignerassociation`;
            
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

            // Add Signature to Header
            let signatureHeaders: any
            if (configuration && configuration.apiKey !== null) {
                const secret = configuration.getSecret()
                if (secret !== '') {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
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
            const nonString = typeof ezsignfoldersignerassociationCreateObjectV1Request !== 'string';
            const needsSerialization = nonString && configuration && configuration.isJsonMime
                ? configuration.isJsonMime(localVarRequestOptions.headers['Content-Type'])
                : nonString;
            localVarRequestOptions.data =  needsSerialization
                ? JSON.stringify(ezsignfoldersignerassociationCreateObjectV1Request !== undefined ? ezsignfoldersignerassociationCreateObjectV1Request : {})
                : (ezsignfoldersignerassociationCreateObjectV1Request || "");

            

            return {
                url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash,
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationDeleteObjectV1: async (pkiEzsignfoldersignerassociationID: number, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            if (pkiEzsignfoldersignerassociationID === null || pkiEzsignfoldersignerassociationID === undefined) {
                throw new RequiredError('pkiEzsignfoldersignerassociationID','Required parameter pkiEzsignfoldersignerassociationID was null or undefined when calling ezsignfoldersignerassociationDeleteObjectV1.');
            }
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
            
            let basePath = BASE_PATH
            if (configuration && configuration.basePath) basePath = configuration.basePath

            const localVarUrlObj = new URL(localVarPath, basePath);
            
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'DELETE', ...baseOptions, ...options};
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
            if (configuration && configuration.apiKey !== null) {
                const secret = configuration.getSecret()
                if (secret !== '') {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'DELETE' as string,
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
        /**
         * 
         * @summary Retrieve an existing Ezsignfoldersignerassociation\'s children IDs
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetChildrenV1: async (pkiEzsignfoldersignerassociationID: number, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            if (pkiEzsignfoldersignerassociationID === null || pkiEzsignfoldersignerassociationID === undefined) {
                throw new RequiredError('pkiEzsignfoldersignerassociationID','Required parameter pkiEzsignfoldersignerassociationID was null or undefined when calling ezsignfoldersignerassociationGetChildrenV1.');
            }
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}/getChildren`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
            
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
        /**
         * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
         * @summary Retrieve a Login Url to allow In-Person signing
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetInPersonLoginUrlV1: async (pkiEzsignfoldersignerassociationID: number, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            if (pkiEzsignfoldersignerassociationID === null || pkiEzsignfoldersignerassociationID === undefined) {
                throw new RequiredError('pkiEzsignfoldersignerassociationID','Required parameter pkiEzsignfoldersignerassociationID was null or undefined when calling ezsignfoldersignerassociationGetInPersonLoginUrlV1.');
            }
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}/getInPersonLoginUrl`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
            
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
        /**
         * 
         * @summary Retrieve an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetObjectV1: async (pkiEzsignfoldersignerassociationID: number, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            if (pkiEzsignfoldersignerassociationID === null || pkiEzsignfoldersignerassociationID === undefined) {
                throw new RequiredError('pkiEzsignfoldersignerassociationID','Required parameter pkiEzsignfoldersignerassociationID was null or undefined when calling ezsignfoldersignerassociationGetObjectV1.');
            }
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
            
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
 * ObjectEzsignfoldersignerassociationApi - functional programming interface
 * @export
 */
export const ObjectEzsignfoldersignerassociationApiFp = function(configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request: Array<EzsignfoldersignerassociationCreateObjectV1Request>, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfoldersignerassociationCreateObjectV1Response>> {
            const localVarAxiosArgs = await ObjectEzsignfoldersignerassociationApiAxiosParamCreator(configuration).ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * 
         * @summary Delete an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID: number, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfoldersignerassociationDeleteObjectV1Response>> {
            const localVarAxiosArgs = await ObjectEzsignfoldersignerassociationApiAxiosParamCreator(configuration).ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignfoldersignerassociation\'s children IDs
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID: number, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await ObjectEzsignfoldersignerassociationApiAxiosParamCreator(configuration).ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
         * @summary Retrieve a Login Url to allow In-Person signing
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID: number, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfoldersignerassociationGetInPersonLoginUrlV1Response>> {
            const localVarAxiosArgs = await ObjectEzsignfoldersignerassociationApiAxiosParamCreator(configuration).ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID: number, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfoldersignerassociationGetObjectV1Response>> {
            const localVarAxiosArgs = await ObjectEzsignfoldersignerassociationApiAxiosParamCreator(configuration).ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * ObjectEzsignfoldersignerassociationApi - factory interface
 * @export
 */
export const ObjectEzsignfoldersignerassociationApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request: Array<EzsignfoldersignerassociationCreateObjectV1Request>, options?: any): AxiosPromise<EzsignfoldersignerassociationCreateObjectV1Response> {
            return ObjectEzsignfoldersignerassociationApiFp(configuration).ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID: number, options?: any): AxiosPromise<EzsignfoldersignerassociationDeleteObjectV1Response> {
            return ObjectEzsignfoldersignerassociationApiFp(configuration).ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignfoldersignerassociation\'s children IDs
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID: number, options?: any): AxiosPromise<void> {
            return ObjectEzsignfoldersignerassociationApiFp(configuration).ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(axios, basePath));
        },
        /**
         * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
         * @summary Retrieve a Login Url to allow In-Person signing
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID: number, options?: any): AxiosPromise<EzsignfoldersignerassociationGetInPersonLoginUrlV1Response> {
            return ObjectEzsignfoldersignerassociationApiFp(configuration).ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID: number, options?: any): AxiosPromise<EzsignfoldersignerassociationGetObjectV1Response> {
            return ObjectEzsignfoldersignerassociationApiFp(configuration).ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignfoldersignerassociationApi - object-oriented interface
 * @export
 * @class ObjectEzsignfoldersignerassociationApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignfoldersignerassociationApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
     * @summary Create a new Ezsignfoldersignerassociation
     * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    public ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request: Array<EzsignfoldersignerassociationCreateObjectV1Request>, options?: any) {
        return ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsignfoldersignerassociation
     * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    public ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID: number, options?: any) {
        return ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignfoldersignerassociation\'s children IDs
     * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    public ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID: number, options?: any) {
        return ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
     * @summary Retrieve a Login Url to allow In-Person signing
     * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    public ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID: number, options?: any) {
        return ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignfoldersignerassociation
     * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    public ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID: number, options?: any) {
        return ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(this.axios, this.basePath));
    }
}
