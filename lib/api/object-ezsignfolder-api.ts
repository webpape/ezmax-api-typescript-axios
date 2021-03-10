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
import { EzsignfolderCreateObjectV1Request } from '../model';
// @ts-ignore
import { EzsignfolderCreateObjectV1Response } from '../model';
// @ts-ignore
import { EzsignfolderDeleteObjectV1Response } from '../model';
// @ts-ignore
import { EzsignfolderGetObjectV1Response } from '../model';
// @ts-ignore
import { EzsignfolderSendV1Request } from '../model';
// @ts-ignore
import { EzsignfolderSendV1Response } from '../model';
// @ts-ignore
import { RequestSignatureApi, IHeadersData } from './_request-signature-api';

/**
 * ObjectEzsignfolderApi - axios parameter creator
 * @export
 */
export const ObjectEzsignfolderApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfolder
         * @param {Array<EzsignfolderCreateObjectV1Request>} ezsignfolderCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfolderCreateObjectV1: async (ezsignfolderCreateObjectV1Request: Array<EzsignfolderCreateObjectV1Request>, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsignfolderCreateObjectV1Request' is not null or undefined
            if (ezsignfolderCreateObjectV1Request === null || ezsignfolderCreateObjectV1Request === undefined) {
                throw new RequiredError('ezsignfolderCreateObjectV1Request','Required parameter ezsignfolderCreateObjectV1Request was null or undefined when calling ezsignfolderCreateObjectV1.');
            }
            const localVarPath = `/1/object/ezsignfolder`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, 'https://example.com');
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
            if (configuration.apiKey !== null) {
                const secret = configuration.getSecret()
                if (secret !== '') {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
                        url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash as string,
                        body: options.body || '' as string
                    }
                    signatureHeaders = RequestSignatureApi.getHeaders(headers)
                } 
            }

            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers, ...signatureHeaders};
            const nonString = typeof ezsignfolderCreateObjectV1Request !== 'string';
            const needsSerialization = nonString && configuration && configuration.isJsonMime
                ? configuration.isJsonMime(localVarRequestOptions.headers['Content-Type'])
                : nonString;
            localVarRequestOptions.data =  needsSerialization
                ? JSON.stringify(ezsignfolderCreateObjectV1Request !== undefined ? ezsignfolderCreateObjectV1Request : {})
                : (ezsignfolderCreateObjectV1Request || "");

            

            return {
                url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash,
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete an existing Ezsignfolder
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfolderDeleteObjectV1: async (pkiEzsignfolderID: number, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfolderID' is not null or undefined
            if (pkiEzsignfolderID === null || pkiEzsignfolderID === undefined) {
                throw new RequiredError('pkiEzsignfolderID','Required parameter pkiEzsignfolderID was null or undefined when calling ezsignfolderDeleteObjectV1.');
            }
            const localVarPath = `/1/object/ezsignfolder/{pkiEzsignfolderID}`
                .replace(`{${"pkiEzsignfolderID"}}`, encodeURIComponent(String(pkiEzsignfolderID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, 'https://example.com');
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
            if (configuration.apiKey !== null) {
                const secret = configuration.getSecret()
                if (secret !== '') {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'DELETE' as string,
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
        /**
         * 
         * @summary Retrieve an existing Ezsignfolder\'s children IDs
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfolderGetChildrenV1: async (pkiEzsignfolderID: number, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfolderID' is not null or undefined
            if (pkiEzsignfolderID === null || pkiEzsignfolderID === undefined) {
                throw new RequiredError('pkiEzsignfolderID','Required parameter pkiEzsignfolderID was null or undefined when calling ezsignfolderGetChildrenV1.');
            }
            const localVarPath = `/1/object/ezsignfolder/{pkiEzsignfolderID}/getChildren`
                .replace(`{${"pkiEzsignfolderID"}}`, encodeURIComponent(String(pkiEzsignfolderID)));
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
        /**
         * 
         * @summary Retrieve an existing Ezsignfolder
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfolderGetObjectV1: async (pkiEzsignfolderID: number, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfolderID' is not null or undefined
            if (pkiEzsignfolderID === null || pkiEzsignfolderID === undefined) {
                throw new RequiredError('pkiEzsignfolderID','Required parameter pkiEzsignfolderID was null or undefined when calling ezsignfolderGetObjectV1.');
            }
            const localVarPath = `/1/object/ezsignfolder/{pkiEzsignfolderID}`
                .replace(`{${"pkiEzsignfolderID"}}`, encodeURIComponent(String(pkiEzsignfolderID)));
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
        /**
         * 
         * @summary Send the Ezsignfolder to the signatories for signature
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {EzsignfolderSendV1Request} ezsignfolderSendV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfolderSendV1: async (pkiEzsignfolderID: number, ezsignfolderSendV1Request: EzsignfolderSendV1Request, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfolderID' is not null or undefined
            if (pkiEzsignfolderID === null || pkiEzsignfolderID === undefined) {
                throw new RequiredError('pkiEzsignfolderID','Required parameter pkiEzsignfolderID was null or undefined when calling ezsignfolderSendV1.');
            }
            // verify required parameter 'ezsignfolderSendV1Request' is not null or undefined
            if (ezsignfolderSendV1Request === null || ezsignfolderSendV1Request === undefined) {
                throw new RequiredError('ezsignfolderSendV1Request','Required parameter ezsignfolderSendV1Request was null or undefined when calling ezsignfolderSendV1.');
            }
            const localVarPath = `/1/object/ezsignfolder/{pkiEzsignfolderID}/send`
                .replace(`{${"pkiEzsignfolderID"}}`, encodeURIComponent(String(pkiEzsignfolderID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, 'https://example.com');
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
            if (configuration.apiKey !== null) {
                const secret = configuration.getSecret()
                if (secret !== '') {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
                        url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash as string,
                        body: options.body || '' as string
                    }
                    signatureHeaders = RequestSignatureApi.getHeaders(headers)
                } 
            }

            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers, ...signatureHeaders};
            const nonString = typeof ezsignfolderSendV1Request !== 'string';
            const needsSerialization = nonString && configuration && configuration.isJsonMime
                ? configuration.isJsonMime(localVarRequestOptions.headers['Content-Type'])
                : nonString;
            localVarRequestOptions.data =  needsSerialization
                ? JSON.stringify(ezsignfolderSendV1Request !== undefined ? ezsignfolderSendV1Request : {})
                : (ezsignfolderSendV1Request || "");

            

            return {
                url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash,
                options: localVarRequestOptions,
            };
        },
    }
};

/**
 * ObjectEzsignfolderApi - functional programming interface
 * @export
 */
export const ObjectEzsignfolderApiFp = function(configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfolder
         * @param {Array<EzsignfolderCreateObjectV1Request>} ezsignfolderCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfolderCreateObjectV1(ezsignfolderCreateObjectV1Request: Array<EzsignfolderCreateObjectV1Request>, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfolderCreateObjectV1Response>> {
            const localVarAxiosArgs = await ObjectEzsignfolderApiAxiosParamCreator(configuration).ezsignfolderCreateObjectV1(ezsignfolderCreateObjectV1Request, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * 
         * @summary Delete an existing Ezsignfolder
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfolderDeleteObjectV1(pkiEzsignfolderID: number, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfolderDeleteObjectV1Response>> {
            const localVarAxiosArgs = await ObjectEzsignfolderApiAxiosParamCreator(configuration).ezsignfolderDeleteObjectV1(pkiEzsignfolderID, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignfolder\'s children IDs
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfolderGetChildrenV1(pkiEzsignfolderID: number, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await ObjectEzsignfolderApiAxiosParamCreator(configuration).ezsignfolderGetChildrenV1(pkiEzsignfolderID, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignfolder
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfolderGetObjectV1(pkiEzsignfolderID: number, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfolderGetObjectV1Response>> {
            const localVarAxiosArgs = await ObjectEzsignfolderApiAxiosParamCreator(configuration).ezsignfolderGetObjectV1(pkiEzsignfolderID, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * 
         * @summary Send the Ezsignfolder to the signatories for signature
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {EzsignfolderSendV1Request} ezsignfolderSendV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfolderSendV1(pkiEzsignfolderID: number, ezsignfolderSendV1Request: EzsignfolderSendV1Request, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfolderSendV1Response>> {
            const localVarAxiosArgs = await ObjectEzsignfolderApiAxiosParamCreator(configuration).ezsignfolderSendV1(pkiEzsignfolderID, ezsignfolderSendV1Request, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * ObjectEzsignfolderApi - factory interface
 * @export
 */
export const ObjectEzsignfolderApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfolder
         * @param {Array<EzsignfolderCreateObjectV1Request>} ezsignfolderCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfolderCreateObjectV1(ezsignfolderCreateObjectV1Request: Array<EzsignfolderCreateObjectV1Request>, options?: any): AxiosPromise<EzsignfolderCreateObjectV1Response> {
            return ObjectEzsignfolderApiFp(configuration).ezsignfolderCreateObjectV1(ezsignfolderCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsignfolder
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfolderDeleteObjectV1(pkiEzsignfolderID: number, options?: any): AxiosPromise<EzsignfolderDeleteObjectV1Response> {
            return ObjectEzsignfolderApiFp(configuration).ezsignfolderDeleteObjectV1(pkiEzsignfolderID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignfolder\'s children IDs
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfolderGetChildrenV1(pkiEzsignfolderID: number, options?: any): AxiosPromise<void> {
            return ObjectEzsignfolderApiFp(configuration).ezsignfolderGetChildrenV1(pkiEzsignfolderID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignfolder
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfolderGetObjectV1(pkiEzsignfolderID: number, options?: any): AxiosPromise<EzsignfolderGetObjectV1Response> {
            return ObjectEzsignfolderApiFp(configuration).ezsignfolderGetObjectV1(pkiEzsignfolderID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Send the Ezsignfolder to the signatories for signature
         * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
         * @param {EzsignfolderSendV1Request} ezsignfolderSendV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfolderSendV1(pkiEzsignfolderID: number, ezsignfolderSendV1Request: EzsignfolderSendV1Request, options?: any): AxiosPromise<EzsignfolderSendV1Response> {
            return ObjectEzsignfolderApiFp(configuration).ezsignfolderSendV1(pkiEzsignfolderID, ezsignfolderSendV1Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignfolderApi - object-oriented interface
 * @export
 * @class ObjectEzsignfolderApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignfolderApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
     * @summary Create a new Ezsignfolder
     * @param {Array<EzsignfolderCreateObjectV1Request>} ezsignfolderCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfolderApi
     */
    public ezsignfolderCreateObjectV1(ezsignfolderCreateObjectV1Request: Array<EzsignfolderCreateObjectV1Request>, options?: any) {
        return ObjectEzsignfolderApiFp(this.configuration).ezsignfolderCreateObjectV1(ezsignfolderCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsignfolder
     * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfolderApi
     */
    public ezsignfolderDeleteObjectV1(pkiEzsignfolderID: number, options?: any) {
        return ObjectEzsignfolderApiFp(this.configuration).ezsignfolderDeleteObjectV1(pkiEzsignfolderID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignfolder\'s children IDs
     * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfolderApi
     */
    public ezsignfolderGetChildrenV1(pkiEzsignfolderID: number, options?: any) {
        return ObjectEzsignfolderApiFp(this.configuration).ezsignfolderGetChildrenV1(pkiEzsignfolderID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignfolder
     * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfolderApi
     */
    public ezsignfolderGetObjectV1(pkiEzsignfolderID: number, options?: any) {
        return ObjectEzsignfolderApiFp(this.configuration).ezsignfolderGetObjectV1(pkiEzsignfolderID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Send the Ezsignfolder to the signatories for signature
     * @param {number} pkiEzsignfolderID The unique ID of the Ezsignfolder
     * @param {EzsignfolderSendV1Request} ezsignfolderSendV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfolderApi
     */
    public ezsignfolderSendV1(pkiEzsignfolderID: number, ezsignfolderSendV1Request: EzsignfolderSendV1Request, options?: any) {
        return ObjectEzsignfolderApiFp(this.configuration).ezsignfolderSendV1(pkiEzsignfolderID, ezsignfolderSendV1Request, options).then((request) => request(this.axios, this.basePath));
    }
}
