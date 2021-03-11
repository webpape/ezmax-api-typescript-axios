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
import { SsprResetPasswordRequestV1Request } from '../model';
// @ts-ignore
import { SsprResetPasswordV1Request } from '../model';
// @ts-ignore
import { SsprSendUsernamesV1Request } from '../model';
// @ts-ignore
import { SsprUnlockAccountRequestV1Request } from '../model';
// @ts-ignore
import { SsprUnlockAccountV1Request } from '../model';
// @ts-ignore
import { RequestSignatureApi, IHeadersData } from './_request-signature-api';

/**
 * ModuleSsprApi - axios parameter creator
 * @export
 */
export const ModuleSsprApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * This endpoint sends an email with a link to reset the user\'s password.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Reset Password Request
         * @param {SsprResetPasswordRequestV1Request} ssprResetPasswordRequestV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ssprResetPasswordRequestV1: async (ssprResetPasswordRequestV1Request: SsprResetPasswordRequestV1Request, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'ssprResetPasswordRequestV1Request' is not null or undefined
            if (ssprResetPasswordRequestV1Request === null || ssprResetPasswordRequestV1Request === undefined) {
                throw new RequiredError('ssprResetPasswordRequestV1Request','Required parameter ssprResetPasswordRequestV1Request was null or undefined when calling ssprResetPasswordRequestV1.');
            }
            const localVarPath = `/1/module/sspr/resetPasswordRequest/`;
            
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
                        body: options.body || '' as string
                    }
                    signatureHeaders = RequestSignatureApi.getHeaders(headers)
                } 
            }

            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers, ...signatureHeaders};
            const nonString = typeof ssprResetPasswordRequestV1Request !== 'string';
            const needsSerialization = nonString && configuration && configuration.isJsonMime
                ? configuration.isJsonMime(localVarRequestOptions.headers['Content-Type'])
                : nonString;
            localVarRequestOptions.data =  needsSerialization
                ? JSON.stringify(ssprResetPasswordRequestV1Request !== undefined ? ssprResetPasswordRequestV1Request : {})
                : (ssprResetPasswordRequestV1Request || "");

            

            return {
                url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash,
                options: localVarRequestOptions,
            };
        },
        /**
         * This endpoint resets the user\'s password.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Reset Password
         * @param {SsprResetPasswordV1Request} ssprResetPasswordV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ssprResetPasswordV1: async (ssprResetPasswordV1Request: SsprResetPasswordV1Request, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'ssprResetPasswordV1Request' is not null or undefined
            if (ssprResetPasswordV1Request === null || ssprResetPasswordV1Request === undefined) {
                throw new RequiredError('ssprResetPasswordV1Request','Required parameter ssprResetPasswordV1Request was null or undefined when calling ssprResetPasswordV1.');
            }
            const localVarPath = `/1/module/sspr/resetPassword`;
            
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
                        body: options.body || '' as string
                    }
                    signatureHeaders = RequestSignatureApi.getHeaders(headers)
                } 
            }

            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers, ...signatureHeaders};
            const nonString = typeof ssprResetPasswordV1Request !== 'string';
            const needsSerialization = nonString && configuration && configuration.isJsonMime
                ? configuration.isJsonMime(localVarRequestOptions.headers['Content-Type'])
                : nonString;
            localVarRequestOptions.data =  needsSerialization
                ? JSON.stringify(ssprResetPasswordV1Request !== undefined ? ssprResetPasswordV1Request : {})
                : (ssprResetPasswordV1Request || "");

            

            return {
                url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash,
                options: localVarRequestOptions,
            };
        },
        /**
         * This endpoint returns an email with the username(s) matching the email address provided in case of forgotten username
         * @summary Send username(s)
         * @param {SsprSendUsernamesV1Request} ssprSendUsernamesV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ssprSendUsernamesV1: async (ssprSendUsernamesV1Request: SsprSendUsernamesV1Request, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'ssprSendUsernamesV1Request' is not null or undefined
            if (ssprSendUsernamesV1Request === null || ssprSendUsernamesV1Request === undefined) {
                throw new RequiredError('ssprSendUsernamesV1Request','Required parameter ssprSendUsernamesV1Request was null or undefined when calling ssprSendUsernamesV1.');
            }
            const localVarPath = `/1/module/sspr/sendUsernames`;
            
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
                        body: options.body || '' as string
                    }
                    signatureHeaders = RequestSignatureApi.getHeaders(headers)
                } 
            }

            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers, ...signatureHeaders};
            const nonString = typeof ssprSendUsernamesV1Request !== 'string';
            const needsSerialization = nonString && configuration && configuration.isJsonMime
                ? configuration.isJsonMime(localVarRequestOptions.headers['Content-Type'])
                : nonString;
            localVarRequestOptions.data =  needsSerialization
                ? JSON.stringify(ssprSendUsernamesV1Request !== undefined ? ssprSendUsernamesV1Request : {})
                : (ssprSendUsernamesV1Request || "");

            

            return {
                url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash,
                options: localVarRequestOptions,
            };
        },
        /**
         * This endpoint sends an email with a link to unlock the user account.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Unlock Account Request
         * @param {SsprUnlockAccountRequestV1Request} ssprUnlockAccountRequestV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ssprUnlockAccountRequestV1: async (ssprUnlockAccountRequestV1Request: SsprUnlockAccountRequestV1Request, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'ssprUnlockAccountRequestV1Request' is not null or undefined
            if (ssprUnlockAccountRequestV1Request === null || ssprUnlockAccountRequestV1Request === undefined) {
                throw new RequiredError('ssprUnlockAccountRequestV1Request','Required parameter ssprUnlockAccountRequestV1Request was null or undefined when calling ssprUnlockAccountRequestV1.');
            }
            const localVarPath = `/1/module/sspr/unlockAccountRequest`;
            
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
                        body: options.body || '' as string
                    }
                    signatureHeaders = RequestSignatureApi.getHeaders(headers)
                } 
            }

            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers, ...signatureHeaders};
            const nonString = typeof ssprUnlockAccountRequestV1Request !== 'string';
            const needsSerialization = nonString && configuration && configuration.isJsonMime
                ? configuration.isJsonMime(localVarRequestOptions.headers['Content-Type'])
                : nonString;
            localVarRequestOptions.data =  needsSerialization
                ? JSON.stringify(ssprUnlockAccountRequestV1Request !== undefined ? ssprUnlockAccountRequestV1Request : {})
                : (ssprUnlockAccountRequestV1Request || "");

            

            return {
                url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash,
                options: localVarRequestOptions,
            };
        },
        /**
         * This endpoint unlocks the user account.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Unlock Account
         * @param {SsprUnlockAccountV1Request} ssprUnlockAccountV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ssprUnlockAccountV1: async (ssprUnlockAccountV1Request: SsprUnlockAccountV1Request, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'ssprUnlockAccountV1Request' is not null or undefined
            if (ssprUnlockAccountV1Request === null || ssprUnlockAccountV1Request === undefined) {
                throw new RequiredError('ssprUnlockAccountV1Request','Required parameter ssprUnlockAccountV1Request was null or undefined when calling ssprUnlockAccountV1.');
            }
            const localVarPath = `/1/module/sspr/unlockAccount`;
            
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
                        body: options.body || '' as string
                    }
                    signatureHeaders = RequestSignatureApi.getHeaders(headers)
                } 
            }

            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers, ...signatureHeaders};
            const nonString = typeof ssprUnlockAccountV1Request !== 'string';
            const needsSerialization = nonString && configuration && configuration.isJsonMime
                ? configuration.isJsonMime(localVarRequestOptions.headers['Content-Type'])
                : nonString;
            localVarRequestOptions.data =  needsSerialization
                ? JSON.stringify(ssprUnlockAccountV1Request !== undefined ? ssprUnlockAccountV1Request : {})
                : (ssprUnlockAccountV1Request || "");

            

            return {
                url: localVarUrlObj.pathname + localVarUrlObj.search + localVarUrlObj.hash,
                options: localVarRequestOptions,
            };
        },
    }
};

/**
 * ModuleSsprApi - functional programming interface
 * @export
 */
export const ModuleSsprApiFp = function(configuration?: Configuration) {
    return {
        /**
         * This endpoint sends an email with a link to reset the user\'s password.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Reset Password Request
         * @param {SsprResetPasswordRequestV1Request} ssprResetPasswordRequestV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ssprResetPasswordRequestV1(ssprResetPasswordRequestV1Request: SsprResetPasswordRequestV1Request, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await ModuleSsprApiAxiosParamCreator(configuration).ssprResetPasswordRequestV1(ssprResetPasswordRequestV1Request, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * This endpoint resets the user\'s password.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Reset Password
         * @param {SsprResetPasswordV1Request} ssprResetPasswordV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ssprResetPasswordV1(ssprResetPasswordV1Request: SsprResetPasswordV1Request, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await ModuleSsprApiAxiosParamCreator(configuration).ssprResetPasswordV1(ssprResetPasswordV1Request, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * This endpoint returns an email with the username(s) matching the email address provided in case of forgotten username
         * @summary Send username(s)
         * @param {SsprSendUsernamesV1Request} ssprSendUsernamesV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ssprSendUsernamesV1(ssprSendUsernamesV1Request: SsprSendUsernamesV1Request, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await ModuleSsprApiAxiosParamCreator(configuration).ssprSendUsernamesV1(ssprSendUsernamesV1Request, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * This endpoint sends an email with a link to unlock the user account.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Unlock Account Request
         * @param {SsprUnlockAccountRequestV1Request} ssprUnlockAccountRequestV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ssprUnlockAccountRequestV1(ssprUnlockAccountRequestV1Request: SsprUnlockAccountRequestV1Request, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await ModuleSsprApiAxiosParamCreator(configuration).ssprUnlockAccountRequestV1(ssprUnlockAccountRequestV1Request, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
        /**
         * This endpoint unlocks the user account.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Unlock Account
         * @param {SsprUnlockAccountV1Request} ssprUnlockAccountV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ssprUnlockAccountV1(ssprUnlockAccountV1Request: SsprUnlockAccountV1Request, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await ModuleSsprApiAxiosParamCreator(configuration).ssprUnlockAccountV1(ssprUnlockAccountV1Request, options);
            return (axios: AxiosInstance = globalAxios, basePath: string = BASE_PATH) => {
                const axiosRequestArgs = {...localVarAxiosArgs.options, url: (configuration?.basePath || basePath) + localVarAxiosArgs.url};
                return axios.request(axiosRequestArgs);
            };
        },
    }
};

/**
 * ModuleSsprApi - factory interface
 * @export
 */
export const ModuleSsprApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    return {
        /**
         * This endpoint sends an email with a link to reset the user\'s password.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Reset Password Request
         * @param {SsprResetPasswordRequestV1Request} ssprResetPasswordRequestV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ssprResetPasswordRequestV1(ssprResetPasswordRequestV1Request: SsprResetPasswordRequestV1Request, options?: any): AxiosPromise<void> {
            return ModuleSsprApiFp(configuration).ssprResetPasswordRequestV1(ssprResetPasswordRequestV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * This endpoint resets the user\'s password.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Reset Password
         * @param {SsprResetPasswordV1Request} ssprResetPasswordV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ssprResetPasswordV1(ssprResetPasswordV1Request: SsprResetPasswordV1Request, options?: any): AxiosPromise<void> {
            return ModuleSsprApiFp(configuration).ssprResetPasswordV1(ssprResetPasswordV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * This endpoint returns an email with the username(s) matching the email address provided in case of forgotten username
         * @summary Send username(s)
         * @param {SsprSendUsernamesV1Request} ssprSendUsernamesV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ssprSendUsernamesV1(ssprSendUsernamesV1Request: SsprSendUsernamesV1Request, options?: any): AxiosPromise<void> {
            return ModuleSsprApiFp(configuration).ssprSendUsernamesV1(ssprSendUsernamesV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * This endpoint sends an email with a link to unlock the user account.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Unlock Account Request
         * @param {SsprUnlockAccountRequestV1Request} ssprUnlockAccountRequestV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ssprUnlockAccountRequestV1(ssprUnlockAccountRequestV1Request: SsprUnlockAccountRequestV1Request, options?: any): AxiosPromise<void> {
            return ModuleSsprApiFp(configuration).ssprUnlockAccountRequestV1(ssprUnlockAccountRequestV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * This endpoint unlocks the user account.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
         * @summary Unlock Account
         * @param {SsprUnlockAccountV1Request} ssprUnlockAccountV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ssprUnlockAccountV1(ssprUnlockAccountV1Request: SsprUnlockAccountV1Request, options?: any): AxiosPromise<void> {
            return ModuleSsprApiFp(configuration).ssprUnlockAccountV1(ssprUnlockAccountV1Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ModuleSsprApi - object-oriented interface
 * @export
 * @class ModuleSsprApi
 * @extends {BaseAPI}
 */
export class ModuleSsprApi extends BaseAPI {
    /**
     * This endpoint sends an email with a link to reset the user\'s password.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
     * @summary Reset Password Request
     * @param {SsprResetPasswordRequestV1Request} ssprResetPasswordRequestV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ModuleSsprApi
     */
    public ssprResetPasswordRequestV1(ssprResetPasswordRequestV1Request: SsprResetPasswordRequestV1Request, options?: any) {
        return ModuleSsprApiFp(this.configuration).ssprResetPasswordRequestV1(ssprResetPasswordRequestV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * This endpoint resets the user\'s password.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
     * @summary Reset Password
     * @param {SsprResetPasswordV1Request} ssprResetPasswordV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ModuleSsprApi
     */
    public ssprResetPasswordV1(ssprResetPasswordV1Request: SsprResetPasswordV1Request, options?: any) {
        return ModuleSsprApiFp(this.configuration).ssprResetPasswordV1(ssprResetPasswordV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * This endpoint returns an email with the username(s) matching the email address provided in case of forgotten username
     * @summary Send username(s)
     * @param {SsprSendUsernamesV1Request} ssprSendUsernamesV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ModuleSsprApi
     */
    public ssprSendUsernamesV1(ssprSendUsernamesV1Request: SsprSendUsernamesV1Request, options?: any) {
        return ModuleSsprApiFp(this.configuration).ssprSendUsernamesV1(ssprSendUsernamesV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * This endpoint sends an email with a link to unlock the user account.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
     * @summary Unlock Account Request
     * @param {SsprUnlockAccountRequestV1Request} ssprUnlockAccountRequestV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ModuleSsprApi
     */
    public ssprUnlockAccountRequestV1(ssprUnlockAccountRequestV1Request: SsprUnlockAccountRequestV1Request, options?: any) {
        return ModuleSsprApiFp(this.configuration).ssprUnlockAccountRequestV1(ssprUnlockAccountRequestV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * This endpoint unlocks the user account.  sEmailAddress must be set if eUserTypeSSPR = EzsignUser  sUserLoginname must be set if eUserTypeSSPR = Native
     * @summary Unlock Account
     * @param {SsprUnlockAccountV1Request} ssprUnlockAccountV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ModuleSsprApi
     */
    public ssprUnlockAccountV1(ssprUnlockAccountV1Request: SsprUnlockAccountV1Request, options?: any) {
        return ModuleSsprApiFp(this.configuration).ssprUnlockAccountV1(ssprUnlockAccountV1Request, options).then((request) => request(this.axios, this.basePath));
    }
}
