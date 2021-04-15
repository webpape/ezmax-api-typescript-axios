"use strict";
/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.39
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ObjectEzsignfoldersignerassociationApi = exports.ObjectEzsignfoldersignerassociationApiFactory = exports.ObjectEzsignfoldersignerassociationApiFp = exports.ObjectEzsignfoldersignerassociationApiAxiosParamCreator = void 0;
const axios_1 = require("axios");
// Some imports not used depending on template conditions
// @ts-ignore
const common_1 = require("../common");
// @ts-ignore
const base_1 = require("../base");
// @ts-ignore
const request_signature_1 = require("../api/request-signature");
/**
 * ObjectEzsignfoldersignerassociationApi - axios parameter creator
 * @export
 */
const ObjectEzsignfoldersignerassociationApiAxiosParamCreator = function (configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationCreateObjectV1: (ezsignfoldersignerassociationCreateObjectV1Request, options = {}) => __awaiter(this, void 0, void 0, function* () {
            // verify required parameter 'ezsignfoldersignerassociationCreateObjectV1Request' is not null or undefined
            common_1.assertParamExists('ezsignfoldersignerassociationCreateObjectV1', 'ezsignfoldersignerassociationCreateObjectV1Request', ezsignfoldersignerassociationCreateObjectV1Request);
            const localVarPath = `/1/object/ezsignfoldersignerassociation`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = common_1.DUMMY_BASE_URL;
            if (configuration && configuration.basePath)
                basePath = configuration.basePath;
            const localVarUrlObj = new URL(localVarPath, basePath);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }
            const localVarRequestOptions = Object.assign(Object.assign({ method: 'POST' }, baseOptions), options);
            const localVarHeaderParameter = {};
            const localVarQueryParameter = {};
            // authentication Authorization required
            yield common_1.setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration);
            localVarHeaderParameter['Content-Type'] = 'application/json';
            common_1.setSearchParams(localVarUrlObj, localVarQueryParameter, options.query);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = Object.assign(Object.assign(Object.assign({}, localVarHeaderParameter), headersFromBaseOptions), options.headers);
            localVarRequestOptions.data = common_1.serializeDataIfNeeded(ezsignfoldersignerassociationCreateObjectV1Request, localVarRequestOptions, configuration);
            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret();
                if (secret) {
                    const headers = {
                        authorization: configuration.apiKey,
                        secret: secret,
                        method: 'POST',
                        url: basePath + localVarPath,
                        body: localVarRequestOptions.data
                    };
                    const signatureHeaders = request_signature_1.RequestSignature.getHeaders(headers);
                    localVarRequestOptions.headers = Object.assign(Object.assign({}, localVarRequestOptions.headers), signatureHeaders);
                }
            }
            return {
                url: common_1.toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        }),
        /**
         *
         * @summary Delete an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationDeleteObjectV1: (pkiEzsignfoldersignerassociationID, options = {}) => __awaiter(this, void 0, void 0, function* () {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            common_1.assertParamExists('ezsignfoldersignerassociationDeleteObjectV1', 'pkiEzsignfoldersignerassociationID', pkiEzsignfoldersignerassociationID);
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = common_1.DUMMY_BASE_URL;
            if (configuration && configuration.basePath)
                basePath = configuration.basePath;
            const localVarUrlObj = new URL(localVarPath, basePath);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }
            const localVarRequestOptions = Object.assign(Object.assign({ method: 'DELETE' }, baseOptions), options);
            const localVarHeaderParameter = {};
            const localVarQueryParameter = {};
            // authentication Authorization required
            yield common_1.setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration);
            common_1.setSearchParams(localVarUrlObj, localVarQueryParameter, options.query);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = Object.assign(Object.assign(Object.assign({}, localVarHeaderParameter), headersFromBaseOptions), options.headers);
            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret();
                if (secret) {
                    const headers = {
                        authorization: configuration.apiKey,
                        secret: secret,
                        method: 'DELETE',
                        url: basePath + localVarPath,
                        body: localVarRequestOptions.data
                    };
                    const signatureHeaders = request_signature_1.RequestSignature.getHeaders(headers);
                    localVarRequestOptions.headers = Object.assign(Object.assign({}, localVarRequestOptions.headers), signatureHeaders);
                }
            }
            return {
                url: common_1.toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        }),
        /**
         *
         * @summary Retrieve an existing Ezsignfoldersignerassociation\'s children IDs
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetChildrenV1: (pkiEzsignfoldersignerassociationID, options = {}) => __awaiter(this, void 0, void 0, function* () {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            common_1.assertParamExists('ezsignfoldersignerassociationGetChildrenV1', 'pkiEzsignfoldersignerassociationID', pkiEzsignfoldersignerassociationID);
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}/getChildren`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = common_1.DUMMY_BASE_URL;
            if (configuration && configuration.basePath)
                basePath = configuration.basePath;
            const localVarUrlObj = new URL(localVarPath, basePath);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }
            const localVarRequestOptions = Object.assign(Object.assign({ method: 'GET' }, baseOptions), options);
            const localVarHeaderParameter = {};
            const localVarQueryParameter = {};
            // authentication Authorization required
            yield common_1.setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration);
            common_1.setSearchParams(localVarUrlObj, localVarQueryParameter, options.query);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = Object.assign(Object.assign(Object.assign({}, localVarHeaderParameter), headersFromBaseOptions), options.headers);
            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret();
                if (secret) {
                    const headers = {
                        authorization: configuration.apiKey,
                        secret: secret,
                        method: 'GET',
                        url: basePath + localVarPath,
                        body: localVarRequestOptions.data
                    };
                    const signatureHeaders = request_signature_1.RequestSignature.getHeaders(headers);
                    localVarRequestOptions.headers = Object.assign(Object.assign({}, localVarRequestOptions.headers), signatureHeaders);
                }
            }
            return {
                url: common_1.toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        }),
        /**
         * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
         * @summary Retrieve a Login Url to allow In-Person signing
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetInPersonLoginUrlV1: (pkiEzsignfoldersignerassociationID, options = {}) => __awaiter(this, void 0, void 0, function* () {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            common_1.assertParamExists('ezsignfoldersignerassociationGetInPersonLoginUrlV1', 'pkiEzsignfoldersignerassociationID', pkiEzsignfoldersignerassociationID);
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}/getInPersonLoginUrl`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = common_1.DUMMY_BASE_URL;
            if (configuration && configuration.basePath)
                basePath = configuration.basePath;
            const localVarUrlObj = new URL(localVarPath, basePath);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }
            const localVarRequestOptions = Object.assign(Object.assign({ method: 'GET' }, baseOptions), options);
            const localVarHeaderParameter = {};
            const localVarQueryParameter = {};
            // authentication Authorization required
            yield common_1.setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration);
            common_1.setSearchParams(localVarUrlObj, localVarQueryParameter, options.query);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = Object.assign(Object.assign(Object.assign({}, localVarHeaderParameter), headersFromBaseOptions), options.headers);
            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret();
                if (secret) {
                    const headers = {
                        authorization: configuration.apiKey,
                        secret: secret,
                        method: 'GET',
                        url: basePath + localVarPath,
                        body: localVarRequestOptions.data
                    };
                    const signatureHeaders = request_signature_1.RequestSignature.getHeaders(headers);
                    localVarRequestOptions.headers = Object.assign(Object.assign({}, localVarRequestOptions.headers), signatureHeaders);
                }
            }
            return {
                url: common_1.toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        }),
        /**
         *
         * @summary Retrieve an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetObjectV1: (pkiEzsignfoldersignerassociationID, options = {}) => __awaiter(this, void 0, void 0, function* () {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            common_1.assertParamExists('ezsignfoldersignerassociationGetObjectV1', 'pkiEzsignfoldersignerassociationID', pkiEzsignfoldersignerassociationID);
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = common_1.DUMMY_BASE_URL;
            if (configuration && configuration.basePath)
                basePath = configuration.basePath;
            const localVarUrlObj = new URL(localVarPath, basePath);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }
            const localVarRequestOptions = Object.assign(Object.assign({ method: 'GET' }, baseOptions), options);
            const localVarHeaderParameter = {};
            const localVarQueryParameter = {};
            // authentication Authorization required
            yield common_1.setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration);
            common_1.setSearchParams(localVarUrlObj, localVarQueryParameter, options.query);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = Object.assign(Object.assign(Object.assign({}, localVarHeaderParameter), headersFromBaseOptions), options.headers);
            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret();
                if (secret) {
                    const headers = {
                        authorization: configuration.apiKey,
                        secret: secret,
                        method: 'GET',
                        url: basePath + localVarPath,
                        body: localVarRequestOptions.data
                    };
                    const signatureHeaders = request_signature_1.RequestSignature.getHeaders(headers);
                    localVarRequestOptions.headers = Object.assign(Object.assign({}, localVarRequestOptions.headers), signatureHeaders);
                }
            }
            return {
                url: common_1.toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        }),
    };
};
exports.ObjectEzsignfoldersignerassociationApiAxiosParamCreator = ObjectEzsignfoldersignerassociationApiAxiosParamCreator;
/**
 * ObjectEzsignfoldersignerassociationApi - functional programming interface
 * @export
 */
const ObjectEzsignfoldersignerassociationApiFp = function (configuration) {
    const localVarAxiosParamCreator = exports.ObjectEzsignfoldersignerassociationApiAxiosParamCreator(configuration);
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options) {
            return __awaiter(this, void 0, void 0, function* () {
                const localVarAxiosArgs = yield localVarAxiosParamCreator.ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options);
                return common_1.createRequestFunction(localVarAxiosArgs, axios_1.default, base_1.BASE_PATH, configuration);
            });
        },
        /**
         *
         * @summary Delete an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options) {
            return __awaiter(this, void 0, void 0, function* () {
                const localVarAxiosArgs = yield localVarAxiosParamCreator.ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options);
                return common_1.createRequestFunction(localVarAxiosArgs, axios_1.default, base_1.BASE_PATH, configuration);
            });
        },
        /**
         *
         * @summary Retrieve an existing Ezsignfoldersignerassociation\'s children IDs
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID, options) {
            return __awaiter(this, void 0, void 0, function* () {
                const localVarAxiosArgs = yield localVarAxiosParamCreator.ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID, options);
                return common_1.createRequestFunction(localVarAxiosArgs, axios_1.default, base_1.BASE_PATH, configuration);
            });
        },
        /**
         * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
         * @summary Retrieve a Login Url to allow In-Person signing
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options) {
            return __awaiter(this, void 0, void 0, function* () {
                const localVarAxiosArgs = yield localVarAxiosParamCreator.ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options);
                return common_1.createRequestFunction(localVarAxiosArgs, axios_1.default, base_1.BASE_PATH, configuration);
            });
        },
        /**
         *
         * @summary Retrieve an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options) {
            return __awaiter(this, void 0, void 0, function* () {
                const localVarAxiosArgs = yield localVarAxiosParamCreator.ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options);
                return common_1.createRequestFunction(localVarAxiosArgs, axios_1.default, base_1.BASE_PATH, configuration);
            });
        },
    };
};
exports.ObjectEzsignfoldersignerassociationApiFp = ObjectEzsignfoldersignerassociationApiFp;
/**
 * ObjectEzsignfoldersignerassociationApi - factory interface
 * @export
 */
const ObjectEzsignfoldersignerassociationApiFactory = function (configuration, basePath, axios) {
    const localVarFp = exports.ObjectEzsignfoldersignerassociationApiFp(configuration);
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options) {
            return localVarFp.ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         *
         * @summary Delete an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options) {
            return localVarFp.ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(axios, basePath));
        },
        /**
         *
         * @summary Retrieve an existing Ezsignfoldersignerassociation\'s children IDs
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID, options) {
            return localVarFp.ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(axios, basePath));
        },
        /**
         * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
         * @summary Retrieve a Login Url to allow In-Person signing
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options) {
            return localVarFp.ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(axios, basePath));
        },
        /**
         *
         * @summary Retrieve an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options) {
            return localVarFp.ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(axios, basePath));
        },
    };
};
exports.ObjectEzsignfoldersignerassociationApiFactory = ObjectEzsignfoldersignerassociationApiFactory;
/**
 * ObjectEzsignfoldersignerassociationApi - object-oriented interface
 * @export
 * @class ObjectEzsignfoldersignerassociationApi
 * @extends {BaseAPI}
 */
class ObjectEzsignfoldersignerassociationApi extends base_1.BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
     * @summary Create a new Ezsignfoldersignerassociation
     * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options) {
        return exports.ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }
    /**
     *
     * @summary Delete an existing Ezsignfoldersignerassociation
     * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options) {
        return exports.ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(this.axios, this.basePath));
    }
    /**
     *
     * @summary Retrieve an existing Ezsignfoldersignerassociation\'s children IDs
     * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID, options) {
        return exports.ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationGetChildrenV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(this.axios, this.basePath));
    }
    /**
     * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
     * @summary Retrieve a Login Url to allow In-Person signing
     * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options) {
        return exports.ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(this.axios, this.basePath));
    }
    /**
     *
     * @summary Retrieve an existing Ezsignfoldersignerassociation
     * @param {number} pkiEzsignfoldersignerassociationID The unique ID of the Ezsignfoldersignerassociation
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options) {
        return exports.ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(this.axios, this.basePath));
    }
}
exports.ObjectEzsignfoldersignerassociationApi = ObjectEzsignfoldersignerassociationApi;
