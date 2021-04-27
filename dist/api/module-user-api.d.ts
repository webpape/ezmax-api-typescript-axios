/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.42
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
import { AxiosPromise, AxiosInstance } from 'axios';
import { Configuration } from '../configuration';
import { RequestArgs, BaseAPI } from '../base';
import { UserCreateEzsignuserV1Request } from '../models';
import { UserCreateEzsignuserV1Response } from '../models';
/**
 * ModuleUserApi - axios parameter creator
 * @export
 */
export declare const ModuleUserApiAxiosParamCreator: (configuration?: Configuration) => {
    /**
     * The endpoint allows to initiate the creation or a user of type Ezsignuser.  The user will be created only once the email verification process will be completed
     * @summary Create a new User of type Ezsignuser
     * @param {Array<UserCreateEzsignuserV1Request>} userCreateEzsignuserV1Request
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     */
    userCreateEzsignuserV1: (userCreateEzsignuserV1Request: Array<UserCreateEzsignuserV1Request>, options?: any) => Promise<RequestArgs>;
};
/**
 * ModuleUserApi - functional programming interface
 * @export
 */
export declare const ModuleUserApiFp: (configuration?: Configuration) => {
    /**
     * The endpoint allows to initiate the creation or a user of type Ezsignuser.  The user will be created only once the email verification process will be completed
     * @summary Create a new User of type Ezsignuser
     * @param {Array<UserCreateEzsignuserV1Request>} userCreateEzsignuserV1Request
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     */
    userCreateEzsignuserV1(userCreateEzsignuserV1Request: Array<UserCreateEzsignuserV1Request>, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UserCreateEzsignuserV1Response>>;
};
/**
 * ModuleUserApi - factory interface
 * @export
 */
export declare const ModuleUserApiFactory: (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) => {
    /**
     * The endpoint allows to initiate the creation or a user of type Ezsignuser.  The user will be created only once the email verification process will be completed
     * @summary Create a new User of type Ezsignuser
     * @param {Array<UserCreateEzsignuserV1Request>} userCreateEzsignuserV1Request
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     */
    userCreateEzsignuserV1(userCreateEzsignuserV1Request: Array<UserCreateEzsignuserV1Request>, options?: any): AxiosPromise<UserCreateEzsignuserV1Response>;
};
/**
 * ModuleUserApi - object-oriented interface
 * @export
 * @class ModuleUserApi
 * @extends {BaseAPI}
 */
export declare class ModuleUserApi extends BaseAPI {
    /**
     * The endpoint allows to initiate the creation or a user of type Ezsignuser.  The user will be created only once the email verification process will be completed
     * @summary Create a new User of type Ezsignuser
     * @param {Array<UserCreateEzsignuserV1Request>} userCreateEzsignuserV1Request
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ModuleUserApi
     */
    userCreateEzsignuserV1(userCreateEzsignuserV1Request: Array<UserCreateEzsignuserV1Request>, options?: any): Promise<import("axios").AxiosResponse<any>>;
}
