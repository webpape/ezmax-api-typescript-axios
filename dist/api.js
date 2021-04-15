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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
__exportStar(require("./api/global-customer-api"), exports);
__exportStar(require("./api/module-sspr-api"), exports);
__exportStar(require("./api/module-user-api"), exports);
__exportStar(require("./api/object-activesession-api"), exports);
__exportStar(require("./api/object-apikey-api"), exports);
__exportStar(require("./api/object-ezsigndocument-api"), exports);
__exportStar(require("./api/object-ezsignfolder-api"), exports);
__exportStar(require("./api/object-ezsignfoldersignerassociation-api"), exports);
__exportStar(require("./api/object-ezsignsignature-api"), exports);
__exportStar(require("./api/object-franchisebroker-api"), exports);
__exportStar(require("./api/object-franchiseoffice-api"), exports);
__exportStar(require("./api/object-franchisereferalincome-api"), exports);
__exportStar(require("./api/object-period-api"), exports);
