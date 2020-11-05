import { isPlatformBrowser } from '@angular/common';
import { hextob64u, KEYUTIL, KJUR } from 'jsrsasign';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Router } from '@angular/router';
import { Subject, from, Observable, of, BehaviorSubject, throwError, timer } from 'rxjs';
import { Inject, Injectable, PLATFORM_ID, NgZone, NgModule } from '@angular/core';
import { take, catchError, map, filter, race, shareReplay, switchMap, switchMapTo, tap } from 'rxjs/operators';

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class AuthWellKnownEndpoints {
    constructor() {
        this.issuer = '';
        this.jwks_uri = '';
        this.authorization_endpoint = '';
        this.token_endpoint = '';
        this.userinfo_endpoint = '';
        this.end_session_endpoint = '';
        this.check_session_iframe = '';
        this.revocation_endpoint = '';
        this.introspection_endpoint = '';
    }
    /**
     * @param {?} data
     * @return {?}
     */
    setWellKnownEndpoints(data) {
        this.issuer = data.issuer;
        this.jwks_uri = data.jwks_uri;
        this.authorization_endpoint = data.authorization_endpoint;
        this.token_endpoint = data.token_endpoint;
        this.userinfo_endpoint = data.userinfo_endpoint;
        if (data.end_session_endpoint) {
            this.end_session_endpoint = data.end_session_endpoint;
        }
        if (data.check_session_iframe) {
            this.check_session_iframe = data.check_session_iframe;
        }
        if (data.revocation_endpoint) {
            this.revocation_endpoint = data.revocation_endpoint;
        }
        if (data.introspection_endpoint) {
            this.introspection_endpoint = data.introspection_endpoint;
        }
    }
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class AuthorizationResult {
    /**
     * @param {?} authorizationState
     * @param {?} validationResult
     */
    constructor(authorizationState, validationResult) {
        this.authorizationState = authorizationState;
        this.validationResult = validationResult;
    }
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/** @enum {string} */
const AuthorizationState = {
    authorized: 'authorized',
    forbidden: 'forbidden',
    unauthorized: 'unauthorized',
};

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class JwtKeys {
    constructor() {
        this.keys = [];
    }
}
class JwtKey {
    constructor() {
        this.kty = '';
        this.use = '';
        this.kid = '';
        this.x5t = '';
        this.e = '';
        this.n = '';
        this.x5c = [];
    }
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/** @enum {string} */
const ValidationResult = {
    NotSet: 'NotSet',
    StatesDoNotMatch: 'StatesDoNotMatch',
    SignatureFailed: 'SignatureFailed',
    IncorrectNonce: 'IncorrectNonce',
    RequiredPropertyMissing: 'RequiredPropertyMissing',
    MaxOffsetExpired: 'MaxOffsetExpired',
    IssDoesNotMatchIssuer: 'IssDoesNotMatchIssuer',
    NoAuthWellKnownEndPoints: 'NoAuthWellKnownEndPoints',
    IncorrectAud: 'IncorrectAud',
    TokenExpired: 'TokenExpired',
    IncorrectAtHash: 'IncorrectAtHash',
    Ok: 'Ok',
    LoginRequired: 'LoginRequired',
    SecureTokenServerError: 'SecureTokenServerError',
};

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class ValidateStateResult {
    /**
     * @param {?=} access_token
     * @param {?=} id_token
     * @param {?=} authResponseIsValid
     * @param {?=} decoded_id_token
     * @param {?=} state
     */
    constructor(access_token = '', id_token = '', authResponseIsValid = false, decoded_id_token = {}, state = ValidationResult.NotSet) {
        this.access_token = access_token;
        this.id_token = id_token;
        this.authResponseIsValid = authResponseIsValid;
        this.decoded_id_token = decoded_id_token;
        this.state = state;
    }
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class OpenIDImplicitFlowConfiguration {
    constructor() {
        this.stsServer = 'https://localhost:44318';
        this.redirect_url = 'https://localhost:44311';
        // The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified
        // by the iss (issuer) Claim as an audience.
        // The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience,
        // or if it contains additional audiences not trusted by the Client.
        this.client_id = 'angularclient';
        this.response_type = 'id_token token';
        this.scope = 'openid email profile';
        // Only for Google Auth with particular G Suite domain, see https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
        this.hd_param = '';
        this.post_logout_redirect_uri = 'https://localhost:44311/unauthorized';
        this.start_checksession = false;
        this.silent_renew = false;
        this.silent_renew_url = 'https://localhost:44311';
        this.silent_renew_offset_in_seconds = 0;
        this.silent_redirect_url = 'https://localhost:44311';
        this.post_login_route = '/';
        // HTTP 403
        this.forbidden_route = '/forbidden';
        // HTTP 401
        this.unauthorized_route = '/unauthorized';
        this.auto_userinfo = true;
        this.auto_clean_state_after_authentication = true;
        this.trigger_authorization_result_event = false;
        this.log_console_warning_active = true;
        this.log_console_debug_active = false;
        this.iss_validation_off = false;
        this.history_cleanup_off = false;
        // id_token C8: The iat Claim can be used to reject tokens that were issued too far away from the current time,
        // limiting the amount of time that nonces need to be stored to prevent attacks.The acceptable range is Client specific.
        this.max_id_token_iat_offset_allowed_in_seconds = 3;
        this.disable_iat_offset_validation = false;
        this.storage = typeof Storage !== 'undefined' ? sessionStorage : null;
    }
}
class AuthConfiguration {
    /**
     * @param {?} platformId
     */
    constructor(platformId) {
        this.platformId = platformId;
        this._onConfigurationChange = new Subject();
        this.defaultConfig = new OpenIDImplicitFlowConfiguration();
    }
    /**
     * @return {?}
     */
    get stsServer() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.stsServer;
        }
        return this.defaultConfig.stsServer;
    }
    /**
     * @return {?}
     */
    get redirect_url() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.redirect_url;
        }
        return this.defaultConfig.redirect_url;
    }
    /**
     * @return {?}
     */
    get silent_redirect_url() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.silent_renew_url;
        }
        return this.defaultConfig.silent_renew_url;
    }
    /**
     * @return {?}
     */
    get client_id() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.client_id;
        }
        return this.defaultConfig.client_id;
    }
    /**
     * @return {?}
     */
    get response_type() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.response_type;
        }
        return this.defaultConfig.response_type;
    }
    /**
     * @return {?}
     */
    get scope() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.scope;
        }
        return this.defaultConfig.scope;
    }
    /**
     * @return {?}
     */
    get hd_param() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.hd_param;
        }
        return this.defaultConfig.hd_param;
    }
    /**
     * @return {?}
     */
    get post_logout_redirect_uri() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.post_logout_redirect_uri;
        }
        return this.defaultConfig.post_logout_redirect_uri;
    }
    /**
     * @return {?}
     */
    get start_checksession() {
        if (!isPlatformBrowser(this.platformId)) {
            return false;
        }
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.start_checksession;
        }
        return this.defaultConfig.start_checksession;
    }
    /**
     * @return {?}
     */
    get silent_renew() {
        if (!isPlatformBrowser(this.platformId)) {
            return false;
        }
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.silent_renew;
        }
        return this.defaultConfig.silent_renew;
    }
    /**
     * @return {?}
     */
    get silent_renew_offset_in_seconds() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.silent_renew_offset_in_seconds;
        }
        return this.defaultConfig.silent_renew_offset_in_seconds;
    }
    /**
     * @return {?}
     */
    get post_login_route() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.post_login_route;
        }
        return this.defaultConfig.post_login_route;
    }
    /**
     * @return {?}
     */
    get forbidden_route() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.forbidden_route;
        }
        return this.defaultConfig.forbidden_route;
    }
    /**
     * @return {?}
     */
    get unauthorized_route() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.unauthorized_route;
        }
        return this.defaultConfig.unauthorized_route;
    }
    /**
     * @return {?}
     */
    get auto_userinfo() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.auto_userinfo;
        }
        return this.defaultConfig.auto_userinfo;
    }
    /**
     * @return {?}
     */
    get auto_clean_state_after_authentication() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.auto_clean_state_after_authentication;
        }
        return this.defaultConfig.auto_clean_state_after_authentication;
    }
    /**
     * @return {?}
     */
    get trigger_authorization_result_event() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.trigger_authorization_result_event;
        }
        return this.defaultConfig.trigger_authorization_result_event;
    }
    /**
     * @return {?}
     */
    get isLogLevelWarningEnabled() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.log_console_warning_active;
        }
        return this.defaultConfig.log_console_warning_active;
    }
    /**
     * @return {?}
     */
    get isLogLevelDebugEnabled() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.log_console_debug_active;
        }
        return this.defaultConfig.log_console_debug_active;
    }
    /**
     * @return {?}
     */
    get iss_validation_off() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.iss_validation_off;
        }
        return this.defaultConfig.iss_validation_off;
    }
    /**
     * @return {?}
     */
    get history_cleanup_off() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.history_cleanup_off;
        }
        return this.defaultConfig.history_cleanup_off;
    }
    /**
     * @return {?}
     */
    get max_id_token_iat_offset_allowed_in_seconds() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.max_id_token_iat_offset_allowed_in_seconds;
        }
        return this.defaultConfig.max_id_token_iat_offset_allowed_in_seconds;
    }
    /**
     * @return {?}
     */
    get disable_iat_offset_validation() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.disable_iat_offset_validation;
        }
        return this.defaultConfig.disable_iat_offset_validation;
    }
    /**
     * @return {?}
     */
    get storage() {
        if (this.openIDImplicitFlowConfiguration) {
            return this.openIDImplicitFlowConfiguration.storage;
        }
        return this.defaultConfig.storage;
    }
    /**
     * @param {?} openIDImplicitFlowConfiguration
     * @return {?}
     */
    init(openIDImplicitFlowConfiguration) {
        this.openIDImplicitFlowConfiguration = openIDImplicitFlowConfiguration;
        this._onConfigurationChange.next(openIDImplicitFlowConfiguration);
    }
    /**
     * @return {?}
     */
    get onConfigurationChange() {
        return this._onConfigurationChange.asObservable();
    }
}
AuthConfiguration.decorators = [
    { type: Injectable }
];
/** @nocollapse */
AuthConfiguration.ctorParameters = () => [
    { type: Object, decorators: [{ type: Inject, args: [PLATFORM_ID,] }] }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class OidcDataService {
    /**
     * @param {?} httpClient
     */
    constructor(httpClient) {
        this.httpClient = httpClient;
    }
    /**
     * @template T
     * @param {?} url
     * @return {?}
     */
    getWellknownEndpoints(url) {
        /** @type {?} */
        let headers = new HttpHeaders();
        headers = headers.set('Accept', 'application/json');
        return this.httpClient.get(url, {
            headers: headers,
        });
    }
    /**
     * @template T
     * @param {?} url
     * @param {?} token
     * @return {?}
     */
    getIdentityUserData(url, token) {
        /** @type {?} */
        let headers = new HttpHeaders();
        headers = headers.set('Accept', 'application/json');
        headers = headers.set('Authorization', 'Bearer ' + decodeURIComponent(token));
        return this.httpClient.get(url, {
            headers: headers,
        });
    }
    /**
     * @template T
     * @param {?} url
     * @return {?}
     */
    get(url) {
        /** @type {?} */
        let headers = new HttpHeaders();
        headers = headers.set('Accept', 'application/json');
        return this.httpClient.get(url, {
            headers: headers,
        });
    }
}
OidcDataService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcDataService.ctorParameters = () => [
    { type: HttpClient }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class LoggerService {
    /**
     * @param {?} authConfiguration
     */
    constructor(authConfiguration) {
        this.authConfiguration = authConfiguration;
    }
    /**
     * @param {?} message
     * @return {?}
     */
    logError(message) {
        console.error(message);
    }
    /**
     * @param {?} message
     * @return {?}
     */
    logWarning(message) {
        if (this.authConfiguration.isLogLevelWarningEnabled) {
            console.warn(message);
        }
    }
    /**
     * @param {?} message
     * @return {?}
     */
    logDebug(message) {
        if (this.authConfiguration.isLogLevelDebugEnabled) {
            console.log(message);
        }
    }
}
LoggerService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
LoggerService.ctorParameters = () => [
    { type: AuthConfiguration }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class IFrameService {
    /**
     * @param {?} loggerService
     */
    constructor(loggerService) {
        this.loggerService = loggerService;
    }
    /**
     * @param {?} identifier
     * @return {?}
     */
    getExistingIFrame(identifier) {
        /** @type {?} */
        const iFrameOnParent = this.getIFrameFromParentWindow(identifier);
        if (iFrameOnParent) {
            return iFrameOnParent;
        }
        return this.getIFrameFromWindow(identifier);
    }
    /**
     * @param {?} identifier
     * @return {?}
     */
    addIFrameToWindowBody(identifier) {
        /** @type {?} */
        const sessionIframe = window.document.createElement('iframe');
        sessionIframe.id = identifier;
        this.loggerService.logDebug(sessionIframe);
        sessionIframe.style.display = 'none';
        window.document.body.appendChild(sessionIframe);
        return sessionIframe;
    }
    /**
     * @private
     * @param {?} identifier
     * @return {?}
     */
    getIFrameFromParentWindow(identifier) {
        try {
            return window.parent.document.getElementById(identifier);
        }
        catch (e) {
            return null;
        }
    }
    /**
     * @private
     * @param {?} identifier
     * @return {?}
     */
    getIFrameFromWindow(identifier) {
        return window.document.getElementById(identifier);
    }
}
IFrameService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
IFrameService.ctorParameters = () => [
    { type: LoggerService }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class EqualityHelperService {
    /**
     * @param {?} value1
     * @param {?} value2
     * @return {?}
     */
    areEqual(value1, value2) {
        if (!value1 || !value2) {
            return false;
        }
        if (this.bothValuesAreArrays(value1, value2)) {
            return this.arraysEqual((/** @type {?} */ (value1)), (/** @type {?} */ (value2)));
        }
        if (this.bothValuesAreStrings(value1, value2)) {
            return value1 === value2;
        }
        if (this.bothValuesAreObjects(value1, value2)) {
            return JSON.stringify(value1).toLowerCase() === JSON.stringify(value2).toLowerCase();
        }
        if (this.oneValueIsStringAndTheOtherIsArray(value1, value2)) {
            if (Array.isArray(value1) && this.valueIsString(value2)) {
                return value1[0] === value2;
            }
            if (Array.isArray(value2) && this.valueIsString(value1)) {
                return value2[0] === value1;
            }
        }
    }
    /**
     * @private
     * @param {?} value1
     * @param {?} value2
     * @return {?}
     */
    oneValueIsStringAndTheOtherIsArray(value1, value2) {
        return (Array.isArray(value1) && this.valueIsString(value2)) || (Array.isArray(value2) && this.valueIsString(value1));
    }
    /**
     * @private
     * @param {?} value1
     * @param {?} value2
     * @return {?}
     */
    bothValuesAreObjects(value1, value2) {
        return this.valueIsObject(value1) && this.valueIsObject(value2);
    }
    /**
     * @private
     * @param {?} value1
     * @param {?} value2
     * @return {?}
     */
    bothValuesAreStrings(value1, value2) {
        return this.valueIsString(value1) && this.valueIsString(value2);
    }
    /**
     * @private
     * @param {?} value1
     * @param {?} value2
     * @return {?}
     */
    bothValuesAreArrays(value1, value2) {
        return Array.isArray(value1) && Array.isArray(value2);
    }
    /**
     * @private
     * @param {?} value
     * @return {?}
     */
    valueIsString(value) {
        return typeof value === 'string' || value instanceof String;
    }
    /**
     * @private
     * @param {?} value
     * @return {?}
     */
    valueIsObject(value) {
        return typeof value === 'object';
    }
    /**
     * @private
     * @param {?} arr1
     * @param {?} arr2
     * @return {?}
     */
    arraysEqual(arr1, arr2) {
        if (arr1.length !== arr2.length) {
            return false;
        }
        for (let i = arr1.length; i--;) {
            if (arr1[i] !== arr2[i]) {
                return false;
            }
        }
        return true;
    }
}
EqualityHelperService.decorators = [
    { type: Injectable }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class TokenHelperService {
    /**
     * @param {?} loggerService
     */
    constructor(loggerService) {
        this.loggerService = loggerService;
        this.PARTS_OF_TOKEN = 3;
    }
    /**
     * @param {?} dataIdToken
     * @return {?}
     */
    getTokenExpirationDate(dataIdToken) {
        if (!dataIdToken.hasOwnProperty('exp')) {
            return new Date();
        }
        /** @type {?} */
        const date = new Date(0);
        date.setUTCSeconds(dataIdToken.exp);
        return date;
    }
    /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    getHeaderFromToken(token, encoded) {
        if (!this.tokenIsValid(token)) {
            return {};
        }
        return this.getPartOfToken(token, 0, encoded);
    }
    /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    getPayloadFromToken(token, encoded) {
        if (!this.tokenIsValid(token)) {
            return {};
        }
        return this.getPartOfToken(token, 1, encoded);
    }
    /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    getSignatureFromToken(token, encoded) {
        if (!this.tokenIsValid(token)) {
            return {};
        }
        return this.getPartOfToken(token, 2, encoded);
    }
    /**
     * @private
     * @param {?} token
     * @param {?} index
     * @param {?} encoded
     * @return {?}
     */
    getPartOfToken(token, index, encoded) {
        /** @type {?} */
        const partOfToken = this.extractPartOfToken(token, index);
        if (encoded) {
            return partOfToken;
        }
        /** @type {?} */
        const result = this.urlBase64Decode(partOfToken);
        return JSON.parse(result);
    }
    /**
     * @private
     * @param {?} str
     * @return {?}
     */
    urlBase64Decode(str) {
        /** @type {?} */
        let output = str.replace(/-/g, '+').replace(/_/g, '/');
        switch (output.length % 4) {
            case 0:
                break;
            case 2:
                output += '==';
                break;
            case 3:
                output += '=';
                break;
            default:
                throw Error('Illegal base64url string!');
        }
        /** @type {?} */
        const decoded = typeof window !== 'undefined' ? window.atob(output) : new Buffer(output, 'base64').toString('binary');
        try {
            // Going backwards: from bytestream, to percent-encoding, to original string.
            return decodeURIComponent(decoded.split('')
                .map((/**
             * @param {?} c
             * @return {?}
             */
            (c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)))
                .join(''));
        }
        catch (err) {
            return decoded;
        }
    }
    /**
     * @private
     * @param {?} token
     * @return {?}
     */
    tokenIsValid(token) {
        if (!token) {
            this.loggerService.logError(`token '${token}' is not valid --> token falsy`);
            return false;
        }
        if (!((/** @type {?} */ (token))).includes('.')) {
            this.loggerService.logError(`token '${token}' is not valid --> no dots included`);
            return false;
        }
        /** @type {?} */
        const parts = token.split('.');
        if (parts.length !== this.PARTS_OF_TOKEN) {
            this.loggerService.logError(`token '${token}' is not valid --> token has t have exact three dots`);
            return false;
        }
        return true;
    }
    /**
     * @private
     * @param {?} token
     * @param {?} index
     * @return {?}
     */
    extractPartOfToken(token, index) {
        return token.split('.')[index];
    }
}
TokenHelperService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
TokenHelperService.ctorParameters = () => [
    { type: LoggerService }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * Implement this class-interface to create a custom storage.
 * @abstract
 */
class OidcSecurityStorage {
}
OidcSecurityStorage.decorators = [
    { type: Injectable }
];
class BrowserStorage {
    /**
     * @param {?} authConfiguration
     */
    constructor(authConfiguration) {
        this.authConfiguration = authConfiguration;
        this.hasStorage = typeof Storage !== 'undefined';
    }
    /**
     * @param {?} key
     * @return {?}
     */
    read(key) {
        if (this.hasStorage) {
            return JSON.parse(this.authConfiguration.storage.getItem(key + '_' + this.authConfiguration.client_id));
        }
        return;
    }
    /**
     * @param {?} key
     * @param {?} value
     * @return {?}
     */
    write(key, value) {
        if (this.hasStorage) {
            value = value === undefined ? null : value;
            this.authConfiguration.storage.setItem(key + '_' + this.authConfiguration.client_id, JSON.stringify(value));
        }
    }
}
BrowserStorage.decorators = [
    { type: Injectable }
];
/** @nocollapse */
BrowserStorage.ctorParameters = () => [
    { type: AuthConfiguration }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class OidcSecurityCommon {
    /**
     * @param {?} oidcSecurityStorage
     */
    constructor(oidcSecurityStorage) {
        this.oidcSecurityStorage = oidcSecurityStorage;
        this.storage_auth_result = 'authorizationResult';
        this.storage_access_token = 'authorizationData';
        this.storage_id_token = 'authorizationDataIdToken';
        this.storage_is_authorized = '_isAuthorized';
        this.storage_user_data = 'userData';
        this.storage_auth_nonce = 'authNonce';
        this.storage_code_verifier = 'code_verifier';
        this.storage_auth_state_control = 'authStateControl';
        this.storage_session_state = 'session_state';
        this.storage_silent_renew_running = 'storage_silent_renew_running';
        this.storage_custom_request_params = 'storage_custom_request_params';
    }
    /**
     * @return {?}
     */
    get authResult() {
        return this.retrieve(this.storage_auth_result);
    }
    /**
     * @param {?} value
     * @return {?}
     */
    set authResult(value) {
        this.store(this.storage_auth_result, value);
    }
    /**
     * @return {?}
     */
    get accessToken() {
        return this.retrieve(this.storage_access_token) || '';
    }
    /**
     * @param {?} value
     * @return {?}
     */
    set accessToken(value) {
        this.store(this.storage_access_token, value);
    }
    /**
     * @return {?}
     */
    get idToken() {
        return this.retrieve(this.storage_id_token) || '';
    }
    /**
     * @param {?} value
     * @return {?}
     */
    set idToken(value) {
        this.store(this.storage_id_token, value);
    }
    /**
     * @return {?}
     */
    get isAuthorized() {
        return this.retrieve(this.storage_is_authorized);
    }
    /**
     * @param {?} value
     * @return {?}
     */
    set isAuthorized(value) {
        this.store(this.storage_is_authorized, value);
    }
    /**
     * @return {?}
     */
    get userData() {
        return this.retrieve(this.storage_user_data);
    }
    /**
     * @param {?} value
     * @return {?}
     */
    set userData(value) {
        this.store(this.storage_user_data, value);
    }
    /**
     * @return {?}
     */
    get authNonce() {
        return this.retrieve(this.storage_auth_nonce) || '';
    }
    /**
     * @param {?} value
     * @return {?}
     */
    set authNonce(value) {
        this.store(this.storage_auth_nonce, value);
    }
    /**
     * @return {?}
     */
    get code_verifier() {
        return this.retrieve(this.storage_code_verifier) || '';
    }
    /**
     * @param {?} value
     * @return {?}
     */
    set code_verifier(value) {
        this.store(this.storage_code_verifier, value);
    }
    /**
     * @return {?}
     */
    get authStateControl() {
        return this.retrieve(this.storage_auth_state_control) || '';
    }
    /**
     * @param {?} value
     * @return {?}
     */
    set authStateControl(value) {
        this.store(this.storage_auth_state_control, value);
    }
    /**
     * @return {?}
     */
    get sessionState() {
        return this.retrieve(this.storage_session_state);
    }
    /**
     * @param {?} value
     * @return {?}
     */
    set sessionState(value) {
        this.store(this.storage_session_state, value);
    }
    /**
     * @return {?}
     */
    get silentRenewRunning() {
        return this.retrieve(this.storage_silent_renew_running) || '';
    }
    /**
     * @param {?} value
     * @return {?}
     */
    set silentRenewRunning(value) {
        this.store(this.storage_silent_renew_running, value);
    }
    /**
     * @return {?}
     */
    get customRequestParams() {
        return this.retrieve(this.storage_custom_request_params);
    }
    /**
     * @param {?} value
     * @return {?}
     */
    set customRequestParams(value) {
        this.store(this.storage_custom_request_params, value);
    }
    /**
     * @private
     * @param {?} key
     * @return {?}
     */
    retrieve(key) {
        return this.oidcSecurityStorage.read(key);
    }
    /**
     * @private
     * @param {?} key
     * @param {?} value
     * @return {?}
     */
    store(key, value) {
        this.oidcSecurityStorage.write(key, value);
    }
    /**
     * @param {?} isRenewProcess
     * @return {?}
     */
    resetStorageData(isRenewProcess) {
        if (!isRenewProcess) {
            this.store(this.storage_auth_result, '');
            this.store(this.storage_session_state, '');
            this.store(this.storage_silent_renew_running, '');
            this.store(this.storage_is_authorized, false);
            this.store(this.storage_access_token, '');
            this.store(this.storage_id_token, '');
            this.store(this.storage_user_data, '');
            this.store(this.storage_code_verifier, '');
        }
    }
    /**
     * @return {?}
     */
    getAccessToken() {
        return this.retrieve(this.storage_access_token);
    }
    /**
     * @return {?}
     */
    getIdToken() {
        return this.retrieve(this.storage_id_token);
    }
}
OidcSecurityCommon.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcSecurityCommon.ctorParameters = () => [
    { type: OidcSecurityStorage }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
// http://openid.net/specs/openid-connect-implicit-1_0.html
// id_token
// id_token C1: The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
// MUST exactly match the value of the iss (issuer) Claim.
//
// id_token C2: The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified
// by the iss (issuer) Claim as an audience.The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience,
// or if it contains additional audiences not trusted by the Client.
//
// id_token C3: If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
//
// id_token C4: If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
//
// id_token C5: The Client MUST validate the signature of the ID Token according to JWS [JWS] using the algorithm specified in the
// alg Header Parameter of the JOSE Header.The Client MUST use the keys provided by the Issuer.
//
// id_token C6: The alg value SHOULD be RS256. Validation of tokens using other signing algorithms is described in the OpenID Connect Core 1.0
// [OpenID.Core] specification.
//
// id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account
// for clock skew).
//
// id_token C8: The iat Claim can be used to reject tokens that were issued too far away from the current time,
// limiting the amount of time that nonces need to be stored to prevent attacks.The acceptable range is Client specific.
//
// id_token C9: The value of the nonce Claim MUST be checked to verify that it is the same value as the one that was sent
// in the Authentication Request.The Client SHOULD check the nonce value for replay attacks.The precise method for detecting replay attacks
// is Client specific.
//
// id_token C10: If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate.
// The meaning and processing of acr Claim Values is out of scope for this document.
//
// id_token C11: When a max_age request is made, the Client SHOULD check the auth_time Claim value and request re- authentication
// if it determines too much time has elapsed since the last End- User authentication.
// Access Token Validation
// access_token C1: Hash the octets of the ASCII representation of the access_token with the hash algorithm specified in JWA[JWA]
// for the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, the hash algorithm used is SHA-256.
// access_token C2: Take the left- most half of the hash and base64url- encode it.
// access_token C3: The value of at_hash in the ID Token MUST match the value produced in the previous step if at_hash is present in the ID Token.
class OidcSecurityValidation {
    /**
     * @param {?} arrayHelperService
     * @param {?} tokenHelperService
     * @param {?} loggerService
     */
    constructor(arrayHelperService, tokenHelperService, loggerService) {
        this.arrayHelperService = arrayHelperService;
        this.tokenHelperService = tokenHelperService;
        this.loggerService = loggerService;
    }
    // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
    /**
     * @param {?} token
     * @param {?=} offsetSeconds
     * @return {?}
     */
    isTokenExpired(token, offsetSeconds) {
        /** @type {?} */
        let decoded;
        decoded = this.tokenHelperService.getPayloadFromToken(token, false);
        return !this.validate_id_token_exp_not_expired(decoded, offsetSeconds);
    }
    // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
    /**
     * @param {?} decoded_id_token
     * @param {?=} offsetSeconds
     * @return {?}
     */
    validate_id_token_exp_not_expired(decoded_id_token, offsetSeconds) {
        /** @type {?} */
        const tokenExpirationDate = this.tokenHelperService.getTokenExpirationDate(decoded_id_token);
        offsetSeconds = offsetSeconds || 0;
        if (!tokenExpirationDate) {
            return false;
        }
        /** @type {?} */
        const tokenExpirationValue = tokenExpirationDate.valueOf();
        /** @type {?} */
        const nowWithOffset = new Date().valueOf() + offsetSeconds * 1000;
        /** @type {?} */
        const tokenNotExpired = tokenExpirationValue > nowWithOffset;
        this.loggerService.logDebug(`Token not expired?: ${tokenExpirationValue} > ${nowWithOffset}  (${tokenNotExpired})`);
        // Token not expired?
        return tokenNotExpired;
    }
    // iss
    // REQUIRED. Issuer Identifier for the Issuer of the response.The iss value is a case-sensitive URL using the https scheme that contains scheme, host,
    // and optionally, port number and path components and no query or fragment components.
    //
    // sub
    // REQUIRED. Subject Identifier.Locally unique and never reassigned identifier within the Issuer for the End- User,
    // which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
    // It MUST NOT exceed 255 ASCII characters in length.The sub value is a case-sensitive string.
    //
    // aud
    // REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value.
    // It MAY also contain identifiers for other audiences.In the general case, the aud value is an array of case-sensitive strings.
    // In the common special case when there is one audience, the aud value MAY be a single case-sensitive string.
    //
    // exp
    // REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
    // The processing of this parameter requires that the current date/ time MUST be before the expiration date/ time listed in the value.
    // Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.
    // Its value is a JSON [RFC7159] number representing the number of seconds from 1970- 01 - 01T00: 00:00Z as measured in UTC until the date/ time.
    // See RFC 3339 [RFC3339] for details regarding date/ times in general and UTC in particular.
    //
    // iat
    // REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970- 01 - 01T00: 00:00Z as measured
    // in UTC until the date/ time.
    /**
     * @param {?} dataIdToken
     * @return {?}
     */
    validate_required_id_token(dataIdToken) {
        /** @type {?} */
        let validated = true;
        if (!dataIdToken.hasOwnProperty('iss')) {
            validated = false;
            this.loggerService.logWarning('iss is missing, this is required in the id_token');
        }
        if (!dataIdToken.hasOwnProperty('sub')) {
            validated = false;
            this.loggerService.logWarning('sub is missing, this is required in the id_token');
        }
        if (!dataIdToken.hasOwnProperty('aud')) {
            validated = false;
            this.loggerService.logWarning('aud is missing, this is required in the id_token');
        }
        if (!dataIdToken.hasOwnProperty('exp')) {
            validated = false;
            this.loggerService.logWarning('exp is missing, this is required in the id_token');
        }
        if (!dataIdToken.hasOwnProperty('iat')) {
            validated = false;
            this.loggerService.logWarning('iat is missing, this is required in the id_token');
        }
        return validated;
    }
    // id_token C8: The iat Claim can be used to reject tokens that were issued too far away from the current time,
    // limiting the amount of time that nonces need to be stored to prevent attacks.The acceptable range is Client specific.
    /**
     * @param {?} dataIdToken
     * @param {?} max_offset_allowed_in_seconds
     * @param {?} disable_iat_offset_validation
     * @return {?}
     */
    validate_id_token_iat_max_offset(dataIdToken, max_offset_allowed_in_seconds, disable_iat_offset_validation) {
        if (disable_iat_offset_validation) {
            return true;
        }
        if (!dataIdToken.hasOwnProperty('iat')) {
            return false;
        }
        /** @type {?} */
        const dateTime_iat_id_token = new Date(0);
        dateTime_iat_id_token.setUTCSeconds(dataIdToken.iat);
        max_offset_allowed_in_seconds = max_offset_allowed_in_seconds || 0;
        if (dateTime_iat_id_token == null) {
            return false;
        }
        this.loggerService.logDebug('validate_id_token_iat_max_offset: ' +
            (new Date().valueOf() - dateTime_iat_id_token.valueOf()) +
            ' < ' +
            max_offset_allowed_in_seconds * 1000);
        return new Date().valueOf() - dateTime_iat_id_token.valueOf() < max_offset_allowed_in_seconds * 1000;
    }
    // id_token C9: The value of the nonce Claim MUST be checked to verify that it is the same value as the one
    // that was sent in the Authentication Request.The Client SHOULD check the nonce value for replay attacks.
    // The precise method for detecting replay attacks is Client specific.
    /**
     * @param {?} dataIdToken
     * @param {?} local_nonce
     * @return {?}
     */
    validate_id_token_nonce(dataIdToken, local_nonce) {
        if (dataIdToken.nonce !== local_nonce) {
            this.loggerService.logDebug('Validate_id_token_nonce failed, dataIdToken.nonce: ' + dataIdToken.nonce + ' local_nonce:' + local_nonce);
            return false;
        }
        return true;
    }
    // id_token C1: The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
    // MUST exactly match the value of the iss (issuer) Claim.
    /**
     * @param {?} dataIdToken
     * @param {?} authWellKnownEndpoints_issuer
     * @return {?}
     */
    validate_id_token_iss(dataIdToken, authWellKnownEndpoints_issuer) {
        if (((/** @type {?} */ (dataIdToken.iss))) !== ((/** @type {?} */ (authWellKnownEndpoints_issuer)))) {
            this.loggerService.logDebug('Validate_id_token_iss failed, dataIdToken.iss: ' +
                dataIdToken.iss +
                ' authWellKnownEndpoints issuer:' +
                authWellKnownEndpoints_issuer);
            return false;
        }
        return true;
    }
    // id_token C2: The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified
    // by the iss (issuer) Claim as an audience.
    // The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences
    // not trusted by the Client.
    /**
     * @param {?} dataIdToken
     * @param {?} aud
     * @return {?}
     */
    validate_id_token_aud(dataIdToken, aud) {
        if (dataIdToken.aud instanceof Array) {
            /** @type {?} */
            const result = this.arrayHelperService.areEqual(dataIdToken.aud, aud);
            if (!result) {
                this.loggerService.logDebug('Validate_id_token_aud  array failed, dataIdToken.aud: ' + dataIdToken.aud + ' client_id:' + aud);
                return false;
            }
            return true;
        }
        else if (dataIdToken.aud !== aud) {
            this.loggerService.logDebug('Validate_id_token_aud failed, dataIdToken.aud: ' + dataIdToken.aud + ' client_id:' + aud);
            return false;
        }
        return true;
    }
    /**
     * @param {?} state
     * @param {?} local_state
     * @return {?}
     */
    validateStateFromHashCallback(state, local_state) {
        if (((/** @type {?} */ (state))) !== ((/** @type {?} */ (local_state)))) {
            this.loggerService.logDebug('ValidateStateFromHashCallback failed, state: ' + state + ' local_state:' + local_state);
            return false;
        }
        return true;
    }
    /**
     * @param {?} id_token_sub
     * @param {?} userdata_sub
     * @return {?}
     */
    validate_userdata_sub_id_token(id_token_sub, userdata_sub) {
        if (((/** @type {?} */ (id_token_sub))) !== ((/** @type {?} */ (userdata_sub)))) {
            this.loggerService.logDebug('validate_userdata_sub_id_token failed, id_token_sub: ' + id_token_sub + ' userdata_sub:' + userdata_sub);
            return false;
        }
        return true;
    }
    // id_token C5: The Client MUST validate the signature of the ID Token according to JWS [JWS] using the algorithm specified in the alg
    // Header Parameter of the JOSE Header.The Client MUST use the keys provided by the Issuer.
    // id_token C6: The alg value SHOULD be RS256. Validation of tokens using other signing algorithms is described in the
    // OpenID Connect Core 1.0 [OpenID.Core] specification.
    /**
     * @param {?} id_token
     * @param {?} jwtkeys
     * @return {?}
     */
    validate_signature_id_token(id_token, jwtkeys) {
        if (!jwtkeys || !jwtkeys.keys) {
            return false;
        }
        /** @type {?} */
        const header_data = this.tokenHelperService.getHeaderFromToken(id_token, false);
        if (Object.keys(header_data).length === 0 && header_data.constructor === Object) {
            this.loggerService.logWarning('id token has no header data');
            return false;
        }
        /** @type {?} */
        const kid = header_data.kid;
        /** @type {?} */
        const alg = header_data.alg;
        if ('RS256' !== ((/** @type {?} */ (alg)))) {
            this.loggerService.logWarning('Only RS256 supported');
            return false;
        }
        /** @type {?} */
        let isValid = false;
        if (!header_data.hasOwnProperty('kid')) {
            // exactly 1 key in the jwtkeys and no kid in the Jose header
            // kty	"RSA" use "sig"
            /** @type {?} */
            let amountOfMatchingKeys = 0;
            for (const key of jwtkeys.keys) {
                if (((/** @type {?} */ (key.kty))) === 'RSA' && ((/** @type {?} */ (key.use))) === 'sig') {
                    amountOfMatchingKeys = amountOfMatchingKeys + 1;
                }
            }
            if (amountOfMatchingKeys === 0) {
                this.loggerService.logWarning('no keys found, incorrect Signature, validation failed for id_token');
                return false;
            }
            else if (amountOfMatchingKeys > 1) {
                this.loggerService.logWarning('no ID Token kid claim in JOSE header and multiple supplied in jwks_uri');
                return false;
            }
            else {
                for (const key of jwtkeys.keys) {
                    if (((/** @type {?} */ (key.kty))) === 'RSA' && ((/** @type {?} */ (key.use))) === 'sig') {
                        /** @type {?} */
                        const publickey = KEYUTIL.getKey(key);
                        isValid = KJUR.jws.JWS.verify(id_token, publickey, ['RS256']);
                        if (!isValid) {
                            this.loggerService.logWarning('incorrect Signature, validation failed for id_token');
                        }
                        return isValid;
                    }
                }
            }
        }
        else {
            // kid in the Jose header of id_token
            for (const key of jwtkeys.keys) {
                if (((/** @type {?} */ (key.kid))) === ((/** @type {?} */ (kid)))) {
                    /** @type {?} */
                    const publickey = KEYUTIL.getKey(key);
                    isValid = KJUR.jws.JWS.verify(id_token, publickey, ['RS256']);
                    if (!isValid) {
                        this.loggerService.logWarning('incorrect Signature, validation failed for id_token');
                    }
                    return isValid;
                }
            }
        }
        return isValid;
    }
    /**
     * @param {?} response_type
     * @return {?}
     */
    config_validate_response_type(response_type) {
        if (response_type === 'id_token token' || response_type === 'id_token') {
            return true;
        }
        if (response_type === 'code') {
            return true;
        }
        this.loggerService.logWarning('module configure incorrect, invalid response_type:' + response_type);
        return false;
    }
    // Accepts ID Token without 'kid' claim in JOSE header if only one JWK supplied in 'jwks_url'
    //// private validate_no_kid_in_header_only_one_allowed_in_jwtkeys(header_data: any, jwtkeys: any): boolean {
    ////    this.oidcSecurityCommon.logDebug('amount of jwtkeys.keys: ' + jwtkeys.keys.length);
    ////    if (!header_data.hasOwnProperty('kid')) {
    ////        // no kid defined in Jose header
    ////        if (jwtkeys.keys.length != 1) {
    ////            this.oidcSecurityCommon.logDebug('jwtkeys.keys.length != 1 and no kid in header');
    ////            return false;
    ////        }
    ////    }
    ////    return true;
    //// }
    // Access Token Validation
    // access_token C1: Hash the octets of the ASCII representation of the access_token with the hash algorithm specified in JWA[JWA]
    // for the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, the hash algorithm used is SHA-256.
    // access_token C2: Take the left- most half of the hash and base64url- encode it.
    // access_token C3: The value of at_hash in the ID Token MUST match the value produced in the previous step if at_hash
    // is present in the ID Token.
    /**
     * @param {?} access_token
     * @param {?} at_hash
     * @param {?} isCodeFlow
     * @return {?}
     */
    validate_id_token_at_hash(access_token, at_hash, isCodeFlow) {
        this.loggerService.logDebug('at_hash from the server:' + at_hash);
        // The at_hash is optional for the code flow
        if (isCodeFlow) {
            if (!((/** @type {?} */ (at_hash)))) {
                this.loggerService.logDebug('Code Flow active, and no at_hash in the id_token, skipping check!');
                return true;
            }
        }
        /** @type {?} */
        const testdata = this.generate_at_hash('' + access_token);
        this.loggerService.logDebug('at_hash client validation not decoded:' + testdata);
        if (testdata === ((/** @type {?} */ (at_hash)))) {
            return true; // isValid;
        }
        else {
            /** @type {?} */
            const testValue = this.generate_at_hash('' + decodeURIComponent(access_token));
            this.loggerService.logDebug('-gen access--' + testValue);
            if (testValue === ((/** @type {?} */ (at_hash)))) {
                return true; // isValid
            }
        }
        return false;
    }
    /**
     * @private
     * @param {?} access_token
     * @return {?}
     */
    generate_at_hash(access_token) {
        /** @type {?} */
        const hash = KJUR.crypto.Util.hashString(access_token, 'sha256');
        /** @type {?} */
        const first128bits = hash.substr(0, hash.length / 2);
        /** @type {?} */
        const testdata = hextob64u(first128bits);
        return testdata;
    }
    /**
     * @param {?} code_challenge
     * @return {?}
     */
    generate_code_verifier(code_challenge) {
        /** @type {?} */
        const hash = KJUR.crypto.Util.hashString(code_challenge, 'sha256');
        /** @type {?} */
        const testdata = hextob64u(hash);
        return testdata;
    }
}
OidcSecurityValidation.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcSecurityValidation.ctorParameters = () => [
    { type: EqualityHelperService },
    { type: TokenHelperService },
    { type: LoggerService }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class StateValidationService {
    /**
     * @param {?} authConfiguration
     * @param {?} oidcSecurityCommon
     * @param {?} oidcSecurityValidation
     * @param {?} tokenHelperService
     * @param {?} loggerService
     */
    constructor(authConfiguration, oidcSecurityCommon, oidcSecurityValidation, tokenHelperService, loggerService) {
        this.authConfiguration = authConfiguration;
        this.oidcSecurityCommon = oidcSecurityCommon;
        this.oidcSecurityValidation = oidcSecurityValidation;
        this.tokenHelperService = tokenHelperService;
        this.loggerService = loggerService;
        this.authWellKnownEndpoints = new AuthWellKnownEndpoints();
    }
    /**
     * @param {?} authWellKnownEndpoints
     * @return {?}
     */
    setupModule(authWellKnownEndpoints) {
        this.authWellKnownEndpoints = Object.assign({}, authWellKnownEndpoints);
    }
    /**
     * @param {?} result
     * @param {?} jwtKeys
     * @return {?}
     */
    validateState(result, jwtKeys) {
        /** @type {?} */
        const toReturn = new ValidateStateResult();
        if (!this.oidcSecurityValidation.validateStateFromHashCallback(result.state, this.oidcSecurityCommon.authStateControl)) {
            this.loggerService.logWarning('authorizedCallback incorrect state');
            toReturn.state = ValidationResult.StatesDoNotMatch;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (this.authConfiguration.response_type === 'id_token token' || this.authConfiguration.response_type === 'code') {
            toReturn.access_token = result.access_token;
        }
        toReturn.id_token = result.id_token;
        toReturn.decoded_id_token = this.tokenHelperService.getPayloadFromToken(toReturn.id_token, false);
        if (!this.oidcSecurityValidation.validate_signature_id_token(toReturn.id_token, jwtKeys)) {
            this.loggerService.logDebug('authorizedCallback Signature validation failed id_token');
            toReturn.state = ValidationResult.SignatureFailed;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_id_token_nonce(toReturn.decoded_id_token, this.oidcSecurityCommon.authNonce)) {
            this.loggerService.logWarning('authorizedCallback incorrect nonce');
            toReturn.state = ValidationResult.IncorrectNonce;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_required_id_token(toReturn.decoded_id_token)) {
            this.loggerService.logDebug('authorizedCallback Validation, one of the REQUIRED properties missing from id_token');
            toReturn.state = ValidationResult.RequiredPropertyMissing;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_id_token_iat_max_offset(toReturn.decoded_id_token, this.authConfiguration.max_id_token_iat_offset_allowed_in_seconds, this.authConfiguration.disable_iat_offset_validation)) {
            this.loggerService.logWarning('authorizedCallback Validation, iat rejected id_token was issued too far away from the current time');
            toReturn.state = ValidationResult.MaxOffsetExpired;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (this.authWellKnownEndpoints) {
            if (this.authConfiguration.iss_validation_off) {
                this.loggerService.logDebug('iss validation is turned off, this is not recommended!');
            }
            else if (!this.authConfiguration.iss_validation_off &&
                !this.oidcSecurityValidation.validate_id_token_iss(toReturn.decoded_id_token, this.authWellKnownEndpoints.issuer)) {
                this.loggerService.logWarning('authorizedCallback incorrect iss does not match authWellKnownEndpoints issuer');
                toReturn.state = ValidationResult.IssDoesNotMatchIssuer;
                this.handleUnsuccessfulValidation();
                return toReturn;
            }
        }
        else {
            this.loggerService.logWarning('authWellKnownEndpoints is undefined');
            toReturn.state = ValidationResult.NoAuthWellKnownEndPoints;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_id_token_aud(toReturn.decoded_id_token, this.authConfiguration.client_id)) {
            this.loggerService.logWarning('authorizedCallback incorrect aud');
            toReturn.state = ValidationResult.IncorrectAud;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_id_token_exp_not_expired(toReturn.decoded_id_token)) {
            this.loggerService.logWarning('authorizedCallback token expired');
            toReturn.state = ValidationResult.TokenExpired;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        // flow id_token token
        if (this.authConfiguration.response_type !== 'id_token token' && this.authConfiguration.response_type !== 'code') {
            toReturn.authResponseIsValid = true;
            toReturn.state = ValidationResult.Ok;
            this.handleSuccessfulValidation();
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_id_token_at_hash(toReturn.access_token, toReturn.decoded_id_token.at_hash, this.authConfiguration.response_type === 'code') ||
            !toReturn.access_token) {
            this.loggerService.logWarning('authorizedCallback incorrect at_hash');
            toReturn.state = ValidationResult.IncorrectAtHash;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        toReturn.authResponseIsValid = true;
        toReturn.state = ValidationResult.Ok;
        this.handleSuccessfulValidation();
        return toReturn;
    }
    /**
     * @private
     * @return {?}
     */
    handleSuccessfulValidation() {
        this.oidcSecurityCommon.authNonce = '';
        if (this.authConfiguration.auto_clean_state_after_authentication) {
            this.oidcSecurityCommon.authStateControl = '';
        }
        this.loggerService.logDebug('AuthorizedCallback token(s) validated, continue');
    }
    /**
     * @private
     * @return {?}
     */
    handleUnsuccessfulValidation() {
        this.oidcSecurityCommon.authNonce = '';
        if (this.authConfiguration.auto_clean_state_after_authentication) {
            this.oidcSecurityCommon.authStateControl = '';
        }
        this.loggerService.logDebug('AuthorizedCallback token(s) invalid');
    }
}
StateValidationService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
StateValidationService.ctorParameters = () => [
    { type: AuthConfiguration },
    { type: OidcSecurityCommon },
    { type: OidcSecurityValidation },
    { type: TokenHelperService },
    { type: LoggerService }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/** @type {?} */
const IFRAME_FOR_CHECK_SESSION_IDENTIFIER = 'myiFrameForCheckSession';
// http://openid.net/specs/openid-connect-session-1_0-ID4.html
class OidcSecurityCheckSession {
    /**
     * @param {?} authConfiguration
     * @param {?} oidcSecurityCommon
     * @param {?} loggerService
     * @param {?} iFrameService
     * @param {?} zone
     */
    constructor(authConfiguration, oidcSecurityCommon, loggerService, iFrameService, zone) {
        this.authConfiguration = authConfiguration;
        this.oidcSecurityCommon = oidcSecurityCommon;
        this.loggerService = loggerService;
        this.iFrameService = iFrameService;
        this.zone = zone;
        this.lastIFrameRefresh = 0;
        this.outstandingMessages = 0;
        this.heartBeatInterval = 3000;
        this.iframeRefreshInterval = 60000;
        this._onCheckSessionChanged = new Subject();
    }
    /**
     * @return {?}
     */
    get onCheckSessionChanged() {
        return this._onCheckSessionChanged.asObservable();
    }
    /**
     * @param {?} authWellKnownEndpoints
     * @return {?}
     */
    setupModule(authWellKnownEndpoints) {
        this.authWellKnownEndpoints = Object.assign({}, authWellKnownEndpoints);
    }
    /**
     * @private
     * @return {?}
     */
    doesSessionExist() {
        /** @type {?} */
        const existingIFrame = this.iFrameService.getExistingIFrame(IFRAME_FOR_CHECK_SESSION_IDENTIFIER);
        if (!existingIFrame) {
            return false;
        }
        this.sessionIframe = existingIFrame;
        return true;
    }
    /**
     * @private
     * @return {?}
     */
    init() {
        if (this.lastIFrameRefresh + this.iframeRefreshInterval > Date.now()) {
            return from([this]);
        }
        if (!this.doesSessionExist()) {
            this.sessionIframe = this.iFrameService.addIFrameToWindowBody(IFRAME_FOR_CHECK_SESSION_IDENTIFIER);
            this.iframeMessageEvent = this.messageHandler.bind(this);
            window.addEventListener('message', this.iframeMessageEvent, false);
        }
        if (this.authWellKnownEndpoints) {
            this.sessionIframe.contentWindow.location.replace(this.authWellKnownEndpoints.check_session_iframe);
        }
        else {
            this.loggerService.logWarning('init check session: authWellKnownEndpoints is undefined');
        }
        return Observable.create((/**
         * @param {?} observer
         * @return {?}
         */
        (observer) => {
            this.sessionIframe.onload = (/**
             * @return {?}
             */
            () => {
                this.lastIFrameRefresh = Date.now();
                observer.next(this);
                observer.complete();
            });
        }));
    }
    /**
     * @param {?} clientId
     * @return {?}
     */
    startCheckingSession(clientId) {
        if (this.scheduledHeartBeat) {
            return;
        }
        this.pollServerSession(clientId);
    }
    /**
     * @return {?}
     */
    stopCheckingSession() {
        if (!this.scheduledHeartBeat) {
            return;
        }
        this.clearScheduledHeartBeat();
    }
    /**
     * @private
     * @param {?} clientId
     * @return {?}
     */
    pollServerSession(clientId) {
        /** @type {?} */
        const _pollServerSessionRecur = (/**
         * @return {?}
         */
        () => {
            this.init()
                .pipe(take(1))
                .subscribe((/**
             * @return {?}
             */
            () => {
                if (this.sessionIframe && clientId) {
                    this.loggerService.logDebug(this.sessionIframe);
                    /** @type {?} */
                    const session_state = this.oidcSecurityCommon.sessionState;
                    if (session_state) {
                        this.outstandingMessages++;
                        this.sessionIframe.contentWindow.postMessage(clientId + ' ' + session_state, this.authConfiguration.stsServer);
                    }
                    else {
                        this.loggerService.logDebug('OidcSecurityCheckSession pollServerSession session_state is blank');
                        this._onCheckSessionChanged.next();
                    }
                }
                else {
                    this.loggerService.logWarning('OidcSecurityCheckSession pollServerSession sessionIframe does not exist');
                    this.loggerService.logDebug(clientId);
                    this.loggerService.logDebug(this.sessionIframe);
                    // this.init();
                }
                // after sending three messages with no response, fail.
                if (this.outstandingMessages > 3) {
                    this.loggerService.logError(`OidcSecurityCheckSession not receiving check session response messages. Outstanding messages: ${this.outstandingMessages}. Server unreachable?`);
                    this._onCheckSessionChanged.next();
                }
                this.scheduledHeartBeat = setTimeout(_pollServerSessionRecur, this.heartBeatInterval);
            }));
        });
        this.outstandingMessages = 0;
        this.zone.runOutsideAngular((/**
         * @return {?}
         */
        () => {
            this.scheduledHeartBeat = setTimeout(_pollServerSessionRecur, this.heartBeatInterval);
        }));
    }
    /**
     * @private
     * @return {?}
     */
    clearScheduledHeartBeat() {
        clearTimeout(this.scheduledHeartBeat);
        this.scheduledHeartBeat = null;
    }
    /**
     * @private
     * @param {?} e
     * @return {?}
     */
    messageHandler(e) {
        this.outstandingMessages = 0;
        if (this.sessionIframe && e.origin === this.authConfiguration.stsServer && e.source === this.sessionIframe.contentWindow) {
            if (e.data === 'error') {
                this.loggerService.logWarning('error from checksession messageHandler');
            }
            else if (e.data === 'changed') {
                this._onCheckSessionChanged.next();
            }
            else {
                this.loggerService.logDebug(e.data + ' from checksession messageHandler');
            }
        }
    }
}
OidcSecurityCheckSession.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcSecurityCheckSession.ctorParameters = () => [
    { type: AuthConfiguration },
    { type: OidcSecurityCommon },
    { type: LoggerService },
    { type: IFrameService },
    { type: NgZone }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class OidcConfigService {
    /**
     * @param {?} httpClient
     */
    constructor(httpClient) {
        this.httpClient = httpClient;
        this._onConfigurationLoaded = new Subject();
    }
    /**
     * @return {?}
     */
    get onConfigurationLoaded() {
        return this._onConfigurationLoaded.asObservable();
    }
    /**
     * @param {?} configUrl
     * @return {?}
     */
    load(configUrl) {
        this.httpClient
            .get(configUrl)
            .pipe(map((/**
         * @param {?} response
         * @return {?}
         */
        response => {
            this.clientConfiguration = response;
            this.load_using_stsServer(this.clientConfiguration.stsServer);
        })), catchError((/**
         * @param {?} error
         * @return {?}
         */
        error => {
            console.error(`OidcConfigService 'load' threw an error on calling ${configUrl}`, error);
            this._onConfigurationLoaded.next(false);
            return of(false);
        })))
            .subscribe();
    }
    /**
     * @param {?} stsServer
     * @return {?}
     */
    load_using_stsServer(stsServer) {
        /** @type {?} */
        const url = `${stsServer}/.well-known/openid-configuration`;
        this.httpClient
            .get(url)
            .pipe(map((/**
         * @param {?} response
         * @return {?}
         */
        response => {
            this.wellKnownEndpoints = response;
            this._onConfigurationLoaded.next(true);
        })), catchError((/**
         * @param {?} error
         * @return {?}
         */
        error => {
            console.error(`OidcConfigService 'load_using_stsServer' threw an error on calling ${stsServer}`, error);
            this._onConfigurationLoaded.next(false);
            return of(false);
        })))
            .subscribe();
    }
    /**
     * @param {?} url
     * @return {?}
     */
    load_using_custom_stsServer(url) {
        this.httpClient
            .get(url)
            .pipe(map((/**
         * @param {?} response
         * @return {?}
         */
        response => {
            this.wellKnownEndpoints = response;
            this._onConfigurationLoaded.next(true);
        })), catchError((/**
         * @param {?} error
         * @return {?}
         */
        error => {
            console.error(`OidcConfigService 'load_using_custom_stsServer' threw an error on calling ${url}`, error);
            this._onConfigurationLoaded.next(false);
            return of(false);
        })))
            .subscribe();
    }
}
OidcConfigService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcConfigService.ctorParameters = () => [
    { type: HttpClient }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/** @type {?} */
const IFRAME_FOR_SILENT_RENEW_IDENTIFIER = 'myiFrameForSilentRenew';
class OidcSecuritySilentRenew {
    /**
     * @param {?} loggerService
     * @param {?} iFrameService
     */
    constructor(loggerService, iFrameService) {
        this.loggerService = loggerService;
        this.iFrameService = iFrameService;
        this.isRenewInitialized = false;
    }
    /**
     * @return {?}
     */
    initRenew() {
        /** @type {?} */
        const existingIFrame = this.iFrameService.getExistingIFrame(IFRAME_FOR_SILENT_RENEW_IDENTIFIER);
        if (!existingIFrame) {
            this.iFrameService.addIFrameToWindowBody(IFRAME_FOR_SILENT_RENEW_IDENTIFIER);
        }
        this.isRenewInitialized = true;
    }
    /**
     * @param {?} url
     * @return {?}
     */
    startRenew(url) {
        if (!this.isRenewInitialized) {
            this.initRenew();
        }
        this.sessionIframe = this.iFrameService.getExistingIFrame(IFRAME_FOR_SILENT_RENEW_IDENTIFIER);
        this.loggerService.logDebug('startRenew for URL:' + url);
        this.sessionIframe.contentWindow.location.replace(url);
        return Observable.create((/**
         * @param {?} observer
         * @return {?}
         */
        (observer) => {
            this.sessionIframe.onload = (/**
             * @return {?}
             */
            () => {
                observer.next(this);
                observer.complete();
            });
        }));
    }
}
OidcSecuritySilentRenew.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcSecuritySilentRenew.ctorParameters = () => [
    { type: LoggerService },
    { type: IFrameService }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class OidcSecurityUserService {
    /**
     * @param {?} oidcDataService
     * @param {?} oidcSecurityCommon
     * @param {?} loggerService
     */
    constructor(oidcDataService, oidcSecurityCommon, loggerService) {
        this.oidcDataService = oidcDataService;
        this.oidcSecurityCommon = oidcSecurityCommon;
        this.loggerService = loggerService;
        this.userData = '';
    }
    /**
     * @param {?} authWellKnownEndpoints
     * @return {?}
     */
    setupModule(authWellKnownEndpoints) {
        this.authWellKnownEndpoints = Object.assign({}, authWellKnownEndpoints);
    }
    /**
     * @return {?}
     */
    initUserData() {
        return this.getIdentityUserData().pipe(map((/**
         * @param {?} data
         * @return {?}
         */
        (data) => (this.userData = data))));
    }
    /**
     * @return {?}
     */
    getUserData() {
        if (!this.userData) {
            throw Error('UserData is not set!');
        }
        return this.userData;
    }
    /**
     * @param {?} value
     * @return {?}
     */
    setUserData(value) {
        this.userData = value;
    }
    /**
     * @private
     * @return {?}
     */
    getIdentityUserData() {
        /** @type {?} */
        const token = this.oidcSecurityCommon.getAccessToken();
        if (!this.authWellKnownEndpoints) {
            this.loggerService.logWarning('init check session: authWellKnownEndpoints is undefined');
            throw Error('authWellKnownEndpoints is undefined');
        }
        /** @type {?} */
        const canGetUserData = this.authWellKnownEndpoints && this.authWellKnownEndpoints.userinfo_endpoint;
        if (!canGetUserData) {
            this.loggerService.logError('init check session: authWellKnownEndpoints.userinfo_endpoint is undefined; set auto_userinfo = false in config');
            throw Error('authWellKnownEndpoints.userinfo_endpoint is undefined');
        }
        return this.oidcDataService.getIdentityUserData(this.authWellKnownEndpoints.userinfo_endpoint, token);
    }
}
OidcSecurityUserService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcSecurityUserService.ctorParameters = () => [
    { type: OidcDataService },
    { type: OidcSecurityCommon },
    { type: LoggerService }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class UriEncoder {
    /**
     * @param {?} key
     * @return {?}
     */
    encodeKey(key) {
        return encodeURIComponent(key);
    }
    /**
     * @param {?} value
     * @return {?}
     */
    encodeValue(value) {
        return encodeURIComponent(value);
    }
    /**
     * @param {?} key
     * @return {?}
     */
    decodeKey(key) {
        return decodeURIComponent(key);
    }
    /**
     * @param {?} value
     * @return {?}
     */
    decodeValue(value) {
        return decodeURIComponent(value);
    }
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class OidcSecurityService {
    /**
     * @param {?} oidcDataService
     * @param {?} stateValidationService
     * @param {?} authConfiguration
     * @param {?} router
     * @param {?} oidcSecurityCheckSession
     * @param {?} oidcSecuritySilentRenew
     * @param {?} oidcSecurityUserService
     * @param {?} oidcSecurityCommon
     * @param {?} oidcSecurityValidation
     * @param {?} tokenHelperService
     * @param {?} loggerService
     * @param {?} zone
     * @param {?} httpClient
     */
    constructor(oidcDataService, stateValidationService, authConfiguration, router, oidcSecurityCheckSession, oidcSecuritySilentRenew, oidcSecurityUserService, oidcSecurityCommon, oidcSecurityValidation, tokenHelperService, loggerService, zone, httpClient) {
        this.oidcDataService = oidcDataService;
        this.stateValidationService = stateValidationService;
        this.authConfiguration = authConfiguration;
        this.router = router;
        this.oidcSecurityCheckSession = oidcSecurityCheckSession;
        this.oidcSecuritySilentRenew = oidcSecuritySilentRenew;
        this.oidcSecurityUserService = oidcSecurityUserService;
        this.oidcSecurityCommon = oidcSecurityCommon;
        this.oidcSecurityValidation = oidcSecurityValidation;
        this.tokenHelperService = tokenHelperService;
        this.loggerService = loggerService;
        this.zone = zone;
        this.httpClient = httpClient;
        this._onModuleSetup = new Subject();
        this._onCheckSessionChanged = new Subject();
        this._onAuthorizationResult = new Subject();
        this.checkSessionChanged = false;
        this.moduleSetup = false;
        this._isModuleSetup = new BehaviorSubject(false);
        this._isAuthorized = new BehaviorSubject(false);
        this._userData = new BehaviorSubject('');
        this.authWellKnownEndpointsLoaded = false;
        this.runTokenValidationRunning = false;
        this.onModuleSetup.pipe(take(1)).subscribe((/**
         * @return {?}
         */
        () => {
            this.moduleSetup = true;
            this._isModuleSetup.next(true);
        }));
        this._isSetupAndAuthorized = this._isModuleSetup.pipe(filter((/**
         * @param {?} isModuleSetup
         * @return {?}
         */
        (isModuleSetup) => isModuleSetup)), switchMap((/**
         * @return {?}
         */
        () => {
            if (!this.authConfiguration.silent_renew) {
                return from([true]).pipe(tap((/**
                 * @return {?}
                 */
                () => this.loggerService.logDebug(`IsAuthorizedRace: Silent Renew Not Active. Emitting.`))));
            }
            /** @type {?} */
            const race$ = this._isAuthorized.asObservable().pipe(filter((/**
             * @param {?} isAuthorized
             * @return {?}
             */
            (isAuthorized) => isAuthorized)), take(1), tap((/**
             * @return {?}
             */
            () => this.loggerService.logDebug('IsAuthorizedRace: Existing token is still authorized.'))), race(this._onAuthorizationResult.pipe(take(1), tap((/**
             * @return {?}
             */
            () => this.loggerService.logDebug('IsAuthorizedRace: Silent Renew Refresh Session Complete'))), map((/**
             * @return {?}
             */
            () => true))), timer(5000).pipe(
            // backup, if nothing happens after 5 seconds stop waiting and emit
            tap((/**
             * @return {?}
             */
            () => {
                this.resetAuthorizationData(false);
                this.oidcSecurityCommon.authNonce = '';
                this.loggerService.logWarning('IsAuthorizedRace: Timeout reached. Emitting.');
            })), map((/**
             * @return {?}
             */
            () => true)))));
            this.loggerService.logDebug('Silent Renew is active, check if token in storage is active');
            if (this.oidcSecurityCommon.authNonce === '' || this.oidcSecurityCommon.authNonce === undefined) {
                // login not running, or a second silent renew, user must login first before this will work.
                this.loggerService.logDebug('Silent Renew or login not running, try to refresh the session');
                this.refreshSession();
            }
            return race$;
        })), tap((/**
         * @return {?}
         */
        () => this.loggerService.logDebug('IsAuthorizedRace: Completed'))), switchMapTo(this._isAuthorized.asObservable()), tap((/**
         * @param {?} isAuthorized
         * @return {?}
         */
        (isAuthorized) => this.loggerService.logDebug(`getIsAuthorized: ${isAuthorized}`))), shareReplay(1));
        this._isSetupAndAuthorized.pipe(filter((/**
         * @return {?}
         */
        () => this.authConfiguration.start_checksession))).subscribe((/**
         * @param {?} isSetupAndAuthorized
         * @return {?}
         */
        isSetupAndAuthorized => {
            if (isSetupAndAuthorized) {
                this.oidcSecurityCheckSession.startCheckingSession(this.authConfiguration.client_id);
            }
            else {
                this.oidcSecurityCheckSession.stopCheckingSession();
            }
        }));
    }
    /**
     * @return {?}
     */
    get onModuleSetup() {
        return this._onModuleSetup.asObservable();
    }
    /**
     * @return {?}
     */
    get onAuthorizationResult() {
        return this._onAuthorizationResult.asObservable();
    }
    /**
     * @return {?}
     */
    get onCheckSessionChanged() {
        return this._onCheckSessionChanged.asObservable();
    }
    /**
     * @return {?}
     */
    get onConfigurationChange() {
        return this.authConfiguration.onConfigurationChange;
    }
    /**
     * @param {?} openIDImplicitFlowConfiguration
     * @param {?} authWellKnownEndpoints
     * @return {?}
     */
    setupModule(openIDImplicitFlowConfiguration, authWellKnownEndpoints) {
        this.authWellKnownEndpoints = Object.assign({}, authWellKnownEndpoints);
        this.authConfiguration.init(openIDImplicitFlowConfiguration);
        this.stateValidationService.setupModule(authWellKnownEndpoints);
        this.oidcSecurityCheckSession.setupModule(authWellKnownEndpoints);
        this.oidcSecurityUserService.setupModule(authWellKnownEndpoints);
        this.oidcSecurityCheckSession.onCheckSessionChanged.subscribe((/**
         * @return {?}
         */
        () => {
            this.loggerService.logDebug('onCheckSessionChanged');
            this.checkSessionChanged = true;
            this._onCheckSessionChanged.next(this.checkSessionChanged);
        }));
        /** @type {?} */
        const userData = this.oidcSecurityCommon.userData;
        if (userData) {
            this.setUserData(userData);
        }
        /** @type {?} */
        const isAuthorized = this.oidcSecurityCommon.isAuthorized;
        if (isAuthorized) {
            this.loggerService.logDebug('IsAuthorized setup module');
            this.loggerService.logDebug(this.oidcSecurityCommon.idToken);
            if (this.oidcSecurityValidation.isTokenExpired(this.oidcSecurityCommon.idToken, this.authConfiguration.silent_renew_offset_in_seconds)) {
                this.loggerService.logDebug('IsAuthorized setup module; id_token isTokenExpired');
            }
            else {
                this.loggerService.logDebug('IsAuthorized setup module; id_token is valid');
                this.setIsAuthorized(isAuthorized);
            }
            this.runTokenValidation();
        }
        this.loggerService.logDebug('STS server: ' + this.authConfiguration.stsServer);
        this._onModuleSetup.next();
        if (this.authConfiguration.silent_renew) {
            this.oidcSecuritySilentRenew.initRenew();
            // Support authorization via DOM events.
            // Deregister if OidcSecurityService.setupModule is called again by any instance.
            //      We only ever want the latest setup service to be reacting to this event.
            this.boundSilentRenewEvent = this.silentRenewEventHandler.bind(this);
            /** @type {?} */
            const instanceId = Math.random();
            /** @type {?} */
            const boundSilentRenewInitEvent = ((/**
             * @param {?} e
             * @return {?}
             */
            (e) => {
                if (e.detail !== instanceId) {
                    window.removeEventListener('oidc-silent-renew-message', this.boundSilentRenewEvent);
                    window.removeEventListener('oidc-silent-renew-init', boundSilentRenewInitEvent);
                }
            })).bind(this);
            window.addEventListener('oidc-silent-renew-init', boundSilentRenewInitEvent, false);
            window.addEventListener('oidc-silent-renew-message', this.boundSilentRenewEvent, false);
            window.dispatchEvent(new CustomEvent('oidc-silent-renew-init', {
                detail: instanceId,
            }));
        }
    }
    /**
     * @return {?}
     */
    getUserData() {
        return this._userData.asObservable();
    }
    /**
     * @return {?}
     */
    getIsModuleSetup() {
        return this._isModuleSetup.asObservable();
    }
    /**
     * @return {?}
     */
    getIsAuthorized() {
        return this._isSetupAndAuthorized;
    }
    /**
     * @return {?}
     */
    getToken() {
        if (!this._isAuthorized.getValue()) {
            return '';
        }
        /** @type {?} */
        const token = this.oidcSecurityCommon.getAccessToken();
        return decodeURIComponent(token);
    }
    /**
     * @return {?}
     */
    getIdToken() {
        if (!this._isAuthorized.getValue()) {
            return '';
        }
        /** @type {?} */
        const token = this.oidcSecurityCommon.getIdToken();
        return decodeURIComponent(token);
    }
    /**
     * @param {?=} encode
     * @return {?}
     */
    getPayloadFromIdToken(encode = false) {
        /** @type {?} */
        const token = this.getIdToken();
        return this.tokenHelperService.getPayloadFromToken(token, encode);
    }
    /**
     * @param {?} state
     * @return {?}
     */
    setState(state) {
        this.oidcSecurityCommon.authStateControl = state;
    }
    /**
     * @return {?}
     */
    getState() {
        return this.oidcSecurityCommon.authStateControl;
    }
    /**
     * @param {?} params
     * @return {?}
     */
    setCustomRequestParameters(params) {
        this.oidcSecurityCommon.customRequestParams = params;
    }
    // Code Flow with PCKE or Implicit Flow
    /**
     * @param {?=} urlHandler
     * @return {?}
     */
    authorize(urlHandler) {
        if (this.authWellKnownEndpoints) {
            this.authWellKnownEndpointsLoaded = true;
        }
        if (!this.authWellKnownEndpointsLoaded) {
            this.loggerService.logError('Well known endpoints must be loaded before user can login!');
            return;
        }
        if (!this.oidcSecurityValidation.config_validate_response_type(this.authConfiguration.response_type)) {
            // invalid response_type
            return;
        }
        this.resetAuthorizationData(false);
        this.loggerService.logDebug('BEGIN Authorize Code Flow, no auth data');
        /** @type {?} */
        let state = this.oidcSecurityCommon.authStateControl;
        if (!state) {
            state = Date.now() + '' + Math.random() + Math.random();
            this.oidcSecurityCommon.authStateControl = state;
        }
        /** @type {?} */
        const nonce = 'N' + Math.random() + '' + Date.now();
        this.oidcSecurityCommon.authNonce = nonce;
        this.loggerService.logDebug('AuthorizedController created. local state: ' + this.oidcSecurityCommon.authStateControl);
        /** @type {?} */
        let url = '';
        // Code Flow
        if (this.authConfiguration.response_type === 'code') {
            // code_challenge with "S256"
            /** @type {?} */
            const code_verifier = 'C' + Math.random() + '' + Date.now() + '' + Date.now() + Math.random();
            /** @type {?} */
            const code_challenge = this.oidcSecurityValidation.generate_code_verifier(code_verifier);
            this.oidcSecurityCommon.code_verifier = code_verifier;
            if (this.authWellKnownEndpoints) {
                url = this.createAuthorizeUrl(true, code_challenge, this.authConfiguration.redirect_url, nonce, state, this.authWellKnownEndpoints.authorization_endpoint);
            }
            else {
                this.loggerService.logError('authWellKnownEndpoints is undefined');
            }
        }
        else { // Implicit Flow
            if (this.authWellKnownEndpoints) {
                url = this.createAuthorizeUrl(false, '', this.authConfiguration.redirect_url, nonce, state, this.authWellKnownEndpoints.authorization_endpoint);
            }
            else {
                this.loggerService.logError('authWellKnownEndpoints is undefined');
            }
        }
        if (urlHandler) {
            urlHandler(url);
        }
        else {
            this.redirectTo(url);
        }
    }
    // Code Flow
    /**
     * @param {?} urlToCheck
     * @return {?}
     */
    authorizedCallbackWithCode(urlToCheck) {
        /** @type {?} */
        const urlParts = urlToCheck.split('?');
        /** @type {?} */
        const params = new HttpParams({
            fromString: urlParts[1]
        });
        /** @type {?} */
        const code = params.get('code');
        /** @type {?} */
        const state = params.get('state');
        /** @type {?} */
        const session_state = params.get('session_state');
        if (code && state) {
            this.requestTokensWithCode(code, state, session_state);
        }
    }
    // Code Flow
    /**
     * @param {?} code
     * @param {?} state
     * @param {?} session_state
     * @return {?}
     */
    requestTokensWithCode(code, state, session_state) {
        this._isModuleSetup
            .pipe(filter((/**
         * @param {?} isModuleSetup
         * @return {?}
         */
        (isModuleSetup) => isModuleSetup)), take(1))
            .subscribe((/**
         * @return {?}
         */
        () => {
            this.requestTokensWithCodeProcedure(code, state, session_state);
        }));
    }
    // Code Flow with PCKE
    /**
     * @param {?} code
     * @param {?} state
     * @param {?} session_state
     * @return {?}
     */
    requestTokensWithCodeProcedure(code, state, session_state) {
        /** @type {?} */
        let tokenRequestUrl = '';
        if (this.authWellKnownEndpoints && this.authWellKnownEndpoints.token_endpoint) {
            tokenRequestUrl = `${this.authWellKnownEndpoints.token_endpoint}`;
        }
        if (!this.oidcSecurityValidation.validateStateFromHashCallback(state, this.oidcSecurityCommon.authStateControl)) {
            this.loggerService.logWarning('authorizedCallback incorrect state');
            // ValidationResult.StatesDoNotMatch;
            return;
        }
        /** @type {?} */
        let headers = new HttpHeaders();
        headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
        /** @type {?} */
        let data = `grant_type=authorization_code&client_id=${this.authConfiguration.client_id}`
            + `&code_verifier=${this.oidcSecurityCommon.code_verifier}&code=${code}&redirect_uri=${this.authConfiguration.redirect_url}`;
        if (this.oidcSecurityCommon.silentRenewRunning === 'running') {
            data = `grant_type=authorization_code&client_id=${this.authConfiguration.client_id}`
                + `&code_verifier=${this.oidcSecurityCommon.code_verifier}&code=${code}&redirect_uri=${this.authConfiguration.silent_redirect_url}`;
        }
        this.httpClient
            .post(tokenRequestUrl, data, { headers: headers })
            .pipe(map((/**
         * @param {?} response
         * @return {?}
         */
        response => {
            /** @type {?} */
            let obj = new Object;
            obj = response;
            obj.state = state;
            obj.session_state = session_state;
            this.authorizedCodeFlowCallbackProcedure(obj);
        })), catchError((/**
         * @param {?} error
         * @return {?}
         */
        error => {
            this.loggerService.logError(error);
            this.loggerService.logError(`OidcService code request ${this.authConfiguration.stsServer}`);
            return of(false);
        })))
            .subscribe();
    }
    // Code Flow
    /**
     * @private
     * @param {?} result
     * @return {?}
     */
    authorizedCodeFlowCallbackProcedure(result) {
        /** @type {?} */
        const silentRenew = this.oidcSecurityCommon.silentRenewRunning;
        /** @type {?} */
        const isRenewProcess = silentRenew === 'running';
        this.loggerService.logDebug('BEGIN authorized Code Flow Callback, no auth data');
        this.resetAuthorizationData(isRenewProcess);
        this.authorizedCallbackProcedure(result, isRenewProcess);
    }
    // Implicit Flow
    /**
     * @private
     * @param {?=} hash
     * @return {?}
     */
    authorizedImplicitFlowCallbackProcedure(hash) {
        /** @type {?} */
        const silentRenew = this.oidcSecurityCommon.silentRenewRunning;
        /** @type {?} */
        const isRenewProcess = silentRenew === 'running';
        this.loggerService.logDebug('BEGIN authorizedCallback, no auth data');
        this.resetAuthorizationData(isRenewProcess);
        hash = hash || window.location.hash.substr(1);
        /** @type {?} */
        const result = hash.split('&').reduce((/**
         * @param {?} resultData
         * @param {?} item
         * @return {?}
         */
        function (resultData, item) {
            /** @type {?} */
            const parts = item.split('=');
            resultData[(/** @type {?} */ (parts.shift()))] = parts.join('=');
            return resultData;
        }), {});
        this.authorizedCallbackProcedure(result, isRenewProcess);
    }
    // Implicit Flow
    /**
     * @param {?=} hash
     * @return {?}
     */
    authorizedImplicitFlowCallback(hash) {
        this._isModuleSetup
            .pipe(filter((/**
         * @param {?} isModuleSetup
         * @return {?}
         */
        (isModuleSetup) => isModuleSetup)), take(1))
            .subscribe((/**
         * @return {?}
         */
        () => {
            this.authorizedImplicitFlowCallbackProcedure(hash);
        }));
    }
    /**
     * @private
     * @param {?} url
     * @return {?}
     */
    redirectTo(url) {
        window.location.href = url;
    }
    // Implicit Flow
    /**
     * @private
     * @param {?} result
     * @param {?} isRenewProcess
     * @return {?}
     */
    authorizedCallbackProcedure(result, isRenewProcess) {
        this.oidcSecurityCommon.authResult = result;
        if (!this.authConfiguration.history_cleanup_off && !isRenewProcess) {
            // reset the history to remove the tokens
            window.history.replaceState({}, window.document.title, window.location.origin + window.location.pathname);
        }
        else {
            this.loggerService.logDebug('history clean up inactive');
        }
        if (result.error) {
            if (isRenewProcess) {
                this.loggerService.logDebug(result);
            }
            else {
                this.loggerService.logWarning(result);
            }
            if (((/** @type {?} */ (result.error))) === 'login_required') {
                this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.unauthorized, ValidationResult.LoginRequired));
            }
            else {
                this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.unauthorized, ValidationResult.SecureTokenServerError));
            }
            this.resetAuthorizationData(false);
            this.oidcSecurityCommon.authNonce = '';
            if (!this.authConfiguration.trigger_authorization_result_event && !isRenewProcess) {
                this.router.navigate([this.authConfiguration.unauthorized_route]);
            }
        }
        else {
            this.loggerService.logDebug(result);
            this.loggerService.logDebug('authorizedCallback created, begin token validation');
            this.getSigningKeys().subscribe((/**
             * @param {?} jwtKeys
             * @return {?}
             */
            jwtKeys => {
                /** @type {?} */
                const validationResult = this.getValidatedStateResult(result, jwtKeys);
                if (validationResult.authResponseIsValid) {
                    this.setAuthorizationData(validationResult.access_token, validationResult.id_token);
                    this.oidcSecurityCommon.silentRenewRunning = '';
                    if (this.authConfiguration.auto_userinfo) {
                        this.getUserinfo(isRenewProcess, result, validationResult.id_token, validationResult.decoded_id_token).subscribe((/**
                         * @param {?} response
                         * @return {?}
                         */
                        response => {
                            if (response) {
                                this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.authorized, validationResult.state));
                                if (!this.authConfiguration.trigger_authorization_result_event && !isRenewProcess) {
                                    this.router.navigate([this.authConfiguration.post_login_route]);
                                }
                            }
                            else {
                                this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.unauthorized, validationResult.state));
                                if (!this.authConfiguration.trigger_authorization_result_event && !isRenewProcess) {
                                    this.router.navigate([this.authConfiguration.unauthorized_route]);
                                }
                            }
                        }), (/**
                         * @param {?} err
                         * @return {?}
                         */
                        err => {
                            /* Something went wrong while getting signing key */
                            this.loggerService.logWarning('Failed to retreive user info with error: ' + JSON.stringify(err));
                        }));
                    }
                    else {
                        if (!isRenewProcess) {
                            // userData is set to the id_token decoded, auto get user data set to false
                            this.oidcSecurityUserService.setUserData(validationResult.decoded_id_token);
                            this.setUserData(this.oidcSecurityUserService.getUserData());
                        }
                        this.runTokenValidation();
                        this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.authorized, validationResult.state));
                        if (!this.authConfiguration.trigger_authorization_result_event && !isRenewProcess) {
                            this.router.navigate([this.authConfiguration.post_login_route]);
                        }
                    }
                }
                else {
                    // something went wrong
                    this.loggerService.logWarning('authorizedCallback, token(s) validation failed, resetting');
                    this.loggerService.logWarning(window.location.hash);
                    this.resetAuthorizationData(false);
                    this.oidcSecurityCommon.silentRenewRunning = '';
                    this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.unauthorized, validationResult.state));
                    if (!this.authConfiguration.trigger_authorization_result_event && !isRenewProcess) {
                        this.router.navigate([this.authConfiguration.unauthorized_route]);
                    }
                }
            }), (/**
             * @param {?} err
             * @return {?}
             */
            err => {
                /* Something went wrong while getting signing key */
                this.loggerService.logWarning('Failed to retreive siging key with error: ' + JSON.stringify(err));
                this.oidcSecurityCommon.silentRenewRunning = '';
            }));
        }
    }
    /**
     * @param {?=} isRenewProcess
     * @param {?=} result
     * @param {?=} id_token
     * @param {?=} decoded_id_token
     * @return {?}
     */
    getUserinfo(isRenewProcess = false, result, id_token, decoded_id_token) {
        result = result ? result : this.oidcSecurityCommon.authResult;
        id_token = id_token ? id_token : this.oidcSecurityCommon.idToken;
        decoded_id_token = decoded_id_token ? decoded_id_token : this.tokenHelperService.getPayloadFromToken(id_token, false);
        return new Observable((/**
         * @param {?} observer
         * @return {?}
         */
        observer => {
            // flow id_token token
            if (this.authConfiguration.response_type === 'id_token token' || this.authConfiguration.response_type === 'code') {
                if (isRenewProcess && this._userData.value) {
                    this.oidcSecurityCommon.sessionState = result.session_state;
                    observer.next(true);
                    observer.complete();
                }
                else {
                    this.oidcSecurityUserService.initUserData().subscribe((/**
                     * @return {?}
                     */
                    () => {
                        this.loggerService.logDebug('authorizedCallback (id_token token || code) flow');
                        /** @type {?} */
                        const userData = this.oidcSecurityUserService.getUserData();
                        if (this.oidcSecurityValidation.validate_userdata_sub_id_token(decoded_id_token.sub, userData.sub)) {
                            this.setUserData(userData);
                            this.loggerService.logDebug(this.oidcSecurityCommon.accessToken);
                            this.loggerService.logDebug(this.oidcSecurityUserService.getUserData());
                            this.oidcSecurityCommon.sessionState = result.session_state;
                            this.runTokenValidation();
                            observer.next(true);
                        }
                        else {
                            // something went wrong, userdata sub does not match that from id_token
                            this.loggerService.logWarning('authorizedCallback, User data sub does not match sub in id_token');
                            this.loggerService.logDebug('authorizedCallback, token(s) validation failed, resetting');
                            this.resetAuthorizationData(false);
                            observer.next(false);
                        }
                        observer.complete();
                    }));
                }
            }
            else {
                // flow id_token
                this.loggerService.logDebug('authorizedCallback id_token flow');
                this.loggerService.logDebug(this.oidcSecurityCommon.accessToken);
                // userData is set to the id_token decoded. No access_token.
                this.oidcSecurityUserService.setUserData(decoded_id_token);
                this.setUserData(this.oidcSecurityUserService.getUserData());
                this.oidcSecurityCommon.sessionState = result.session_state;
                this.runTokenValidation();
                observer.next(true);
                observer.complete();
            }
        }));
    }
    /**
     * @param {?=} urlHandler
     * @return {?}
     */
    logoff(urlHandler) {
        // /connect/endsession?id_token_hint=...&post_logout_redirect_uri=https://myapp.com
        this.loggerService.logDebug('BEGIN Authorize, no auth data');
        if (this.authWellKnownEndpoints) {
            if (this.authWellKnownEndpoints.end_session_endpoint) {
                /** @type {?} */
                const end_session_endpoint = this.authWellKnownEndpoints.end_session_endpoint;
                /** @type {?} */
                const id_token_hint = this.oidcSecurityCommon.idToken;
                /** @type {?} */
                const url = this.createEndSessionUrl(end_session_endpoint, id_token_hint);
                this.resetAuthorizationData(false);
                if (this.authConfiguration.start_checksession && this.checkSessionChanged) {
                    this.loggerService.logDebug('only local login cleaned up, server session has changed');
                }
                else if (urlHandler) {
                    urlHandler(url);
                }
                else {
                    this.redirectTo(url);
                }
            }
            else {
                this.resetAuthorizationData(false);
                this.loggerService.logDebug('only local login cleaned up, no end_session_endpoint');
            }
        }
        else {
            this.loggerService.logWarning('authWellKnownEndpoints is undefined');
        }
    }
    /**
     * @return {?}
     */
    refreshSession() {
        if (!this.authConfiguration.silent_renew) {
            return from([false]);
        }
        this.loggerService.logDebug('BEGIN refresh session Authorize');
        /** @type {?} */
        let state = this.oidcSecurityCommon.authStateControl;
        if (state === '' || state === null) {
            state = Date.now() + '' + Math.random() + Math.random();
            this.oidcSecurityCommon.authStateControl = state;
        }
        /** @type {?} */
        const nonce = 'N' + Math.random() + '' + Date.now();
        this.oidcSecurityCommon.authNonce = nonce;
        this.loggerService.logDebug('RefreshSession created. adding myautostate: ' + this.oidcSecurityCommon.authStateControl);
        /** @type {?} */
        let url = '';
        // Code Flow
        if (this.authConfiguration.response_type === 'code') {
            // code_challenge with "S256"
            /** @type {?} */
            const code_verifier = 'C' + Math.random() + '' + Date.now() + '' + Date.now() + Math.random();
            /** @type {?} */
            const code_challenge = this.oidcSecurityValidation.generate_code_verifier(code_verifier);
            this.oidcSecurityCommon.code_verifier = code_verifier;
            if (this.authWellKnownEndpoints) {
                url = this.createAuthorizeUrl(true, code_challenge, this.authConfiguration.silent_redirect_url, nonce, state, this.authWellKnownEndpoints.authorization_endpoint, 'none');
            }
            else {
                this.loggerService.logWarning('authWellKnownEndpoints is undefined');
            }
        }
        else {
            if (this.authWellKnownEndpoints) {
                url = this.createAuthorizeUrl(false, '', this.authConfiguration.silent_redirect_url, nonce, state, this.authWellKnownEndpoints.authorization_endpoint, 'none');
            }
            else {
                this.loggerService.logWarning('authWellKnownEndpoints is undefined');
            }
        }
        this.oidcSecurityCommon.silentRenewRunning = 'running';
        return this.oidcSecuritySilentRenew.startRenew(url);
    }
    /**
     * @param {?} error
     * @return {?}
     */
    handleError(error) {
        this.loggerService.logError(error);
        if (error.status === 403 || error.status === '403') {
            if (this.authConfiguration.trigger_authorization_result_event) {
                this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.unauthorized, ValidationResult.NotSet));
            }
            else {
                this.router.navigate([this.authConfiguration.forbidden_route]);
            }
        }
        else if (error.status === 401 || error.status === '401') {
            /** @type {?} */
            const silentRenew = this.oidcSecurityCommon.silentRenewRunning;
            this.resetAuthorizationData(!!silentRenew);
            if (this.authConfiguration.trigger_authorization_result_event) {
                this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.unauthorized, ValidationResult.NotSet));
            }
            else {
                this.router.navigate([this.authConfiguration.unauthorized_route]);
            }
        }
    }
    /**
     * @return {?}
     */
    startCheckingSilentRenew() {
        this.runTokenValidation();
    }
    /**
     * @return {?}
     */
    stopCheckingSilentRenew() {
        if (this._scheduledHeartBeat) {
            clearTimeout(this._scheduledHeartBeat);
            this._scheduledHeartBeat = null;
            this.runTokenValidationRunning = false;
        }
    }
    /**
     * @param {?} isRenewProcess
     * @return {?}
     */
    resetAuthorizationData(isRenewProcess) {
        if (!isRenewProcess) {
            if (this.authConfiguration.auto_userinfo) {
                // Clear user data. Fixes #97.
                this.setUserData('');
            }
            this.oidcSecurityCommon.resetStorageData(isRenewProcess);
            this.checkSessionChanged = false;
            this.setIsAuthorized(false);
        }
    }
    /**
     * @return {?}
     */
    getEndSessionUrl() {
        if (this.authWellKnownEndpoints) {
            if (this.authWellKnownEndpoints.end_session_endpoint) {
                /** @type {?} */
                const end_session_endpoint = this.authWellKnownEndpoints.end_session_endpoint;
                /** @type {?} */
                const id_token_hint = this.oidcSecurityCommon.idToken;
                return this.createEndSessionUrl(end_session_endpoint, id_token_hint);
            }
        }
    }
    /**
     * @private
     * @param {?} result
     * @param {?} jwtKeys
     * @return {?}
     */
    getValidatedStateResult(result, jwtKeys) {
        if (result.error) {
            return new ValidateStateResult('', '', false, {});
        }
        return this.stateValidationService.validateState(result, jwtKeys);
    }
    /**
     * @private
     * @param {?} userData
     * @return {?}
     */
    setUserData(userData) {
        this.oidcSecurityCommon.userData = userData;
        this._userData.next(userData);
    }
    /**
     * @private
     * @param {?} isAuthorized
     * @return {?}
     */
    setIsAuthorized(isAuthorized) {
        this._isAuthorized.next(isAuthorized);
    }
    /**
     * @private
     * @param {?} access_token
     * @param {?} id_token
     * @return {?}
     */
    setAuthorizationData(access_token, id_token) {
        if (this.oidcSecurityCommon.accessToken !== '') {
            this.oidcSecurityCommon.accessToken = '';
        }
        this.loggerService.logDebug(access_token);
        this.loggerService.logDebug(id_token);
        this.loggerService.logDebug('storing to storage, getting the roles');
        this.oidcSecurityCommon.accessToken = access_token;
        this.oidcSecurityCommon.idToken = id_token;
        this.setIsAuthorized(true);
        this.oidcSecurityCommon.isAuthorized = true;
    }
    /**
     * @private
     * @param {?} isCodeFlow
     * @param {?} code_challenge
     * @param {?} redirect_url
     * @param {?} nonce
     * @param {?} state
     * @param {?} authorization_endpoint
     * @param {?=} prompt
     * @return {?}
     */
    createAuthorizeUrl(isCodeFlow, code_challenge, redirect_url, nonce, state, authorization_endpoint, prompt) {
        /** @type {?} */
        const urlParts = authorization_endpoint.split('?');
        /** @type {?} */
        const authorizationUrl = urlParts[0];
        /** @type {?} */
        let params = new HttpParams({
            fromString: urlParts[1],
            encoder: new UriEncoder(),
        });
        params = params.set('client_id', this.authConfiguration.client_id);
        params = params.append('redirect_uri', redirect_url);
        params = params.append('response_type', this.authConfiguration.response_type);
        params = params.append('scope', this.authConfiguration.scope);
        params = params.append('nonce', nonce);
        params = params.append('state', state);
        if (isCodeFlow) {
            params = params.append('code_challenge', code_challenge);
            params = params.append('code_challenge_method', 'S256');
        }
        if (prompt) {
            params = params.append('prompt', prompt);
        }
        if (this.authConfiguration.hd_param) {
            params = params.append('hd', this.authConfiguration.hd_param);
        }
        /** @type {?} */
        const customParams = Object.assign({}, this.oidcSecurityCommon.customRequestParams);
        Object.keys(customParams).forEach((/**
         * @param {?} key
         * @return {?}
         */
        key => {
            params = params.append(key, customParams[key].toString());
        }));
        return `${authorizationUrl}?${params}`;
    }
    /**
     * @private
     * @param {?} end_session_endpoint
     * @param {?} id_token_hint
     * @return {?}
     */
    createEndSessionUrl(end_session_endpoint, id_token_hint) {
        /** @type {?} */
        const urlParts = end_session_endpoint.split('?');
        /** @type {?} */
        const authorizationEndsessionUrl = urlParts[0];
        /** @type {?} */
        let params = new HttpParams({
            fromString: urlParts[1],
            encoder: new UriEncoder(),
        });
        params = params.set('id_token_hint', id_token_hint);
        params = params.append('post_logout_redirect_uri', this.authConfiguration.post_logout_redirect_uri);
        return `${authorizationEndsessionUrl}?${params}`;
    }
    /**
     * @private
     * @return {?}
     */
    getSigningKeys() {
        if (this.authWellKnownEndpoints) {
            this.loggerService.logDebug('jwks_uri: ' + this.authWellKnownEndpoints.jwks_uri);
            return this.oidcDataService.get(this.authWellKnownEndpoints.jwks_uri).pipe(catchError(this.handleErrorGetSigningKeys));
        }
        else {
            this.loggerService.logWarning('getSigningKeys: authWellKnownEndpoints is undefined');
        }
        return this.oidcDataService.get('undefined').pipe(catchError(this.handleErrorGetSigningKeys));
    }
    /**
     * @private
     * @param {?} error
     * @return {?}
     */
    handleErrorGetSigningKeys(error) {
        /** @type {?} */
        let errMsg;
        if (error instanceof Response) {
            /** @type {?} */
            const body = error.json() || {};
            /** @type {?} */
            const err = JSON.stringify(body);
            errMsg = `${error.status} - ${error.statusText || ''} ${err}`;
        }
        else {
            errMsg = error.message ? error.message : error.toString();
        }
        console.error(errMsg);
        return throwError(errMsg);
    }
    /**
     * @private
     * @return {?}
     */
    runTokenValidation() {
        if (this.runTokenValidationRunning || !this.authConfiguration.silent_renew) {
            return;
        }
        this.runTokenValidationRunning = true;
        this.loggerService.logDebug('runTokenValidation silent-renew running');
        /**
         * First time: delay 10 seconds to call silentRenewHeartBeatCheck
         * Afterwards: Run this check in a 5 second interval only AFTER the previous operation ends.
         * @type {?}
         */
        const silentRenewHeartBeatCheck = (/**
         * @return {?}
         */
        () => {
            this.loggerService.logDebug('silentRenewHeartBeatCheck\r\n' +
                `\tsilentRenewRunning: ${this.oidcSecurityCommon.silentRenewRunning === 'running'}\r\n` +
                `\tidToken: ${!!this.getIdToken()}\r\n` +
                `\t_userData.value: ${!!this._userData.value}`);
            if (this._userData.value && this.oidcSecurityCommon.silentRenewRunning !== 'running' && this.getIdToken()) {
                if (this.oidcSecurityValidation.isTokenExpired(this.oidcSecurityCommon.idToken, this.authConfiguration.silent_renew_offset_in_seconds)) {
                    this.loggerService.logDebug('IsAuthorized: id_token isTokenExpired, start silent renew if active');
                    if (this.authConfiguration.silent_renew) {
                        this.refreshSession().subscribe((/**
                         * @return {?}
                         */
                        () => {
                            this._scheduledHeartBeat = setTimeout(silentRenewHeartBeatCheck, 3000);
                        }), (/**
                         * @param {?} err
                         * @return {?}
                         */
                        (err) => {
                            this.loggerService.logError('Error: ' + err);
                            this._scheduledHeartBeat = setTimeout(silentRenewHeartBeatCheck, 3000);
                        }));
                        /* In this situation, we schedule a heatbeat check only when silentRenew is finished.
                        We don't want to schedule another check so we have to return here */
                        return;
                    }
                    else {
                        this.resetAuthorizationData(false);
                    }
                }
            }
            /* Delay 3 seconds and do the next check */
            this._scheduledHeartBeat = setTimeout(silentRenewHeartBeatCheck, 3000);
        });
        this.zone.runOutsideAngular((/**
         * @return {?}
         */
        () => {
            /* Initial heartbeat check */
            this._scheduledHeartBeat = setTimeout(silentRenewHeartBeatCheck, 10000);
        }));
    }
    /**
     * @private
     * @param {?} e
     * @return {?}
     */
    silentRenewEventHandler(e) {
        this.loggerService.logDebug('silentRenewEventHandler');
        if (this.authConfiguration.response_type === 'code') {
            /** @type {?} */
            const urlParts = e.detail.toString().split('?');
            /** @type {?} */
            const params = new HttpParams({
                fromString: urlParts[1]
            });
            /** @type {?} */
            const code = params.get('code');
            /** @type {?} */
            const state = params.get('state');
            /** @type {?} */
            const session_state = params.get('session_state');
            /** @type {?} */
            const error = params.get('error');
            if (code && state) {
                this.requestTokensWithCodeProcedure(code, state, session_state);
            }
            if (error) {
                this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.unauthorized, ValidationResult.LoginRequired));
                this.resetAuthorizationData(false);
                this.oidcSecurityCommon.authNonce = '';
                this.loggerService.logDebug(e.detail.toString());
            }
        }
        else {
            // ImplicitFlow
            this.authorizedImplicitFlowCallback(e.detail);
        }
    }
}
OidcSecurityService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcSecurityService.ctorParameters = () => [
    { type: OidcDataService },
    { type: StateValidationService },
    { type: AuthConfiguration },
    { type: Router },
    { type: OidcSecurityCheckSession },
    { type: OidcSecuritySilentRenew },
    { type: OidcSecurityUserService },
    { type: OidcSecurityCommon },
    { type: OidcSecurityValidation },
    { type: TokenHelperService },
    { type: LoggerService },
    { type: NgZone },
    { type: HttpClient }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class AuthModule {
    /**
     * @param {?=} token
     * @return {?}
     */
    static forRoot(token = {}) {
        return {
            ngModule: AuthModule,
            providers: [
                OidcConfigService,
                OidcSecurityService,
                OidcSecurityValidation,
                OidcSecurityCheckSession,
                OidcSecuritySilentRenew,
                OidcSecurityUserService,
                OidcSecurityCommon,
                AuthConfiguration,
                TokenHelperService,
                LoggerService,
                IFrameService,
                EqualityHelperService,
                AuthWellKnownEndpoints,
                OidcDataService,
                StateValidationService,
                {
                    provide: OidcSecurityStorage,
                    useClass: token.storage || BrowserStorage,
                },
            ],
        };
    }
}
AuthModule.decorators = [
    { type: NgModule }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */

export { AuthWellKnownEndpoints, AuthorizationResult, AuthorizationState, JwtKeys, JwtKey, ValidateStateResult, ValidationResult, OpenIDImplicitFlowConfiguration, AuthConfiguration, AuthModule, OidcConfigService, OidcSecurityService, OidcSecurityStorage, BrowserStorage, OidcSecurityValidation, TokenHelperService, OidcDataService as ɵa, IFrameService as ɵg, EqualityHelperService as ɵd, StateValidationService as ɵb, LoggerService as ɵe, OidcSecurityCheckSession as ɵf, OidcSecurityCommon as ɵc, OidcSecuritySilentRenew as ɵh, OidcSecurityUserService as ɵi };

//# sourceMappingURL=angular-auth-oidc-client.js.map