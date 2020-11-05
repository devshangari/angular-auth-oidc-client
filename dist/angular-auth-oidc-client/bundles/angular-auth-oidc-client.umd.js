(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('@angular/common'), require('jsrsasign'), require('@angular/common/http'), require('@angular/router'), require('rxjs'), require('@angular/core'), require('rxjs/operators')) :
    typeof define === 'function' && define.amd ? define('angular-auth-oidc-client', ['exports', '@angular/common', 'jsrsasign', '@angular/common/http', '@angular/router', 'rxjs', '@angular/core', 'rxjs/operators'], factory) :
    (factory((global['angular-auth-oidc-client'] = {}),global.ng.common,global.jsrsasign,global.ng.common.http,global.ng.router,global.rxjs,global.ng.core,global.rxjs.operators));
}(this, (function (exports,common,jsrsasign,http,router,rxjs,core,operators) { 'use strict';

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var AuthWellKnownEndpoints = /** @class */ (function () {
        function AuthWellKnownEndpoints() {
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
        AuthWellKnownEndpoints.prototype.setWellKnownEndpoints = /**
         * @param {?} data
         * @return {?}
         */
            function (data) {
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
            };
        return AuthWellKnownEndpoints;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var AuthorizationResult = /** @class */ (function () {
        function AuthorizationResult(authorizationState, validationResult) {
            this.authorizationState = authorizationState;
            this.validationResult = validationResult;
        }
        return AuthorizationResult;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    /** @enum {string} */
    var AuthorizationState = {
        authorized: 'authorized',
        forbidden: 'forbidden',
        unauthorized: 'unauthorized',
    };

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var JwtKeys = /** @class */ (function () {
        function JwtKeys() {
            this.keys = [];
        }
        return JwtKeys;
    }());
    var JwtKey = /** @class */ (function () {
        function JwtKey() {
            this.kty = '';
            this.use = '';
            this.kid = '';
            this.x5t = '';
            this.e = '';
            this.n = '';
            this.x5c = [];
        }
        return JwtKey;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    /** @enum {string} */
    var ValidationResult = {
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
    var ValidateStateResult = /** @class */ (function () {
        function ValidateStateResult(access_token, id_token, authResponseIsValid, decoded_id_token, state) {
            if (access_token === void 0) {
                access_token = '';
            }
            if (id_token === void 0) {
                id_token = '';
            }
            if (authResponseIsValid === void 0) {
                authResponseIsValid = false;
            }
            if (decoded_id_token === void 0) {
                decoded_id_token = {};
            }
            if (state === void 0) {
                state = ValidationResult.NotSet;
            }
            this.access_token = access_token;
            this.id_token = id_token;
            this.authResponseIsValid = authResponseIsValid;
            this.decoded_id_token = decoded_id_token;
            this.state = state;
        }
        return ValidateStateResult;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var OpenIDImplicitFlowConfiguration = /** @class */ (function () {
        function OpenIDImplicitFlowConfiguration() {
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
        return OpenIDImplicitFlowConfiguration;
    }());
    var AuthConfiguration = /** @class */ (function () {
        function AuthConfiguration(platformId) {
            this.platformId = platformId;
            this._onConfigurationChange = new rxjs.Subject();
            this.defaultConfig = new OpenIDImplicitFlowConfiguration();
        }
        Object.defineProperty(AuthConfiguration.prototype, "stsServer", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.stsServer;
                }
                return this.defaultConfig.stsServer;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "redirect_url", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.redirect_url;
                }
                return this.defaultConfig.redirect_url;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "silent_redirect_url", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.silent_renew_url;
                }
                return this.defaultConfig.silent_renew_url;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "client_id", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.client_id;
                }
                return this.defaultConfig.client_id;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "response_type", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.response_type;
                }
                return this.defaultConfig.response_type;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "scope", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.scope;
                }
                return this.defaultConfig.scope;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "hd_param", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.hd_param;
                }
                return this.defaultConfig.hd_param;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "post_logout_redirect_uri", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.post_logout_redirect_uri;
                }
                return this.defaultConfig.post_logout_redirect_uri;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "start_checksession", {
            get: /**
             * @return {?}
             */ function () {
                if (!common.isPlatformBrowser(this.platformId)) {
                    return false;
                }
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.start_checksession;
                }
                return this.defaultConfig.start_checksession;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "silent_renew", {
            get: /**
             * @return {?}
             */ function () {
                if (!common.isPlatformBrowser(this.platformId)) {
                    return false;
                }
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.silent_renew;
                }
                return this.defaultConfig.silent_renew;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "silent_renew_offset_in_seconds", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.silent_renew_offset_in_seconds;
                }
                return this.defaultConfig.silent_renew_offset_in_seconds;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "post_login_route", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.post_login_route;
                }
                return this.defaultConfig.post_login_route;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "forbidden_route", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.forbidden_route;
                }
                return this.defaultConfig.forbidden_route;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "unauthorized_route", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.unauthorized_route;
                }
                return this.defaultConfig.unauthorized_route;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "auto_userinfo", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.auto_userinfo;
                }
                return this.defaultConfig.auto_userinfo;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "auto_clean_state_after_authentication", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.auto_clean_state_after_authentication;
                }
                return this.defaultConfig.auto_clean_state_after_authentication;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "trigger_authorization_result_event", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.trigger_authorization_result_event;
                }
                return this.defaultConfig.trigger_authorization_result_event;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "isLogLevelWarningEnabled", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.log_console_warning_active;
                }
                return this.defaultConfig.log_console_warning_active;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "isLogLevelDebugEnabled", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.log_console_debug_active;
                }
                return this.defaultConfig.log_console_debug_active;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "iss_validation_off", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.iss_validation_off;
                }
                return this.defaultConfig.iss_validation_off;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "history_cleanup_off", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.history_cleanup_off;
                }
                return this.defaultConfig.history_cleanup_off;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "max_id_token_iat_offset_allowed_in_seconds", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.max_id_token_iat_offset_allowed_in_seconds;
                }
                return this.defaultConfig.max_id_token_iat_offset_allowed_in_seconds;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "disable_iat_offset_validation", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.disable_iat_offset_validation;
                }
                return this.defaultConfig.disable_iat_offset_validation;
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(AuthConfiguration.prototype, "storage", {
            get: /**
             * @return {?}
             */ function () {
                if (this.openIDImplicitFlowConfiguration) {
                    return this.openIDImplicitFlowConfiguration.storage;
                }
                return this.defaultConfig.storage;
            },
            enumerable: true,
            configurable: true
        });
        /**
         * @param {?} openIDImplicitFlowConfiguration
         * @return {?}
         */
        AuthConfiguration.prototype.init = /**
         * @param {?} openIDImplicitFlowConfiguration
         * @return {?}
         */
            function (openIDImplicitFlowConfiguration) {
                this.openIDImplicitFlowConfiguration = openIDImplicitFlowConfiguration;
                this._onConfigurationChange.next(openIDImplicitFlowConfiguration);
            };
        Object.defineProperty(AuthConfiguration.prototype, "onConfigurationChange", {
            get: /**
             * @return {?}
             */ function () {
                return this._onConfigurationChange.asObservable();
            },
            enumerable: true,
            configurable: true
        });
        AuthConfiguration.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        AuthConfiguration.ctorParameters = function () {
            return [
                { type: Object, decorators: [{ type: core.Inject, args: [core.PLATFORM_ID,] }] }
            ];
        };
        return AuthConfiguration;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var OidcDataService = /** @class */ (function () {
        function OidcDataService(httpClient) {
            this.httpClient = httpClient;
        }
        /**
         * @template T
         * @param {?} url
         * @return {?}
         */
        OidcDataService.prototype.getWellknownEndpoints = /**
         * @template T
         * @param {?} url
         * @return {?}
         */
            function (url) {
                /** @type {?} */
                var headers = new http.HttpHeaders();
                headers = headers.set('Accept', 'application/json');
                return this.httpClient.get(url, {
                    headers: headers,
                });
            };
        /**
         * @template T
         * @param {?} url
         * @param {?} token
         * @return {?}
         */
        OidcDataService.prototype.getIdentityUserData = /**
         * @template T
         * @param {?} url
         * @param {?} token
         * @return {?}
         */
            function (url, token) {
                /** @type {?} */
                var headers = new http.HttpHeaders();
                headers = headers.set('Accept', 'application/json');
                headers = headers.set('Authorization', 'Bearer ' + decodeURIComponent(token));
                return this.httpClient.get(url, {
                    headers: headers,
                });
            };
        /**
         * @template T
         * @param {?} url
         * @return {?}
         */
        OidcDataService.prototype.get = /**
         * @template T
         * @param {?} url
         * @return {?}
         */
            function (url) {
                /** @type {?} */
                var headers = new http.HttpHeaders();
                headers = headers.set('Accept', 'application/json');
                return this.httpClient.get(url, {
                    headers: headers,
                });
            };
        OidcDataService.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        OidcDataService.ctorParameters = function () {
            return [
                { type: http.HttpClient }
            ];
        };
        return OidcDataService;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var LoggerService = /** @class */ (function () {
        function LoggerService(authConfiguration) {
            this.authConfiguration = authConfiguration;
        }
        /**
         * @param {?} message
         * @return {?}
         */
        LoggerService.prototype.logError = /**
         * @param {?} message
         * @return {?}
         */
            function (message) {
                console.error(message);
            };
        /**
         * @param {?} message
         * @return {?}
         */
        LoggerService.prototype.logWarning = /**
         * @param {?} message
         * @return {?}
         */
            function (message) {
                if (this.authConfiguration.isLogLevelWarningEnabled) {
                    console.warn(message);
                }
            };
        /**
         * @param {?} message
         * @return {?}
         */
        LoggerService.prototype.logDebug = /**
         * @param {?} message
         * @return {?}
         */
            function (message) {
                if (this.authConfiguration.isLogLevelDebugEnabled) {
                    console.log(message);
                }
            };
        LoggerService.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        LoggerService.ctorParameters = function () {
            return [
                { type: AuthConfiguration }
            ];
        };
        return LoggerService;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var IFrameService = /** @class */ (function () {
        function IFrameService(loggerService) {
            this.loggerService = loggerService;
        }
        /**
         * @param {?} identifier
         * @return {?}
         */
        IFrameService.prototype.getExistingIFrame = /**
         * @param {?} identifier
         * @return {?}
         */
            function (identifier) {
                /** @type {?} */
                var iFrameOnParent = this.getIFrameFromParentWindow(identifier);
                if (iFrameOnParent) {
                    return iFrameOnParent;
                }
                return this.getIFrameFromWindow(identifier);
            };
        /**
         * @param {?} identifier
         * @return {?}
         */
        IFrameService.prototype.addIFrameToWindowBody = /**
         * @param {?} identifier
         * @return {?}
         */
            function (identifier) {
                /** @type {?} */
                var sessionIframe = window.document.createElement('iframe');
                sessionIframe.id = identifier;
                this.loggerService.logDebug(sessionIframe);
                sessionIframe.style.display = 'none';
                window.document.body.appendChild(sessionIframe);
                return sessionIframe;
            };
        /**
         * @private
         * @param {?} identifier
         * @return {?}
         */
        IFrameService.prototype.getIFrameFromParentWindow = /**
         * @private
         * @param {?} identifier
         * @return {?}
         */
            function (identifier) {
                try {
                    return window.parent.document.getElementById(identifier);
                }
                catch (e) {
                    return null;
                }
            };
        /**
         * @private
         * @param {?} identifier
         * @return {?}
         */
        IFrameService.prototype.getIFrameFromWindow = /**
         * @private
         * @param {?} identifier
         * @return {?}
         */
            function (identifier) {
                return window.document.getElementById(identifier);
            };
        IFrameService.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        IFrameService.ctorParameters = function () {
            return [
                { type: LoggerService }
            ];
        };
        return IFrameService;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var EqualityHelperService = /** @class */ (function () {
        function EqualityHelperService() {
        }
        /**
         * @param {?} value1
         * @param {?} value2
         * @return {?}
         */
        EqualityHelperService.prototype.areEqual = /**
         * @param {?} value1
         * @param {?} value2
         * @return {?}
         */
            function (value1, value2) {
                if (!value1 || !value2) {
                    return false;
                }
                if (this.bothValuesAreArrays(value1, value2)) {
                    return this.arraysEqual(( /** @type {?} */(value1)), ( /** @type {?} */(value2)));
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
            };
        /**
         * @private
         * @param {?} value1
         * @param {?} value2
         * @return {?}
         */
        EqualityHelperService.prototype.oneValueIsStringAndTheOtherIsArray = /**
         * @private
         * @param {?} value1
         * @param {?} value2
         * @return {?}
         */
            function (value1, value2) {
                return (Array.isArray(value1) && this.valueIsString(value2)) || (Array.isArray(value2) && this.valueIsString(value1));
            };
        /**
         * @private
         * @param {?} value1
         * @param {?} value2
         * @return {?}
         */
        EqualityHelperService.prototype.bothValuesAreObjects = /**
         * @private
         * @param {?} value1
         * @param {?} value2
         * @return {?}
         */
            function (value1, value2) {
                return this.valueIsObject(value1) && this.valueIsObject(value2);
            };
        /**
         * @private
         * @param {?} value1
         * @param {?} value2
         * @return {?}
         */
        EqualityHelperService.prototype.bothValuesAreStrings = /**
         * @private
         * @param {?} value1
         * @param {?} value2
         * @return {?}
         */
            function (value1, value2) {
                return this.valueIsString(value1) && this.valueIsString(value2);
            };
        /**
         * @private
         * @param {?} value1
         * @param {?} value2
         * @return {?}
         */
        EqualityHelperService.prototype.bothValuesAreArrays = /**
         * @private
         * @param {?} value1
         * @param {?} value2
         * @return {?}
         */
            function (value1, value2) {
                return Array.isArray(value1) && Array.isArray(value2);
            };
        /**
         * @private
         * @param {?} value
         * @return {?}
         */
        EqualityHelperService.prototype.valueIsString = /**
         * @private
         * @param {?} value
         * @return {?}
         */
            function (value) {
                return typeof value === 'string' || value instanceof String;
            };
        /**
         * @private
         * @param {?} value
         * @return {?}
         */
        EqualityHelperService.prototype.valueIsObject = /**
         * @private
         * @param {?} value
         * @return {?}
         */
            function (value) {
                return typeof value === 'object';
            };
        /**
         * @private
         * @param {?} arr1
         * @param {?} arr2
         * @return {?}
         */
        EqualityHelperService.prototype.arraysEqual = /**
         * @private
         * @param {?} arr1
         * @param {?} arr2
         * @return {?}
         */
            function (arr1, arr2) {
                if (arr1.length !== arr2.length) {
                    return false;
                }
                for (var i = arr1.length; i--;) {
                    if (arr1[i] !== arr2[i]) {
                        return false;
                    }
                }
                return true;
            };
        EqualityHelperService.decorators = [
            { type: core.Injectable }
        ];
        return EqualityHelperService;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var TokenHelperService = /** @class */ (function () {
        function TokenHelperService(loggerService) {
            this.loggerService = loggerService;
            this.PARTS_OF_TOKEN = 3;
        }
        /**
         * @param {?} dataIdToken
         * @return {?}
         */
        TokenHelperService.prototype.getTokenExpirationDate = /**
         * @param {?} dataIdToken
         * @return {?}
         */
            function (dataIdToken) {
                if (!dataIdToken.hasOwnProperty('exp')) {
                    return new Date();
                }
                /** @type {?} */
                var date = new Date(0);
                date.setUTCSeconds(dataIdToken.exp);
                return date;
            };
        /**
         * @param {?} token
         * @param {?} encoded
         * @return {?}
         */
        TokenHelperService.prototype.getHeaderFromToken = /**
         * @param {?} token
         * @param {?} encoded
         * @return {?}
         */
            function (token, encoded) {
                if (!this.tokenIsValid(token)) {
                    return {};
                }
                return this.getPartOfToken(token, 0, encoded);
            };
        /**
         * @param {?} token
         * @param {?} encoded
         * @return {?}
         */
        TokenHelperService.prototype.getPayloadFromToken = /**
         * @param {?} token
         * @param {?} encoded
         * @return {?}
         */
            function (token, encoded) {
                if (!this.tokenIsValid(token)) {
                    return {};
                }
                return this.getPartOfToken(token, 1, encoded);
            };
        /**
         * @param {?} token
         * @param {?} encoded
         * @return {?}
         */
        TokenHelperService.prototype.getSignatureFromToken = /**
         * @param {?} token
         * @param {?} encoded
         * @return {?}
         */
            function (token, encoded) {
                if (!this.tokenIsValid(token)) {
                    return {};
                }
                return this.getPartOfToken(token, 2, encoded);
            };
        /**
         * @private
         * @param {?} token
         * @param {?} index
         * @param {?} encoded
         * @return {?}
         */
        TokenHelperService.prototype.getPartOfToken = /**
         * @private
         * @param {?} token
         * @param {?} index
         * @param {?} encoded
         * @return {?}
         */
            function (token, index, encoded) {
                /** @type {?} */
                var partOfToken = this.extractPartOfToken(token, index);
                if (encoded) {
                    return partOfToken;
                }
                /** @type {?} */
                var result = this.urlBase64Decode(partOfToken);
                return JSON.parse(result);
            };
        /**
         * @private
         * @param {?} str
         * @return {?}
         */
        TokenHelperService.prototype.urlBase64Decode = /**
         * @private
         * @param {?} str
         * @return {?}
         */
            function (str) {
                /** @type {?} */
                var output = str.replace(/-/g, '+').replace(/_/g, '/');
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
                var decoded = typeof window !== 'undefined' ? window.atob(output) : new Buffer(output, 'base64').toString('binary');
                try {
                    // Going backwards: from bytestream, to percent-encoding, to original string.
                    return decodeURIComponent(decoded.split('')
                        .map(( /**
                 * @param {?} c
                 * @return {?}
                 */function (c) { return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2); }))
                        .join(''));
                }
                catch (err) {
                    return decoded;
                }
            };
        /**
         * @private
         * @param {?} token
         * @return {?}
         */
        TokenHelperService.prototype.tokenIsValid = /**
         * @private
         * @param {?} token
         * @return {?}
         */
            function (token) {
                if (!token) {
                    this.loggerService.logError("token '" + token + "' is not valid --> token falsy");
                    return false;
                }
                if (!(( /** @type {?} */(token))).includes('.')) {
                    this.loggerService.logError("token '" + token + "' is not valid --> no dots included");
                    return false;
                }
                /** @type {?} */
                var parts = token.split('.');
                if (parts.length !== this.PARTS_OF_TOKEN) {
                    this.loggerService.logError("token '" + token + "' is not valid --> token has t have exact three dots");
                    return false;
                }
                return true;
            };
        /**
         * @private
         * @param {?} token
         * @param {?} index
         * @return {?}
         */
        TokenHelperService.prototype.extractPartOfToken = /**
         * @private
         * @param {?} token
         * @param {?} index
         * @return {?}
         */
            function (token, index) {
                return token.split('.')[index];
            };
        TokenHelperService.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        TokenHelperService.ctorParameters = function () {
            return [
                { type: LoggerService }
            ];
        };
        return TokenHelperService;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    /**
     * Implement this class-interface to create a custom storage.
     * @abstract
     */
    var OidcSecurityStorage = /** @class */ (function () {
        function OidcSecurityStorage() {
        }
        OidcSecurityStorage.decorators = [
            { type: core.Injectable }
        ];
        return OidcSecurityStorage;
    }());
    var BrowserStorage = /** @class */ (function () {
        function BrowserStorage(authConfiguration) {
            this.authConfiguration = authConfiguration;
            this.hasStorage = typeof Storage !== 'undefined';
        }
        /**
         * @param {?} key
         * @return {?}
         */
        BrowserStorage.prototype.read = /**
         * @param {?} key
         * @return {?}
         */
            function (key) {
                if (this.hasStorage) {
                    return JSON.parse(this.authConfiguration.storage.getItem(key + '_' + this.authConfiguration.client_id));
                }
                return;
            };
        /**
         * @param {?} key
         * @param {?} value
         * @return {?}
         */
        BrowserStorage.prototype.write = /**
         * @param {?} key
         * @param {?} value
         * @return {?}
         */
            function (key, value) {
                if (this.hasStorage) {
                    value = value === undefined ? null : value;
                    this.authConfiguration.storage.setItem(key + '_' + this.authConfiguration.client_id, JSON.stringify(value));
                }
            };
        BrowserStorage.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        BrowserStorage.ctorParameters = function () {
            return [
                { type: AuthConfiguration }
            ];
        };
        return BrowserStorage;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var OidcSecurityCommon = /** @class */ (function () {
        function OidcSecurityCommon(oidcSecurityStorage) {
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
        Object.defineProperty(OidcSecurityCommon.prototype, "authResult", {
            get: /**
             * @return {?}
             */ function () {
                return this.retrieve(this.storage_auth_result);
            },
            set: /**
             * @param {?} value
             * @return {?}
             */ function (value) {
                this.store(this.storage_auth_result, value);
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityCommon.prototype, "accessToken", {
            get: /**
             * @return {?}
             */ function () {
                return this.retrieve(this.storage_access_token) || '';
            },
            set: /**
             * @param {?} value
             * @return {?}
             */ function (value) {
                this.store(this.storage_access_token, value);
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityCommon.prototype, "idToken", {
            get: /**
             * @return {?}
             */ function () {
                return this.retrieve(this.storage_id_token) || '';
            },
            set: /**
             * @param {?} value
             * @return {?}
             */ function (value) {
                this.store(this.storage_id_token, value);
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityCommon.prototype, "isAuthorized", {
            get: /**
             * @return {?}
             */ function () {
                return this.retrieve(this.storage_is_authorized);
            },
            set: /**
             * @param {?} value
             * @return {?}
             */ function (value) {
                this.store(this.storage_is_authorized, value);
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityCommon.prototype, "userData", {
            get: /**
             * @return {?}
             */ function () {
                return this.retrieve(this.storage_user_data);
            },
            set: /**
             * @param {?} value
             * @return {?}
             */ function (value) {
                this.store(this.storage_user_data, value);
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityCommon.prototype, "authNonce", {
            get: /**
             * @return {?}
             */ function () {
                return this.retrieve(this.storage_auth_nonce) || '';
            },
            set: /**
             * @param {?} value
             * @return {?}
             */ function (value) {
                this.store(this.storage_auth_nonce, value);
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityCommon.prototype, "code_verifier", {
            get: /**
             * @return {?}
             */ function () {
                return this.retrieve(this.storage_code_verifier) || '';
            },
            set: /**
             * @param {?} value
             * @return {?}
             */ function (value) {
                this.store(this.storage_code_verifier, value);
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityCommon.prototype, "authStateControl", {
            get: /**
             * @return {?}
             */ function () {
                return this.retrieve(this.storage_auth_state_control) || '';
            },
            set: /**
             * @param {?} value
             * @return {?}
             */ function (value) {
                this.store(this.storage_auth_state_control, value);
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityCommon.prototype, "sessionState", {
            get: /**
             * @return {?}
             */ function () {
                return this.retrieve(this.storage_session_state);
            },
            set: /**
             * @param {?} value
             * @return {?}
             */ function (value) {
                this.store(this.storage_session_state, value);
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityCommon.prototype, "silentRenewRunning", {
            get: /**
             * @return {?}
             */ function () {
                return this.retrieve(this.storage_silent_renew_running) || '';
            },
            set: /**
             * @param {?} value
             * @return {?}
             */ function (value) {
                this.store(this.storage_silent_renew_running, value);
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityCommon.prototype, "customRequestParams", {
            get: /**
             * @return {?}
             */ function () {
                return this.retrieve(this.storage_custom_request_params);
            },
            set: /**
             * @param {?} value
             * @return {?}
             */ function (value) {
                this.store(this.storage_custom_request_params, value);
            },
            enumerable: true,
            configurable: true
        });
        /**
         * @private
         * @param {?} key
         * @return {?}
         */
        OidcSecurityCommon.prototype.retrieve = /**
         * @private
         * @param {?} key
         * @return {?}
         */
            function (key) {
                return this.oidcSecurityStorage.read(key);
            };
        /**
         * @private
         * @param {?} key
         * @param {?} value
         * @return {?}
         */
        OidcSecurityCommon.prototype.store = /**
         * @private
         * @param {?} key
         * @param {?} value
         * @return {?}
         */
            function (key, value) {
                this.oidcSecurityStorage.write(key, value);
            };
        /**
         * @param {?} isRenewProcess
         * @return {?}
         */
        OidcSecurityCommon.prototype.resetStorageData = /**
         * @param {?} isRenewProcess
         * @return {?}
         */
            function (isRenewProcess) {
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
            };
        /**
         * @return {?}
         */
        OidcSecurityCommon.prototype.getAccessToken = /**
         * @return {?}
         */
            function () {
                return this.retrieve(this.storage_access_token);
            };
        /**
         * @return {?}
         */
        OidcSecurityCommon.prototype.getIdToken = /**
         * @return {?}
         */
            function () {
                return this.retrieve(this.storage_id_token);
            };
        OidcSecurityCommon.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        OidcSecurityCommon.ctorParameters = function () {
            return [
                { type: OidcSecurityStorage }
            ];
        };
        return OidcSecurityCommon;
    }());

    /*! *****************************************************************************
    Copyright (c) Microsoft Corporation. All rights reserved.
    Licensed under the Apache License, Version 2.0 (the "License"); you may not use
    this file except in compliance with the License. You may obtain a copy of the
    License at http://www.apache.org/licenses/LICENSE-2.0

    THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
    WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
    MERCHANTABLITY OR NON-INFRINGEMENT.

    See the Apache Version 2.0 License for specific language governing permissions
    and limitations under the License.
    ***************************************************************************** */
    function __values(o) {
        var m = typeof Symbol === "function" && o[Symbol.iterator], i = 0;
        if (m)
            return m.call(o);
        return {
            next: function () {
                if (o && i >= o.length)
                    o = void 0;
                return { value: o && o[i++], done: !o };
            }
        };
    }

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
    var OidcSecurityValidation = /** @class */ (function () {
        function OidcSecurityValidation(arrayHelperService, tokenHelperService, loggerService) {
            this.arrayHelperService = arrayHelperService;
            this.tokenHelperService = tokenHelperService;
            this.loggerService = loggerService;
        }
        // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
        // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
        /**
         * @param {?} token
         * @param {?=} offsetSeconds
         * @return {?}
         */
        OidcSecurityValidation.prototype.isTokenExpired =
            // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
            /**
             * @param {?} token
             * @param {?=} offsetSeconds
             * @return {?}
             */
            function (token, offsetSeconds) {
                /** @type {?} */
                var decoded;
                decoded = this.tokenHelperService.getPayloadFromToken(token, false);
                return !this.validate_id_token_exp_not_expired(decoded, offsetSeconds);
            };
        // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
        // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
        /**
         * @param {?} decoded_id_token
         * @param {?=} offsetSeconds
         * @return {?}
         */
        OidcSecurityValidation.prototype.validate_id_token_exp_not_expired =
            // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
            /**
             * @param {?} decoded_id_token
             * @param {?=} offsetSeconds
             * @return {?}
             */
            function (decoded_id_token, offsetSeconds) {
                /** @type {?} */
                var tokenExpirationDate = this.tokenHelperService.getTokenExpirationDate(decoded_id_token);
                offsetSeconds = offsetSeconds || 0;
                if (!tokenExpirationDate) {
                    return false;
                }
                /** @type {?} */
                var tokenExpirationValue = tokenExpirationDate.valueOf();
                /** @type {?} */
                var nowWithOffset = new Date().valueOf() + offsetSeconds * 1000;
                /** @type {?} */
                var tokenNotExpired = tokenExpirationValue > nowWithOffset;
                this.loggerService.logDebug("Token not expired?: " + tokenExpirationValue + " > " + nowWithOffset + "  (" + tokenNotExpired + ")");
                // Token not expired?
                return tokenNotExpired;
            };
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
        OidcSecurityValidation.prototype.validate_required_id_token =
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
            function (dataIdToken) {
                /** @type {?} */
                var validated = true;
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
            };
        // id_token C8: The iat Claim can be used to reject tokens that were issued too far away from the current time,
        // limiting the amount of time that nonces need to be stored to prevent attacks.The acceptable range is Client specific.
        // id_token C8: The iat Claim can be used to reject tokens that were issued too far away from the current time,
        // limiting the amount of time that nonces need to be stored to prevent attacks.The acceptable range is Client specific.
        /**
         * @param {?} dataIdToken
         * @param {?} max_offset_allowed_in_seconds
         * @param {?} disable_iat_offset_validation
         * @return {?}
         */
        OidcSecurityValidation.prototype.validate_id_token_iat_max_offset =
            // id_token C8: The iat Claim can be used to reject tokens that were issued too far away from the current time,
            // limiting the amount of time that nonces need to be stored to prevent attacks.The acceptable range is Client specific.
            /**
             * @param {?} dataIdToken
             * @param {?} max_offset_allowed_in_seconds
             * @param {?} disable_iat_offset_validation
             * @return {?}
             */
            function (dataIdToken, max_offset_allowed_in_seconds, disable_iat_offset_validation) {
                if (disable_iat_offset_validation) {
                    return true;
                }
                if (!dataIdToken.hasOwnProperty('iat')) {
                    return false;
                }
                /** @type {?} */
                var dateTime_iat_id_token = new Date(0);
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
            };
        // id_token C9: The value of the nonce Claim MUST be checked to verify that it is the same value as the one
        // that was sent in the Authentication Request.The Client SHOULD check the nonce value for replay attacks.
        // The precise method for detecting replay attacks is Client specific.
        // id_token C9: The value of the nonce Claim MUST be checked to verify that it is the same value as the one
        // that was sent in the Authentication Request.The Client SHOULD check the nonce value for replay attacks.
        // The precise method for detecting replay attacks is Client specific.
        /**
         * @param {?} dataIdToken
         * @param {?} local_nonce
         * @return {?}
         */
        OidcSecurityValidation.prototype.validate_id_token_nonce =
            // id_token C9: The value of the nonce Claim MUST be checked to verify that it is the same value as the one
            // that was sent in the Authentication Request.The Client SHOULD check the nonce value for replay attacks.
            // The precise method for detecting replay attacks is Client specific.
            /**
             * @param {?} dataIdToken
             * @param {?} local_nonce
             * @return {?}
             */
            function (dataIdToken, local_nonce) {
                if (dataIdToken.nonce !== local_nonce) {
                    this.loggerService.logDebug('Validate_id_token_nonce failed, dataIdToken.nonce: ' + dataIdToken.nonce + ' local_nonce:' + local_nonce);
                    return false;
                }
                return true;
            };
        // id_token C1: The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
        // MUST exactly match the value of the iss (issuer) Claim.
        // id_token C1: The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
        // MUST exactly match the value of the iss (issuer) Claim.
        /**
         * @param {?} dataIdToken
         * @param {?} authWellKnownEndpoints_issuer
         * @return {?}
         */
        OidcSecurityValidation.prototype.validate_id_token_iss =
            // id_token C1: The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
            // MUST exactly match the value of the iss (issuer) Claim.
            /**
             * @param {?} dataIdToken
             * @param {?} authWellKnownEndpoints_issuer
             * @return {?}
             */
            function (dataIdToken, authWellKnownEndpoints_issuer) {
                if ((( /** @type {?} */(dataIdToken.iss))) !== (( /** @type {?} */(authWellKnownEndpoints_issuer)))) {
                    this.loggerService.logDebug('Validate_id_token_iss failed, dataIdToken.iss: ' +
                        dataIdToken.iss +
                        ' authWellKnownEndpoints issuer:' +
                        authWellKnownEndpoints_issuer);
                    return false;
                }
                return true;
            };
        // id_token C2: The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified
        // by the iss (issuer) Claim as an audience.
        // The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences
        // not trusted by the Client.
        // id_token C2: The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified
        // by the iss (issuer) Claim as an audience.
        // The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences
        // not trusted by the Client.
        /**
         * @param {?} dataIdToken
         * @param {?} aud
         * @return {?}
         */
        OidcSecurityValidation.prototype.validate_id_token_aud =
            // id_token C2: The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified
            // by the iss (issuer) Claim as an audience.
            // The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences
            // not trusted by the Client.
            /**
             * @param {?} dataIdToken
             * @param {?} aud
             * @return {?}
             */
            function (dataIdToken, aud) {
                if (dataIdToken.aud instanceof Array) {
                    /** @type {?} */
                    var result = this.arrayHelperService.areEqual(dataIdToken.aud, aud);
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
            };
        /**
         * @param {?} state
         * @param {?} local_state
         * @return {?}
         */
        OidcSecurityValidation.prototype.validateStateFromHashCallback = /**
         * @param {?} state
         * @param {?} local_state
         * @return {?}
         */
            function (state, local_state) {
                if ((( /** @type {?} */(state))) !== (( /** @type {?} */(local_state)))) {
                    this.loggerService.logDebug('ValidateStateFromHashCallback failed, state: ' + state + ' local_state:' + local_state);
                    return false;
                }
                return true;
            };
        /**
         * @param {?} id_token_sub
         * @param {?} userdata_sub
         * @return {?}
         */
        OidcSecurityValidation.prototype.validate_userdata_sub_id_token = /**
         * @param {?} id_token_sub
         * @param {?} userdata_sub
         * @return {?}
         */
            function (id_token_sub, userdata_sub) {
                if ((( /** @type {?} */(id_token_sub))) !== (( /** @type {?} */(userdata_sub)))) {
                    this.loggerService.logDebug('validate_userdata_sub_id_token failed, id_token_sub: ' + id_token_sub + ' userdata_sub:' + userdata_sub);
                    return false;
                }
                return true;
            };
        // id_token C5: The Client MUST validate the signature of the ID Token according to JWS [JWS] using the algorithm specified in the alg
        // Header Parameter of the JOSE Header.The Client MUST use the keys provided by the Issuer.
        // id_token C6: The alg value SHOULD be RS256. Validation of tokens using other signing algorithms is described in the
        // OpenID Connect Core 1.0 [OpenID.Core] specification.
        // id_token C5: The Client MUST validate the signature of the ID Token according to JWS [JWS] using the algorithm specified in the alg
        // Header Parameter of the JOSE Header.The Client MUST use the keys provided by the Issuer.
        // id_token C6: The alg value SHOULD be RS256. Validation of tokens using other signing algorithms is described in the
        // OpenID Connect Core 1.0 [OpenID.Core] specification.
        /**
         * @param {?} id_token
         * @param {?} jwtkeys
         * @return {?}
         */
        OidcSecurityValidation.prototype.validate_signature_id_token =
            // id_token C5: The Client MUST validate the signature of the ID Token according to JWS [JWS] using the algorithm specified in the alg
            // Header Parameter of the JOSE Header.The Client MUST use the keys provided by the Issuer.
            // id_token C6: The alg value SHOULD be RS256. Validation of tokens using other signing algorithms is described in the
            // OpenID Connect Core 1.0 [OpenID.Core] specification.
            /**
             * @param {?} id_token
             * @param {?} jwtkeys
             * @return {?}
             */
            function (id_token, jwtkeys) {
                var e_1, _a, e_2, _b, e_3, _c;
                if (!jwtkeys || !jwtkeys.keys) {
                    return false;
                }
                /** @type {?} */
                var header_data = this.tokenHelperService.getHeaderFromToken(id_token, false);
                if (Object.keys(header_data).length === 0 && header_data.constructor === Object) {
                    this.loggerService.logWarning('id token has no header data');
                    return false;
                }
                /** @type {?} */
                var kid = header_data.kid;
                /** @type {?} */
                var alg = header_data.alg;
                if ('RS256' !== (( /** @type {?} */(alg)))) {
                    this.loggerService.logWarning('Only RS256 supported');
                    return false;
                }
                /** @type {?} */
                var isValid = false;
                if (!header_data.hasOwnProperty('kid')) {
                    // exactly 1 key in the jwtkeys and no kid in the Jose header
                    // kty	"RSA" use "sig"
                    /** @type {?} */
                    var amountOfMatchingKeys = 0;
                    try {
                        for (var _d = __values(jwtkeys.keys), _e = _d.next(); !_e.done; _e = _d.next()) {
                            var key = _e.value;
                            if ((( /** @type {?} */(key.kty))) === 'RSA' && (( /** @type {?} */(key.use))) === 'sig') {
                                amountOfMatchingKeys = amountOfMatchingKeys + 1;
                            }
                        }
                    }
                    catch (e_1_1) {
                        e_1 = { error: e_1_1 };
                    }
                    finally {
                        try {
                            if (_e && !_e.done && (_a = _d.return))
                                _a.call(_d);
                        }
                        finally {
                            if (e_1)
                                throw e_1.error;
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
                        try {
                            for (var _f = __values(jwtkeys.keys), _g = _f.next(); !_g.done; _g = _f.next()) {
                                var key = _g.value;
                                if ((( /** @type {?} */(key.kty))) === 'RSA' && (( /** @type {?} */(key.use))) === 'sig') {
                                    /** @type {?} */
                                    var publickey = jsrsasign.KEYUTIL.getKey(key);
                                    isValid = jsrsasign.KJUR.jws.JWS.verify(id_token, publickey, ['RS256']);
                                    if (!isValid) {
                                        this.loggerService.logWarning('incorrect Signature, validation failed for id_token');
                                    }
                                    return isValid;
                                }
                            }
                        }
                        catch (e_2_1) {
                            e_2 = { error: e_2_1 };
                        }
                        finally {
                            try {
                                if (_g && !_g.done && (_b = _f.return))
                                    _b.call(_f);
                            }
                            finally {
                                if (e_2)
                                    throw e_2.error;
                            }
                        }
                    }
                }
                else {
                    try {
                        // kid in the Jose header of id_token
                        for (var _h = __values(jwtkeys.keys), _j = _h.next(); !_j.done; _j = _h.next()) {
                            var key = _j.value;
                            if ((( /** @type {?} */(key.kid))) === (( /** @type {?} */(kid)))) {
                                /** @type {?} */
                                var publickey = jsrsasign.KEYUTIL.getKey(key);
                                isValid = jsrsasign.KJUR.jws.JWS.verify(id_token, publickey, ['RS256']);
                                if (!isValid) {
                                    this.loggerService.logWarning('incorrect Signature, validation failed for id_token');
                                }
                                return isValid;
                            }
                        }
                    }
                    catch (e_3_1) {
                        e_3 = { error: e_3_1 };
                    }
                    finally {
                        try {
                            if (_j && !_j.done && (_c = _h.return))
                                _c.call(_h);
                        }
                        finally {
                            if (e_3)
                                throw e_3.error;
                        }
                    }
                }
                return isValid;
            };
        /**
         * @param {?} response_type
         * @return {?}
         */
        OidcSecurityValidation.prototype.config_validate_response_type = /**
         * @param {?} response_type
         * @return {?}
         */
            function (response_type) {
                if (response_type === 'id_token token' || response_type === 'id_token') {
                    return true;
                }
                if (response_type === 'code') {
                    return true;
                }
                this.loggerService.logWarning('module configure incorrect, invalid response_type:' + response_type);
                return false;
            };
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
        OidcSecurityValidation.prototype.validate_id_token_at_hash =
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
            function (access_token, at_hash, isCodeFlow) {
                this.loggerService.logDebug('at_hash from the server:' + at_hash);
                // The at_hash is optional for the code flow
                if (isCodeFlow) {
                    if (!(( /** @type {?} */(at_hash)))) {
                        this.loggerService.logDebug('Code Flow active, and no at_hash in the id_token, skipping check!');
                        return true;
                    }
                }
                /** @type {?} */
                var testdata = this.generate_at_hash('' + access_token);
                this.loggerService.logDebug('at_hash client validation not decoded:' + testdata);
                if (testdata === (( /** @type {?} */(at_hash)))) {
                    return true; // isValid;
                }
                else {
                    /** @type {?} */
                    var testValue = this.generate_at_hash('' + decodeURIComponent(access_token));
                    this.loggerService.logDebug('-gen access--' + testValue);
                    if (testValue === (( /** @type {?} */(at_hash)))) {
                        return true; // isValid
                    }
                }
                return false;
            };
        /**
         * @private
         * @param {?} access_token
         * @return {?}
         */
        OidcSecurityValidation.prototype.generate_at_hash = /**
         * @private
         * @param {?} access_token
         * @return {?}
         */
            function (access_token) {
                /** @type {?} */
                var hash = jsrsasign.KJUR.crypto.Util.hashString(access_token, 'sha256');
                /** @type {?} */
                var first128bits = hash.substr(0, hash.length / 2);
                /** @type {?} */
                var testdata = jsrsasign.hextob64u(first128bits);
                return testdata;
            };
        /**
         * @param {?} code_challenge
         * @return {?}
         */
        OidcSecurityValidation.prototype.generate_code_verifier = /**
         * @param {?} code_challenge
         * @return {?}
         */
            function (code_challenge) {
                /** @type {?} */
                var hash = jsrsasign.KJUR.crypto.Util.hashString(code_challenge, 'sha256');
                /** @type {?} */
                var testdata = jsrsasign.hextob64u(hash);
                return testdata;
            };
        OidcSecurityValidation.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        OidcSecurityValidation.ctorParameters = function () {
            return [
                { type: EqualityHelperService },
                { type: TokenHelperService },
                { type: LoggerService }
            ];
        };
        return OidcSecurityValidation;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var StateValidationService = /** @class */ (function () {
        function StateValidationService(authConfiguration, oidcSecurityCommon, oidcSecurityValidation, tokenHelperService, loggerService) {
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
        StateValidationService.prototype.setupModule = /**
         * @param {?} authWellKnownEndpoints
         * @return {?}
         */
            function (authWellKnownEndpoints) {
                this.authWellKnownEndpoints = Object.assign({}, authWellKnownEndpoints);
            };
        /**
         * @param {?} result
         * @param {?} jwtKeys
         * @return {?}
         */
        StateValidationService.prototype.validateState = /**
         * @param {?} result
         * @param {?} jwtKeys
         * @return {?}
         */
            function (result, jwtKeys) {
                /** @type {?} */
                var toReturn = new ValidateStateResult();
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
            };
        /**
         * @private
         * @return {?}
         */
        StateValidationService.prototype.handleSuccessfulValidation = /**
         * @private
         * @return {?}
         */
            function () {
                this.oidcSecurityCommon.authNonce = '';
                if (this.authConfiguration.auto_clean_state_after_authentication) {
                    this.oidcSecurityCommon.authStateControl = '';
                }
                this.loggerService.logDebug('AuthorizedCallback token(s) validated, continue');
            };
        /**
         * @private
         * @return {?}
         */
        StateValidationService.prototype.handleUnsuccessfulValidation = /**
         * @private
         * @return {?}
         */
            function () {
                this.oidcSecurityCommon.authNonce = '';
                if (this.authConfiguration.auto_clean_state_after_authentication) {
                    this.oidcSecurityCommon.authStateControl = '';
                }
                this.loggerService.logDebug('AuthorizedCallback token(s) invalid');
            };
        StateValidationService.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        StateValidationService.ctorParameters = function () {
            return [
                { type: AuthConfiguration },
                { type: OidcSecurityCommon },
                { type: OidcSecurityValidation },
                { type: TokenHelperService },
                { type: LoggerService }
            ];
        };
        return StateValidationService;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    /** @type {?} */
    var IFRAME_FOR_CHECK_SESSION_IDENTIFIER = 'myiFrameForCheckSession';
    // http://openid.net/specs/openid-connect-session-1_0-ID4.html
    var OidcSecurityCheckSession = /** @class */ (function () {
        function OidcSecurityCheckSession(authConfiguration, oidcSecurityCommon, loggerService, iFrameService, zone) {
            this.authConfiguration = authConfiguration;
            this.oidcSecurityCommon = oidcSecurityCommon;
            this.loggerService = loggerService;
            this.iFrameService = iFrameService;
            this.zone = zone;
            this.lastIFrameRefresh = 0;
            this.outstandingMessages = 0;
            this.heartBeatInterval = 3000;
            this.iframeRefreshInterval = 60000;
            this._onCheckSessionChanged = new rxjs.Subject();
        }
        Object.defineProperty(OidcSecurityCheckSession.prototype, "onCheckSessionChanged", {
            get: /**
             * @return {?}
             */ function () {
                return this._onCheckSessionChanged.asObservable();
            },
            enumerable: true,
            configurable: true
        });
        /**
         * @param {?} authWellKnownEndpoints
         * @return {?}
         */
        OidcSecurityCheckSession.prototype.setupModule = /**
         * @param {?} authWellKnownEndpoints
         * @return {?}
         */
            function (authWellKnownEndpoints) {
                this.authWellKnownEndpoints = Object.assign({}, authWellKnownEndpoints);
            };
        /**
         * @private
         * @return {?}
         */
        OidcSecurityCheckSession.prototype.doesSessionExist = /**
         * @private
         * @return {?}
         */
            function () {
                /** @type {?} */
                var existingIFrame = this.iFrameService.getExistingIFrame(IFRAME_FOR_CHECK_SESSION_IDENTIFIER);
                if (!existingIFrame) {
                    return false;
                }
                this.sessionIframe = existingIFrame;
                return true;
            };
        /**
         * @private
         * @return {?}
         */
        OidcSecurityCheckSession.prototype.init = /**
         * @private
         * @return {?}
         */
            function () {
                var _this = this;
                if (this.lastIFrameRefresh + this.iframeRefreshInterval > Date.now()) {
                    return rxjs.from([this]);
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
                return rxjs.Observable.create(( /**
                 * @param {?} observer
                 * @return {?}
                 */function (observer) {
                    _this.sessionIframe.onload = ( /**
                     * @return {?}
                     */function () {
                        _this.lastIFrameRefresh = Date.now();
                        observer.next(_this);
                        observer.complete();
                    });
                }));
            };
        /**
         * @param {?} clientId
         * @return {?}
         */
        OidcSecurityCheckSession.prototype.startCheckingSession = /**
         * @param {?} clientId
         * @return {?}
         */
            function (clientId) {
                if (this.scheduledHeartBeat) {
                    return;
                }
                this.pollServerSession(clientId);
            };
        /**
         * @return {?}
         */
        OidcSecurityCheckSession.prototype.stopCheckingSession = /**
         * @return {?}
         */
            function () {
                if (!this.scheduledHeartBeat) {
                    return;
                }
                this.clearScheduledHeartBeat();
            };
        /**
         * @private
         * @param {?} clientId
         * @return {?}
         */
        OidcSecurityCheckSession.prototype.pollServerSession = /**
         * @private
         * @param {?} clientId
         * @return {?}
         */
            function (clientId) {
                var _this = this;
                /** @type {?} */
                var _pollServerSessionRecur = ( /**
                 * @return {?}
                 */function () {
                    _this.init()
                        .pipe(operators.take(1))
                        .subscribe(( /**
                 * @return {?}
                 */function () {
                        if (_this.sessionIframe && clientId) {
                            _this.loggerService.logDebug(_this.sessionIframe);
                            /** @type {?} */
                            var session_state = _this.oidcSecurityCommon.sessionState;
                            if (session_state) {
                                _this.outstandingMessages++;
                                _this.sessionIframe.contentWindow.postMessage(clientId + ' ' + session_state, _this.authConfiguration.stsServer);
                            }
                            else {
                                _this.loggerService.logDebug('OidcSecurityCheckSession pollServerSession session_state is blank');
                                _this._onCheckSessionChanged.next();
                            }
                        }
                        else {
                            _this.loggerService.logWarning('OidcSecurityCheckSession pollServerSession sessionIframe does not exist');
                            _this.loggerService.logDebug(clientId);
                            _this.loggerService.logDebug(_this.sessionIframe);
                            // this.init();
                        }
                        // after sending three messages with no response, fail.
                        if (_this.outstandingMessages > 3) {
                            _this.loggerService.logError("OidcSecurityCheckSession not receiving check session response messages. Outstanding messages: " + _this.outstandingMessages + ". Server unreachable?");
                            _this._onCheckSessionChanged.next();
                        }
                        _this.scheduledHeartBeat = setTimeout(_pollServerSessionRecur, _this.heartBeatInterval);
                    }));
                });
                this.outstandingMessages = 0;
                this.zone.runOutsideAngular(( /**
                 * @return {?}
                 */function () {
                    _this.scheduledHeartBeat = setTimeout(_pollServerSessionRecur, _this.heartBeatInterval);
                }));
            };
        /**
         * @private
         * @return {?}
         */
        OidcSecurityCheckSession.prototype.clearScheduledHeartBeat = /**
         * @private
         * @return {?}
         */
            function () {
                clearTimeout(this.scheduledHeartBeat);
                this.scheduledHeartBeat = null;
            };
        /**
         * @private
         * @param {?} e
         * @return {?}
         */
        OidcSecurityCheckSession.prototype.messageHandler = /**
         * @private
         * @param {?} e
         * @return {?}
         */
            function (e) {
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
            };
        OidcSecurityCheckSession.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        OidcSecurityCheckSession.ctorParameters = function () {
            return [
                { type: AuthConfiguration },
                { type: OidcSecurityCommon },
                { type: LoggerService },
                { type: IFrameService },
                { type: core.NgZone }
            ];
        };
        return OidcSecurityCheckSession;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var OidcConfigService = /** @class */ (function () {
        function OidcConfigService(httpClient) {
            this.httpClient = httpClient;
            this._onConfigurationLoaded = new rxjs.Subject();
        }
        Object.defineProperty(OidcConfigService.prototype, "onConfigurationLoaded", {
            get: /**
             * @return {?}
             */ function () {
                return this._onConfigurationLoaded.asObservable();
            },
            enumerable: true,
            configurable: true
        });
        /**
         * @param {?} configUrl
         * @return {?}
         */
        OidcConfigService.prototype.load = /**
         * @param {?} configUrl
         * @return {?}
         */
            function (configUrl) {
                var _this = this;
                this.httpClient
                    .get(configUrl)
                    .pipe(operators.map(( /**
             * @param {?} response
             * @return {?}
             */function (response) {
                    _this.clientConfiguration = response;
                    _this.load_using_stsServer(_this.clientConfiguration.stsServer);
                })), operators.catchError(( /**
                 * @param {?} error
                 * @return {?}
                 */function (error) {
                    console.error("OidcConfigService 'load' threw an error on calling " + configUrl, error);
                    _this._onConfigurationLoaded.next(false);
                    return rxjs.of(false);
                })))
                    .subscribe();
            };
        /**
         * @param {?} stsServer
         * @return {?}
         */
        OidcConfigService.prototype.load_using_stsServer = /**
         * @param {?} stsServer
         * @return {?}
         */
            function (stsServer) {
                var _this = this;
                /** @type {?} */
                var url = stsServer + "/.well-known/openid-configuration";
                this.httpClient
                    .get(url)
                    .pipe(operators.map(( /**
             * @param {?} response
             * @return {?}
             */function (response) {
                    _this.wellKnownEndpoints = response;
                    _this._onConfigurationLoaded.next(true);
                })), operators.catchError(( /**
                 * @param {?} error
                 * @return {?}
                 */function (error) {
                    console.error("OidcConfigService 'load_using_stsServer' threw an error on calling " + stsServer, error);
                    _this._onConfigurationLoaded.next(false);
                    return rxjs.of(false);
                })))
                    .subscribe();
            };
        /**
         * @param {?} url
         * @return {?}
         */
        OidcConfigService.prototype.load_using_custom_stsServer = /**
         * @param {?} url
         * @return {?}
         */
            function (url) {
                var _this = this;
                this.httpClient
                    .get(url)
                    .pipe(operators.map(( /**
             * @param {?} response
             * @return {?}
             */function (response) {
                    _this.wellKnownEndpoints = response;
                    _this._onConfigurationLoaded.next(true);
                })), operators.catchError(( /**
                 * @param {?} error
                 * @return {?}
                 */function (error) {
                    console.error("OidcConfigService 'load_using_custom_stsServer' threw an error on calling " + url, error);
                    _this._onConfigurationLoaded.next(false);
                    return rxjs.of(false);
                })))
                    .subscribe();
            };
        OidcConfigService.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        OidcConfigService.ctorParameters = function () {
            return [
                { type: http.HttpClient }
            ];
        };
        return OidcConfigService;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    /** @type {?} */
    var IFRAME_FOR_SILENT_RENEW_IDENTIFIER = 'myiFrameForSilentRenew';
    var OidcSecuritySilentRenew = /** @class */ (function () {
        function OidcSecuritySilentRenew(loggerService, iFrameService) {
            this.loggerService = loggerService;
            this.iFrameService = iFrameService;
            this.isRenewInitialized = false;
        }
        /**
         * @return {?}
         */
        OidcSecuritySilentRenew.prototype.initRenew = /**
         * @return {?}
         */
            function () {
                /** @type {?} */
                var existingIFrame = this.iFrameService.getExistingIFrame(IFRAME_FOR_SILENT_RENEW_IDENTIFIER);
                if (!existingIFrame) {
                    this.iFrameService.addIFrameToWindowBody(IFRAME_FOR_SILENT_RENEW_IDENTIFIER);
                }
                this.isRenewInitialized = true;
            };
        /**
         * @param {?} url
         * @return {?}
         */
        OidcSecuritySilentRenew.prototype.startRenew = /**
         * @param {?} url
         * @return {?}
         */
            function (url) {
                var _this = this;
                if (!this.isRenewInitialized) {
                    this.initRenew();
                }
                this.sessionIframe = this.iFrameService.getExistingIFrame(IFRAME_FOR_SILENT_RENEW_IDENTIFIER);
                this.loggerService.logDebug('startRenew for URL:' + url);
                this.sessionIframe.contentWindow.location.replace(url);
                return rxjs.Observable.create(( /**
                 * @param {?} observer
                 * @return {?}
                 */function (observer) {
                    _this.sessionIframe.onload = ( /**
                     * @return {?}
                     */function () {
                        observer.next(_this);
                        observer.complete();
                    });
                }));
            };
        OidcSecuritySilentRenew.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        OidcSecuritySilentRenew.ctorParameters = function () {
            return [
                { type: LoggerService },
                { type: IFrameService }
            ];
        };
        return OidcSecuritySilentRenew;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var OidcSecurityUserService = /** @class */ (function () {
        function OidcSecurityUserService(oidcDataService, oidcSecurityCommon, loggerService) {
            this.oidcDataService = oidcDataService;
            this.oidcSecurityCommon = oidcSecurityCommon;
            this.loggerService = loggerService;
            this.userData = '';
        }
        /**
         * @param {?} authWellKnownEndpoints
         * @return {?}
         */
        OidcSecurityUserService.prototype.setupModule = /**
         * @param {?} authWellKnownEndpoints
         * @return {?}
         */
            function (authWellKnownEndpoints) {
                this.authWellKnownEndpoints = Object.assign({}, authWellKnownEndpoints);
            };
        /**
         * @return {?}
         */
        OidcSecurityUserService.prototype.initUserData = /**
         * @return {?}
         */
            function () {
                var _this = this;
                return this.getIdentityUserData().pipe(operators.map(( /**
                 * @param {?} data
                 * @return {?}
                 */function (data) { return (_this.userData = data); })));
            };
        /**
         * @return {?}
         */
        OidcSecurityUserService.prototype.getUserData = /**
         * @return {?}
         */
            function () {
                if (!this.userData) {
                    throw Error('UserData is not set!');
                }
                return this.userData;
            };
        /**
         * @param {?} value
         * @return {?}
         */
        OidcSecurityUserService.prototype.setUserData = /**
         * @param {?} value
         * @return {?}
         */
            function (value) {
                this.userData = value;
            };
        /**
         * @private
         * @return {?}
         */
        OidcSecurityUserService.prototype.getIdentityUserData = /**
         * @private
         * @return {?}
         */
            function () {
                /** @type {?} */
                var token = this.oidcSecurityCommon.getAccessToken();
                if (!this.authWellKnownEndpoints) {
                    this.loggerService.logWarning('init check session: authWellKnownEndpoints is undefined');
                    throw Error('authWellKnownEndpoints is undefined');
                }
                /** @type {?} */
                var canGetUserData = this.authWellKnownEndpoints && this.authWellKnownEndpoints.userinfo_endpoint;
                if (!canGetUserData) {
                    this.loggerService.logError('init check session: authWellKnownEndpoints.userinfo_endpoint is undefined; set auto_userinfo = false in config');
                    throw Error('authWellKnownEndpoints.userinfo_endpoint is undefined');
                }
                return this.oidcDataService.getIdentityUserData(this.authWellKnownEndpoints.userinfo_endpoint, token);
            };
        OidcSecurityUserService.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        OidcSecurityUserService.ctorParameters = function () {
            return [
                { type: OidcDataService },
                { type: OidcSecurityCommon },
                { type: LoggerService }
            ];
        };
        return OidcSecurityUserService;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var UriEncoder = /** @class */ (function () {
        function UriEncoder() {
        }
        /**
         * @param {?} key
         * @return {?}
         */
        UriEncoder.prototype.encodeKey = /**
         * @param {?} key
         * @return {?}
         */
            function (key) {
                return encodeURIComponent(key);
            };
        /**
         * @param {?} value
         * @return {?}
         */
        UriEncoder.prototype.encodeValue = /**
         * @param {?} value
         * @return {?}
         */
            function (value) {
                return encodeURIComponent(value);
            };
        /**
         * @param {?} key
         * @return {?}
         */
        UriEncoder.prototype.decodeKey = /**
         * @param {?} key
         * @return {?}
         */
            function (key) {
                return decodeURIComponent(key);
            };
        /**
         * @param {?} value
         * @return {?}
         */
        UriEncoder.prototype.decodeValue = /**
         * @param {?} value
         * @return {?}
         */
            function (value) {
                return decodeURIComponent(value);
            };
        return UriEncoder;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var OidcSecurityService = /** @class */ (function () {
        function OidcSecurityService(oidcDataService, stateValidationService, authConfiguration, router$$1, oidcSecurityCheckSession, oidcSecuritySilentRenew, oidcSecurityUserService, oidcSecurityCommon, oidcSecurityValidation, tokenHelperService, loggerService, zone, httpClient) {
            var _this = this;
            this.oidcDataService = oidcDataService;
            this.stateValidationService = stateValidationService;
            this.authConfiguration = authConfiguration;
            this.router = router$$1;
            this.oidcSecurityCheckSession = oidcSecurityCheckSession;
            this.oidcSecuritySilentRenew = oidcSecuritySilentRenew;
            this.oidcSecurityUserService = oidcSecurityUserService;
            this.oidcSecurityCommon = oidcSecurityCommon;
            this.oidcSecurityValidation = oidcSecurityValidation;
            this.tokenHelperService = tokenHelperService;
            this.loggerService = loggerService;
            this.zone = zone;
            this.httpClient = httpClient;
            this._onModuleSetup = new rxjs.Subject();
            this._onCheckSessionChanged = new rxjs.Subject();
            this._onAuthorizationResult = new rxjs.Subject();
            this.checkSessionChanged = false;
            this.moduleSetup = false;
            this._isModuleSetup = new rxjs.BehaviorSubject(false);
            this._isAuthorized = new rxjs.BehaviorSubject(false);
            this._userData = new rxjs.BehaviorSubject('');
            this.authWellKnownEndpointsLoaded = false;
            this.runTokenValidationRunning = false;
            this.onModuleSetup.pipe(operators.take(1)).subscribe(( /**
             * @return {?}
             */function () {
                _this.moduleSetup = true;
                _this._isModuleSetup.next(true);
            }));
            this._isSetupAndAuthorized = this._isModuleSetup.pipe(operators.filter(( /**
             * @param {?} isModuleSetup
             * @return {?}
             */function (isModuleSetup) { return isModuleSetup; })), operators.switchMap(( /**
             * @return {?}
             */function () {
                if (!_this.authConfiguration.silent_renew) {
                    return rxjs.from([true]).pipe(operators.tap(( /**
                     * @return {?}
                     */function () { return _this.loggerService.logDebug("IsAuthorizedRace: Silent Renew Not Active. Emitting."); })));
                }
                /** @type {?} */
                var race$ = _this._isAuthorized.asObservable().pipe(operators.filter(( /**
                 * @param {?} isAuthorized
                 * @return {?}
                 */function (isAuthorized) { return isAuthorized; })), operators.take(1), operators.tap(( /**
                 * @return {?}
                 */function () { return _this.loggerService.logDebug('IsAuthorizedRace: Existing token is still authorized.'); })), operators.race(_this._onAuthorizationResult.pipe(operators.take(1), operators.tap(( /**
                 * @return {?}
                 */function () { return _this.loggerService.logDebug('IsAuthorizedRace: Silent Renew Refresh Session Complete'); })), operators.map(( /**
                 * @return {?}
                 */function () { return true; }))), rxjs.timer(5000).pipe(
                // backup, if nothing happens after 5 seconds stop waiting and emit
                operators.tap(( /**
                 * @return {?}
                 */function () {
                    _this.resetAuthorizationData(false);
                    _this.oidcSecurityCommon.authNonce = '';
                    _this.loggerService.logWarning('IsAuthorizedRace: Timeout reached. Emitting.');
                })), operators.map(( /**
                 * @return {?}
                 */function () { return true; })))));
                _this.loggerService.logDebug('Silent Renew is active, check if token in storage is active');
                if (_this.oidcSecurityCommon.authNonce === '' || _this.oidcSecurityCommon.authNonce === undefined) {
                    // login not running, or a second silent renew, user must login first before this will work.
                    _this.loggerService.logDebug('Silent Renew or login not running, try to refresh the session');
                    _this.refreshSession();
                }
                return race$;
            })), operators.tap(( /**
             * @return {?}
             */function () { return _this.loggerService.logDebug('IsAuthorizedRace: Completed'); })), operators.switchMapTo(this._isAuthorized.asObservable()), operators.tap(( /**
             * @param {?} isAuthorized
             * @return {?}
             */function (isAuthorized) { return _this.loggerService.logDebug("getIsAuthorized: " + isAuthorized); })), operators.shareReplay(1));
            this._isSetupAndAuthorized.pipe(operators.filter(( /**
             * @return {?}
             */function () { return _this.authConfiguration.start_checksession; }))).subscribe(( /**
             * @param {?} isSetupAndAuthorized
             * @return {?}
             */function (isSetupAndAuthorized) {
                if (isSetupAndAuthorized) {
                    _this.oidcSecurityCheckSession.startCheckingSession(_this.authConfiguration.client_id);
                }
                else {
                    _this.oidcSecurityCheckSession.stopCheckingSession();
                }
            }));
        }
        Object.defineProperty(OidcSecurityService.prototype, "onModuleSetup", {
            get: /**
             * @return {?}
             */ function () {
                return this._onModuleSetup.asObservable();
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityService.prototype, "onAuthorizationResult", {
            get: /**
             * @return {?}
             */ function () {
                return this._onAuthorizationResult.asObservable();
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityService.prototype, "onCheckSessionChanged", {
            get: /**
             * @return {?}
             */ function () {
                return this._onCheckSessionChanged.asObservable();
            },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(OidcSecurityService.prototype, "onConfigurationChange", {
            get: /**
             * @return {?}
             */ function () {
                return this.authConfiguration.onConfigurationChange;
            },
            enumerable: true,
            configurable: true
        });
        /**
         * @param {?} openIDImplicitFlowConfiguration
         * @param {?} authWellKnownEndpoints
         * @return {?}
         */
        OidcSecurityService.prototype.setupModule = /**
         * @param {?} openIDImplicitFlowConfiguration
         * @param {?} authWellKnownEndpoints
         * @return {?}
         */
            function (openIDImplicitFlowConfiguration, authWellKnownEndpoints) {
                var _this = this;
                this.authWellKnownEndpoints = Object.assign({}, authWellKnownEndpoints);
                this.authConfiguration.init(openIDImplicitFlowConfiguration);
                this.stateValidationService.setupModule(authWellKnownEndpoints);
                this.oidcSecurityCheckSession.setupModule(authWellKnownEndpoints);
                this.oidcSecurityUserService.setupModule(authWellKnownEndpoints);
                this.oidcSecurityCheckSession.onCheckSessionChanged.subscribe(( /**
                 * @return {?}
                 */function () {
                    _this.loggerService.logDebug('onCheckSessionChanged');
                    _this.checkSessionChanged = true;
                    _this._onCheckSessionChanged.next(_this.checkSessionChanged);
                }));
                /** @type {?} */
                var userData = this.oidcSecurityCommon.userData;
                if (userData) {
                    this.setUserData(userData);
                }
                /** @type {?} */
                var isAuthorized = this.oidcSecurityCommon.isAuthorized;
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
                    var instanceId_1 = Math.random();
                    /** @type {?} */
                    var boundSilentRenewInitEvent_1 = (( /**
                     * @param {?} e
                     * @return {?}
                     */function (e) {
                        if (e.detail !== instanceId_1) {
                            window.removeEventListener('oidc-silent-renew-message', _this.boundSilentRenewEvent);
                            window.removeEventListener('oidc-silent-renew-init', boundSilentRenewInitEvent_1);
                        }
                    })).bind(this);
                    window.addEventListener('oidc-silent-renew-init', boundSilentRenewInitEvent_1, false);
                    window.addEventListener('oidc-silent-renew-message', this.boundSilentRenewEvent, false);
                    window.dispatchEvent(new CustomEvent('oidc-silent-renew-init', {
                        detail: instanceId_1,
                    }));
                }
            };
        /**
         * @return {?}
         */
        OidcSecurityService.prototype.getUserData = /**
         * @return {?}
         */
            function () {
                return this._userData.asObservable();
            };
        /**
         * @return {?}
         */
        OidcSecurityService.prototype.getIsModuleSetup = /**
         * @return {?}
         */
            function () {
                return this._isModuleSetup.asObservable();
            };
        /**
         * @return {?}
         */
        OidcSecurityService.prototype.getIsAuthorized = /**
         * @return {?}
         */
            function () {
                return this._isSetupAndAuthorized;
            };
        /**
         * @return {?}
         */
        OidcSecurityService.prototype.getToken = /**
         * @return {?}
         */
            function () {
                if (!this._isAuthorized.getValue()) {
                    return '';
                }
                /** @type {?} */
                var token = this.oidcSecurityCommon.getAccessToken();
                return decodeURIComponent(token);
            };
        /**
         * @return {?}
         */
        OidcSecurityService.prototype.getIdToken = /**
         * @return {?}
         */
            function () {
                if (!this._isAuthorized.getValue()) {
                    return '';
                }
                /** @type {?} */
                var token = this.oidcSecurityCommon.getIdToken();
                return decodeURIComponent(token);
            };
        /**
         * @param {?=} encode
         * @return {?}
         */
        OidcSecurityService.prototype.getPayloadFromIdToken = /**
         * @param {?=} encode
         * @return {?}
         */
            function (encode) {
                if (encode === void 0) {
                    encode = false;
                }
                /** @type {?} */
                var token = this.getIdToken();
                return this.tokenHelperService.getPayloadFromToken(token, encode);
            };
        /**
         * @param {?} state
         * @return {?}
         */
        OidcSecurityService.prototype.setState = /**
         * @param {?} state
         * @return {?}
         */
            function (state) {
                this.oidcSecurityCommon.authStateControl = state;
            };
        /**
         * @return {?}
         */
        OidcSecurityService.prototype.getState = /**
         * @return {?}
         */
            function () {
                return this.oidcSecurityCommon.authStateControl;
            };
        /**
         * @param {?} params
         * @return {?}
         */
        OidcSecurityService.prototype.setCustomRequestParameters = /**
         * @param {?} params
         * @return {?}
         */
            function (params) {
                this.oidcSecurityCommon.customRequestParams = params;
            };
        // Code Flow with PCKE or Implicit Flow
        // Code Flow with PCKE or Implicit Flow
        /**
         * @param {?=} urlHandler
         * @return {?}
         */
        OidcSecurityService.prototype.authorize =
            // Code Flow with PCKE or Implicit Flow
            /**
             * @param {?=} urlHandler
             * @return {?}
             */
            function (urlHandler) {
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
                var state = this.oidcSecurityCommon.authStateControl;
                if (!state) {
                    state = Date.now() + '' + Math.random() + Math.random();
                    this.oidcSecurityCommon.authStateControl = state;
                }
                /** @type {?} */
                var nonce = 'N' + Math.random() + '' + Date.now();
                this.oidcSecurityCommon.authNonce = nonce;
                this.loggerService.logDebug('AuthorizedController created. local state: ' + this.oidcSecurityCommon.authStateControl);
                /** @type {?} */
                var url = '';
                // Code Flow
                if (this.authConfiguration.response_type === 'code') {
                    // code_challenge with "S256"
                    /** @type {?} */
                    var code_verifier = 'C' + Math.random() + '' + Date.now() + '' + Date.now() + Math.random();
                    /** @type {?} */
                    var code_challenge = this.oidcSecurityValidation.generate_code_verifier(code_verifier);
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
            };
        // Code Flow
        // Code Flow
        /**
         * @param {?} urlToCheck
         * @return {?}
         */
        OidcSecurityService.prototype.authorizedCallbackWithCode =
            // Code Flow
            /**
             * @param {?} urlToCheck
             * @return {?}
             */
            function (urlToCheck) {
                /** @type {?} */
                var urlParts = urlToCheck.split('?');
                /** @type {?} */
                var params = new http.HttpParams({
                    fromString: urlParts[1]
                });
                /** @type {?} */
                var code = params.get('code');
                /** @type {?} */
                var state = params.get('state');
                /** @type {?} */
                var session_state = params.get('session_state');
                if (code && state) {
                    this.requestTokensWithCode(code, state, session_state);
                }
            };
        // Code Flow
        // Code Flow
        /**
         * @param {?} code
         * @param {?} state
         * @param {?} session_state
         * @return {?}
         */
        OidcSecurityService.prototype.requestTokensWithCode =
            // Code Flow
            /**
             * @param {?} code
             * @param {?} state
             * @param {?} session_state
             * @return {?}
             */
            function (code, state, session_state) {
                var _this = this;
                this._isModuleSetup
                    .pipe(operators.filter(( /**
             * @param {?} isModuleSetup
             * @return {?}
             */function (isModuleSetup) { return isModuleSetup; })), operators.take(1))
                    .subscribe(( /**
             * @return {?}
             */function () {
                    _this.requestTokensWithCodeProcedure(code, state, session_state);
                }));
            };
        // Code Flow with PCKE
        // Code Flow with PCKE
        /**
         * @param {?} code
         * @param {?} state
         * @param {?} session_state
         * @return {?}
         */
        OidcSecurityService.prototype.requestTokensWithCodeProcedure =
            // Code Flow with PCKE
            /**
             * @param {?} code
             * @param {?} state
             * @param {?} session_state
             * @return {?}
             */
            function (code, state, session_state) {
                var _this = this;
                /** @type {?} */
                var tokenRequestUrl = '';
                if (this.authWellKnownEndpoints && this.authWellKnownEndpoints.token_endpoint) {
                    tokenRequestUrl = "" + this.authWellKnownEndpoints.token_endpoint;
                }
                if (!this.oidcSecurityValidation.validateStateFromHashCallback(state, this.oidcSecurityCommon.authStateControl)) {
                    this.loggerService.logWarning('authorizedCallback incorrect state');
                    // ValidationResult.StatesDoNotMatch;
                    return;
                }
                /** @type {?} */
                var headers = new http.HttpHeaders();
                headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
                /** @type {?} */
                var data = "grant_type=authorization_code&client_id=" + this.authConfiguration.client_id
                    + ("&code_verifier=" + this.oidcSecurityCommon.code_verifier + "&code=" + code + "&redirect_uri=" + this.authConfiguration.redirect_url);
                if (this.oidcSecurityCommon.silentRenewRunning === 'running') {
                    data = "grant_type=authorization_code&client_id=" + this.authConfiguration.client_id
                        + ("&code_verifier=" + this.oidcSecurityCommon.code_verifier + "&code=" + code + "&redirect_uri=" + this.authConfiguration.silent_redirect_url);
                }
                this.httpClient
                    .post(tokenRequestUrl, data, { headers: headers })
                    .pipe(operators.map(( /**
             * @param {?} response
             * @return {?}
             */function (response) {
                    /** @type {?} */
                    var obj = new Object;
                    obj = response;
                    obj.state = state;
                    obj.session_state = session_state;
                    _this.authorizedCodeFlowCallbackProcedure(obj);
                })), operators.catchError(( /**
                 * @param {?} error
                 * @return {?}
                 */function (error) {
                    _this.loggerService.logError(error);
                    _this.loggerService.logError("OidcService code request " + _this.authConfiguration.stsServer);
                    return rxjs.of(false);
                })))
                    .subscribe();
            };
        // Code Flow
        // Code Flow
        /**
         * @private
         * @param {?} result
         * @return {?}
         */
        OidcSecurityService.prototype.authorizedCodeFlowCallbackProcedure =
            // Code Flow
            /**
             * @private
             * @param {?} result
             * @return {?}
             */
            function (result) {
                /** @type {?} */
                var silentRenew = this.oidcSecurityCommon.silentRenewRunning;
                /** @type {?} */
                var isRenewProcess = silentRenew === 'running';
                this.loggerService.logDebug('BEGIN authorized Code Flow Callback, no auth data');
                this.resetAuthorizationData(isRenewProcess);
                this.authorizedCallbackProcedure(result, isRenewProcess);
            };
        // Implicit Flow
        // Implicit Flow
        /**
         * @private
         * @param {?=} hash
         * @return {?}
         */
        OidcSecurityService.prototype.authorizedImplicitFlowCallbackProcedure =
            // Implicit Flow
            /**
             * @private
             * @param {?=} hash
             * @return {?}
             */
            function (hash) {
                /** @type {?} */
                var silentRenew = this.oidcSecurityCommon.silentRenewRunning;
                /** @type {?} */
                var isRenewProcess = silentRenew === 'running';
                this.loggerService.logDebug('BEGIN authorizedCallback, no auth data');
                this.resetAuthorizationData(isRenewProcess);
                hash = hash || window.location.hash.substr(1);
                /** @type {?} */
                var result = hash.split('&').reduce(( /**
                 * @param {?} resultData
                 * @param {?} item
                 * @return {?}
                 */function (resultData, item) {
                    /** @type {?} */
                    var parts = item.split('=');
                    resultData[( /** @type {?} */(parts.shift()))] = parts.join('=');
                    return resultData;
                }), {});
                this.authorizedCallbackProcedure(result, isRenewProcess);
            };
        // Implicit Flow
        // Implicit Flow
        /**
         * @param {?=} hash
         * @return {?}
         */
        OidcSecurityService.prototype.authorizedImplicitFlowCallback =
            // Implicit Flow
            /**
             * @param {?=} hash
             * @return {?}
             */
            function (hash) {
                var _this = this;
                this._isModuleSetup
                    .pipe(operators.filter(( /**
             * @param {?} isModuleSetup
             * @return {?}
             */function (isModuleSetup) { return isModuleSetup; })), operators.take(1))
                    .subscribe(( /**
             * @return {?}
             */function () {
                    _this.authorizedImplicitFlowCallbackProcedure(hash);
                }));
            };
        /**
         * @private
         * @param {?} url
         * @return {?}
         */
        OidcSecurityService.prototype.redirectTo = /**
         * @private
         * @param {?} url
         * @return {?}
         */
            function (url) {
                window.location.href = url;
            };
        // Implicit Flow
        // Implicit Flow
        /**
         * @private
         * @param {?} result
         * @param {?} isRenewProcess
         * @return {?}
         */
        OidcSecurityService.prototype.authorizedCallbackProcedure =
            // Implicit Flow
            /**
             * @private
             * @param {?} result
             * @param {?} isRenewProcess
             * @return {?}
             */
            function (result, isRenewProcess) {
                var _this = this;
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
                    if ((( /** @type {?} */(result.error))) === 'login_required') {
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
                    this.getSigningKeys().subscribe(( /**
                     * @param {?} jwtKeys
                     * @return {?}
                     */function (jwtKeys) {
                        /** @type {?} */
                        var validationResult = _this.getValidatedStateResult(result, jwtKeys);
                        if (validationResult.authResponseIsValid) {
                            _this.setAuthorizationData(validationResult.access_token, validationResult.id_token);
                            _this.oidcSecurityCommon.silentRenewRunning = '';
                            if (_this.authConfiguration.auto_userinfo) {
                                _this.getUserinfo(isRenewProcess, result, validationResult.id_token, validationResult.decoded_id_token).subscribe(( /**
                                 * @param {?} response
                                 * @return {?}
                                 */function (response) {
                                    if (response) {
                                        _this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.authorized, validationResult.state));
                                        if (!_this.authConfiguration.trigger_authorization_result_event && !isRenewProcess) {
                                            _this.router.navigate([_this.authConfiguration.post_login_route]);
                                        }
                                    }
                                    else {
                                        _this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.unauthorized, validationResult.state));
                                        if (!_this.authConfiguration.trigger_authorization_result_event && !isRenewProcess) {
                                            _this.router.navigate([_this.authConfiguration.unauthorized_route]);
                                        }
                                    }
                                }), ( /**
                                 * @param {?} err
                                 * @return {?}
                                 */function (err) {
                                    /* Something went wrong while getting signing key */
                                    _this.loggerService.logWarning('Failed to retreive user info with error: ' + JSON.stringify(err));
                                }));
                            }
                            else {
                                if (!isRenewProcess) {
                                    // userData is set to the id_token decoded, auto get user data set to false
                                    _this.oidcSecurityUserService.setUserData(validationResult.decoded_id_token);
                                    _this.setUserData(_this.oidcSecurityUserService.getUserData());
                                }
                                _this.runTokenValidation();
                                _this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.authorized, validationResult.state));
                                if (!_this.authConfiguration.trigger_authorization_result_event && !isRenewProcess) {
                                    _this.router.navigate([_this.authConfiguration.post_login_route]);
                                }
                            }
                        }
                        else {
                            // something went wrong
                            _this.loggerService.logWarning('authorizedCallback, token(s) validation failed, resetting');
                            _this.loggerService.logWarning(window.location.hash);
                            _this.resetAuthorizationData(false);
                            _this.oidcSecurityCommon.silentRenewRunning = '';
                            _this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.unauthorized, validationResult.state));
                            if (!_this.authConfiguration.trigger_authorization_result_event && !isRenewProcess) {
                                _this.router.navigate([_this.authConfiguration.unauthorized_route]);
                            }
                        }
                    }), ( /**
                     * @param {?} err
                     * @return {?}
                     */function (err) {
                        /* Something went wrong while getting signing key */
                        _this.loggerService.logWarning('Failed to retreive siging key with error: ' + JSON.stringify(err));
                        _this.oidcSecurityCommon.silentRenewRunning = '';
                    }));
                }
            };
        /**
         * @param {?=} isRenewProcess
         * @param {?=} result
         * @param {?=} id_token
         * @param {?=} decoded_id_token
         * @return {?}
         */
        OidcSecurityService.prototype.getUserinfo = /**
         * @param {?=} isRenewProcess
         * @param {?=} result
         * @param {?=} id_token
         * @param {?=} decoded_id_token
         * @return {?}
         */
            function (isRenewProcess, result, id_token, decoded_id_token) {
                var _this = this;
                if (isRenewProcess === void 0) {
                    isRenewProcess = false;
                }
                result = result ? result : this.oidcSecurityCommon.authResult;
                id_token = id_token ? id_token : this.oidcSecurityCommon.idToken;
                decoded_id_token = decoded_id_token ? decoded_id_token : this.tokenHelperService.getPayloadFromToken(id_token, false);
                return new rxjs.Observable(( /**
                 * @param {?} observer
                 * @return {?}
                 */function (observer) {
                    // flow id_token token
                    if (_this.authConfiguration.response_type === 'id_token token' || _this.authConfiguration.response_type === 'code') {
                        if (isRenewProcess && _this._userData.value) {
                            _this.oidcSecurityCommon.sessionState = result.session_state;
                            observer.next(true);
                            observer.complete();
                        }
                        else {
                            _this.oidcSecurityUserService.initUserData().subscribe(( /**
                             * @return {?}
                             */function () {
                                _this.loggerService.logDebug('authorizedCallback (id_token token || code) flow');
                                /** @type {?} */
                                var userData = _this.oidcSecurityUserService.getUserData();
                                if (_this.oidcSecurityValidation.validate_userdata_sub_id_token(decoded_id_token.sub, userData.sub)) {
                                    _this.setUserData(userData);
                                    _this.loggerService.logDebug(_this.oidcSecurityCommon.accessToken);
                                    _this.loggerService.logDebug(_this.oidcSecurityUserService.getUserData());
                                    _this.oidcSecurityCommon.sessionState = result.session_state;
                                    _this.runTokenValidation();
                                    observer.next(true);
                                }
                                else {
                                    // something went wrong, userdata sub does not match that from id_token
                                    _this.loggerService.logWarning('authorizedCallback, User data sub does not match sub in id_token');
                                    _this.loggerService.logDebug('authorizedCallback, token(s) validation failed, resetting');
                                    _this.resetAuthorizationData(false);
                                    observer.next(false);
                                }
                                observer.complete();
                            }));
                        }
                    }
                    else {
                        // flow id_token
                        _this.loggerService.logDebug('authorizedCallback id_token flow');
                        _this.loggerService.logDebug(_this.oidcSecurityCommon.accessToken);
                        // userData is set to the id_token decoded. No access_token.
                        _this.oidcSecurityUserService.setUserData(decoded_id_token);
                        _this.setUserData(_this.oidcSecurityUserService.getUserData());
                        _this.oidcSecurityCommon.sessionState = result.session_state;
                        _this.runTokenValidation();
                        observer.next(true);
                        observer.complete();
                    }
                }));
            };
        /**
         * @param {?=} urlHandler
         * @return {?}
         */
        OidcSecurityService.prototype.logoff = /**
         * @param {?=} urlHandler
         * @return {?}
         */
            function (urlHandler) {
                // /connect/endsession?id_token_hint=...&post_logout_redirect_uri=https://myapp.com
                this.loggerService.logDebug('BEGIN Authorize, no auth data');
                if (this.authWellKnownEndpoints) {
                    if (this.authWellKnownEndpoints.end_session_endpoint) {
                        /** @type {?} */
                        var end_session_endpoint = this.authWellKnownEndpoints.end_session_endpoint;
                        /** @type {?} */
                        var id_token_hint = this.oidcSecurityCommon.idToken;
                        /** @type {?} */
                        var url = this.createEndSessionUrl(end_session_endpoint, id_token_hint);
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
            };
        /**
         * @return {?}
         */
        OidcSecurityService.prototype.refreshSession = /**
         * @return {?}
         */
            function () {
                if (!this.authConfiguration.silent_renew) {
                    return rxjs.from([false]);
                }
                this.loggerService.logDebug('BEGIN refresh session Authorize');
                /** @type {?} */
                var state = this.oidcSecurityCommon.authStateControl;
                if (state === '' || state === null) {
                    state = Date.now() + '' + Math.random() + Math.random();
                    this.oidcSecurityCommon.authStateControl = state;
                }
                /** @type {?} */
                var nonce = 'N' + Math.random() + '' + Date.now();
                this.oidcSecurityCommon.authNonce = nonce;
                this.loggerService.logDebug('RefreshSession created. adding myautostate: ' + this.oidcSecurityCommon.authStateControl);
                /** @type {?} */
                var url = '';
                // Code Flow
                if (this.authConfiguration.response_type === 'code') {
                    // code_challenge with "S256"
                    /** @type {?} */
                    var code_verifier = 'C' + Math.random() + '' + Date.now() + '' + Date.now() + Math.random();
                    /** @type {?} */
                    var code_challenge = this.oidcSecurityValidation.generate_code_verifier(code_verifier);
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
            };
        /**
         * @param {?} error
         * @return {?}
         */
        OidcSecurityService.prototype.handleError = /**
         * @param {?} error
         * @return {?}
         */
            function (error) {
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
                    var silentRenew = this.oidcSecurityCommon.silentRenewRunning;
                    this.resetAuthorizationData(!!silentRenew);
                    if (this.authConfiguration.trigger_authorization_result_event) {
                        this._onAuthorizationResult.next(new AuthorizationResult(AuthorizationState.unauthorized, ValidationResult.NotSet));
                    }
                    else {
                        this.router.navigate([this.authConfiguration.unauthorized_route]);
                    }
                }
            };
        /**
         * @return {?}
         */
        OidcSecurityService.prototype.startCheckingSilentRenew = /**
         * @return {?}
         */
            function () {
                this.runTokenValidation();
            };
        /**
         * @return {?}
         */
        OidcSecurityService.prototype.stopCheckingSilentRenew = /**
         * @return {?}
         */
            function () {
                if (this._scheduledHeartBeat) {
                    clearTimeout(this._scheduledHeartBeat);
                    this._scheduledHeartBeat = null;
                    this.runTokenValidationRunning = false;
                }
            };
        /**
         * @param {?} isRenewProcess
         * @return {?}
         */
        OidcSecurityService.prototype.resetAuthorizationData = /**
         * @param {?} isRenewProcess
         * @return {?}
         */
            function (isRenewProcess) {
                if (!isRenewProcess) {
                    if (this.authConfiguration.auto_userinfo) {
                        // Clear user data. Fixes #97.
                        this.setUserData('');
                    }
                    this.oidcSecurityCommon.resetStorageData(isRenewProcess);
                    this.checkSessionChanged = false;
                    this.setIsAuthorized(false);
                }
            };
        /**
         * @return {?}
         */
        OidcSecurityService.prototype.getEndSessionUrl = /**
         * @return {?}
         */
            function () {
                if (this.authWellKnownEndpoints) {
                    if (this.authWellKnownEndpoints.end_session_endpoint) {
                        /** @type {?} */
                        var end_session_endpoint = this.authWellKnownEndpoints.end_session_endpoint;
                        /** @type {?} */
                        var id_token_hint = this.oidcSecurityCommon.idToken;
                        return this.createEndSessionUrl(end_session_endpoint, id_token_hint);
                    }
                }
            };
        /**
         * @private
         * @param {?} result
         * @param {?} jwtKeys
         * @return {?}
         */
        OidcSecurityService.prototype.getValidatedStateResult = /**
         * @private
         * @param {?} result
         * @param {?} jwtKeys
         * @return {?}
         */
            function (result, jwtKeys) {
                if (result.error) {
                    return new ValidateStateResult('', '', false, {});
                }
                return this.stateValidationService.validateState(result, jwtKeys);
            };
        /**
         * @private
         * @param {?} userData
         * @return {?}
         */
        OidcSecurityService.prototype.setUserData = /**
         * @private
         * @param {?} userData
         * @return {?}
         */
            function (userData) {
                this.oidcSecurityCommon.userData = userData;
                this._userData.next(userData);
            };
        /**
         * @private
         * @param {?} isAuthorized
         * @return {?}
         */
        OidcSecurityService.prototype.setIsAuthorized = /**
         * @private
         * @param {?} isAuthorized
         * @return {?}
         */
            function (isAuthorized) {
                this._isAuthorized.next(isAuthorized);
            };
        /**
         * @private
         * @param {?} access_token
         * @param {?} id_token
         * @return {?}
         */
        OidcSecurityService.prototype.setAuthorizationData = /**
         * @private
         * @param {?} access_token
         * @param {?} id_token
         * @return {?}
         */
            function (access_token, id_token) {
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
            };
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
        OidcSecurityService.prototype.createAuthorizeUrl = /**
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
            function (isCodeFlow, code_challenge, redirect_url, nonce, state, authorization_endpoint, prompt) {
                /** @type {?} */
                var urlParts = authorization_endpoint.split('?');
                /** @type {?} */
                var authorizationUrl = urlParts[0];
                /** @type {?} */
                var params = new http.HttpParams({
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
                var customParams = Object.assign({}, this.oidcSecurityCommon.customRequestParams);
                Object.keys(customParams).forEach(( /**
                 * @param {?} key
                 * @return {?}
                 */function (key) {
                    params = params.append(key, customParams[key].toString());
                }));
                return authorizationUrl + "?" + params;
            };
        /**
         * @private
         * @param {?} end_session_endpoint
         * @param {?} id_token_hint
         * @return {?}
         */
        OidcSecurityService.prototype.createEndSessionUrl = /**
         * @private
         * @param {?} end_session_endpoint
         * @param {?} id_token_hint
         * @return {?}
         */
            function (end_session_endpoint, id_token_hint) {
                /** @type {?} */
                var urlParts = end_session_endpoint.split('?');
                /** @type {?} */
                var authorizationEndsessionUrl = urlParts[0];
                /** @type {?} */
                var params = new http.HttpParams({
                    fromString: urlParts[1],
                    encoder: new UriEncoder(),
                });
                params = params.set('id_token_hint', id_token_hint);
                params = params.append('post_logout_redirect_uri', this.authConfiguration.post_logout_redirect_uri);
                return authorizationEndsessionUrl + "?" + params;
            };
        /**
         * @private
         * @return {?}
         */
        OidcSecurityService.prototype.getSigningKeys = /**
         * @private
         * @return {?}
         */
            function () {
                if (this.authWellKnownEndpoints) {
                    this.loggerService.logDebug('jwks_uri: ' + this.authWellKnownEndpoints.jwks_uri);
                    return this.oidcDataService.get(this.authWellKnownEndpoints.jwks_uri).pipe(operators.catchError(this.handleErrorGetSigningKeys));
                }
                else {
                    this.loggerService.logWarning('getSigningKeys: authWellKnownEndpoints is undefined');
                }
                return this.oidcDataService.get('undefined').pipe(operators.catchError(this.handleErrorGetSigningKeys));
            };
        /**
         * @private
         * @param {?} error
         * @return {?}
         */
        OidcSecurityService.prototype.handleErrorGetSigningKeys = /**
         * @private
         * @param {?} error
         * @return {?}
         */
            function (error) {
                /** @type {?} */
                var errMsg;
                if (error instanceof Response) {
                    /** @type {?} */
                    var body = error.json() || {};
                    /** @type {?} */
                    var err = JSON.stringify(body);
                    errMsg = error.status + " - " + (error.statusText || '') + " " + err;
                }
                else {
                    errMsg = error.message ? error.message : error.toString();
                }
                console.error(errMsg);
                return rxjs.throwError(errMsg);
            };
        /**
         * @private
         * @return {?}
         */
        OidcSecurityService.prototype.runTokenValidation = /**
         * @private
         * @return {?}
         */
            function () {
                var _this = this;
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
                var silentRenewHeartBeatCheck = ( /**
                 * @return {?}
                 */function () {
                    _this.loggerService.logDebug('silentRenewHeartBeatCheck\r\n' +
                        ("\tsilentRenewRunning: " + (_this.oidcSecurityCommon.silentRenewRunning === 'running') + "\r\n") +
                        ("\tidToken: " + !!_this.getIdToken() + "\r\n") +
                        ("\t_userData.value: " + !!_this._userData.value));
                    if (_this._userData.value && _this.oidcSecurityCommon.silentRenewRunning !== 'running' && _this.getIdToken()) {
                        if (_this.oidcSecurityValidation.isTokenExpired(_this.oidcSecurityCommon.idToken, _this.authConfiguration.silent_renew_offset_in_seconds)) {
                            _this.loggerService.logDebug('IsAuthorized: id_token isTokenExpired, start silent renew if active');
                            if (_this.authConfiguration.silent_renew) {
                                _this.refreshSession().subscribe(( /**
                                 * @return {?}
                                 */function () {
                                    _this._scheduledHeartBeat = setTimeout(silentRenewHeartBeatCheck, 3000);
                                }), ( /**
                                 * @param {?} err
                                 * @return {?}
                                 */function (err) {
                                    _this.loggerService.logError('Error: ' + err);
                                    _this._scheduledHeartBeat = setTimeout(silentRenewHeartBeatCheck, 3000);
                                }));
                                /* In this situation, we schedule a heatbeat check only when silentRenew is finished.
                                We don't want to schedule another check so we have to return here */
                                return;
                            }
                            else {
                                _this.resetAuthorizationData(false);
                            }
                        }
                    }
                    /* Delay 3 seconds and do the next check */
                    _this._scheduledHeartBeat = setTimeout(silentRenewHeartBeatCheck, 3000);
                });
                this.zone.runOutsideAngular(( /**
                 * @return {?}
                 */function () {
                    /* Initial heartbeat check */
                    _this._scheduledHeartBeat = setTimeout(silentRenewHeartBeatCheck, 10000);
                }));
            };
        /**
         * @private
         * @param {?} e
         * @return {?}
         */
        OidcSecurityService.prototype.silentRenewEventHandler = /**
         * @private
         * @param {?} e
         * @return {?}
         */
            function (e) {
                this.loggerService.logDebug('silentRenewEventHandler');
                if (this.authConfiguration.response_type === 'code') {
                    /** @type {?} */
                    var urlParts = e.detail.toString().split('?');
                    /** @type {?} */
                    var params = new http.HttpParams({
                        fromString: urlParts[1]
                    });
                    /** @type {?} */
                    var code = params.get('code');
                    /** @type {?} */
                    var state = params.get('state');
                    /** @type {?} */
                    var session_state = params.get('session_state');
                    /** @type {?} */
                    var error = params.get('error');
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
            };
        OidcSecurityService.decorators = [
            { type: core.Injectable }
        ];
        /** @nocollapse */
        OidcSecurityService.ctorParameters = function () {
            return [
                { type: OidcDataService },
                { type: StateValidationService },
                { type: AuthConfiguration },
                { type: router.Router },
                { type: OidcSecurityCheckSession },
                { type: OidcSecuritySilentRenew },
                { type: OidcSecurityUserService },
                { type: OidcSecurityCommon },
                { type: OidcSecurityValidation },
                { type: TokenHelperService },
                { type: LoggerService },
                { type: core.NgZone },
                { type: http.HttpClient }
            ];
        };
        return OidcSecurityService;
    }());

    /**
     * @fileoverview added by tsickle
     * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
     */
    var AuthModule = /** @class */ (function () {
        function AuthModule() {
        }
        /**
         * @param {?=} token
         * @return {?}
         */
        AuthModule.forRoot = /**
         * @param {?=} token
         * @return {?}
         */
            function (token) {
                if (token === void 0) {
                    token = {};
                }
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
            };
        AuthModule.decorators = [
            { type: core.NgModule }
        ];
        return AuthModule;
    }());

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

    exports.AuthWellKnownEndpoints = AuthWellKnownEndpoints;
    exports.AuthorizationResult = AuthorizationResult;
    exports.AuthorizationState = AuthorizationState;
    exports.JwtKeys = JwtKeys;
    exports.JwtKey = JwtKey;
    exports.ValidateStateResult = ValidateStateResult;
    exports.ValidationResult = ValidationResult;
    exports.OpenIDImplicitFlowConfiguration = OpenIDImplicitFlowConfiguration;
    exports.AuthConfiguration = AuthConfiguration;
    exports.AuthModule = AuthModule;
    exports.OidcConfigService = OidcConfigService;
    exports.OidcSecurityService = OidcSecurityService;
    exports.OidcSecurityStorage = OidcSecurityStorage;
    exports.BrowserStorage = BrowserStorage;
    exports.OidcSecurityValidation = OidcSecurityValidation;
    exports.TokenHelperService = TokenHelperService;
    exports.ɵa = OidcDataService;
    exports.ɵg = IFrameService;
    exports.ɵd = EqualityHelperService;
    exports.ɵb = StateValidationService;
    exports.ɵe = LoggerService;
    exports.ɵf = OidcSecurityCheckSession;
    exports.ɵc = OidcSecurityCommon;
    exports.ɵh = OidcSecuritySilentRenew;
    exports.ɵi = OidcSecurityUserService;

    Object.defineProperty(exports, '__esModule', { value: true });

})));

//# sourceMappingURL=angular-auth-oidc-client.umd.js.map