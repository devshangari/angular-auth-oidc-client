/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Inject, Injectable, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { Subject } from 'rxjs';
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
export { OpenIDImplicitFlowConfiguration };
if (false) {
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.stsServer;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.redirect_url;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.client_id;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.response_type;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.scope;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.hd_param;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.post_logout_redirect_uri;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.start_checksession;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.silent_renew;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.silent_renew_url;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.silent_renew_offset_in_seconds;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.silent_redirect_url;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.post_login_route;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.forbidden_route;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.unauthorized_route;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.auto_userinfo;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.auto_clean_state_after_authentication;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.trigger_authorization_result_event;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.log_console_warning_active;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.log_console_debug_active;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.iss_validation_off;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.history_cleanup_off;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.max_id_token_iat_offset_allowed_in_seconds;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.disable_iat_offset_validation;
    /** @type {?} */
    OpenIDImplicitFlowConfiguration.prototype.storage;
}
var AuthConfiguration = /** @class */ (function () {
    function AuthConfiguration(platformId) {
        this.platformId = platformId;
        this._onConfigurationChange = new Subject();
        this.defaultConfig = new OpenIDImplicitFlowConfiguration();
    }
    Object.defineProperty(AuthConfiguration.prototype, "stsServer", {
        get: /**
         * @return {?}
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
            if (!isPlatformBrowser(this.platformId)) {
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
         */
        function () {
            if (!isPlatformBrowser(this.platformId)) {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
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
         */
        function () {
            return this._onConfigurationChange.asObservable();
        },
        enumerable: true,
        configurable: true
    });
    AuthConfiguration.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    AuthConfiguration.ctorParameters = function () { return [
        { type: Object, decorators: [{ type: Inject, args: [PLATFORM_ID,] }] }
    ]; };
    return AuthConfiguration;
}());
export { AuthConfiguration };
if (false) {
    /**
     * @type {?}
     * @private
     */
    AuthConfiguration.prototype.openIDImplicitFlowConfiguration;
    /**
     * @type {?}
     * @private
     */
    AuthConfiguration.prototype.defaultConfig;
    /**
     * @type {?}
     * @private
     */
    AuthConfiguration.prototype._onConfigurationChange;
    /**
     * @type {?}
     * @private
     */
    AuthConfiguration.prototype.platformId;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5jb25maWd1cmF0aW9uLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1hdXRoLW9pZGMtY2xpZW50LyIsInNvdXJjZXMiOlsibGliL21vZHVsZXMvYXV0aC5jb25maWd1cmF0aW9uLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFBQSxPQUFPLEVBQUUsTUFBTSxFQUFFLFVBQVUsRUFBRSxXQUFXLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDaEUsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFDcEQsT0FBTyxFQUFjLE9BQU8sRUFBRSxNQUFNLE1BQU0sQ0FBQztBQUUzQztJQUFBO1FBQ0ksY0FBUyxHQUFHLHlCQUF5QixDQUFDO1FBQ3RDLGlCQUFZLEdBQUcseUJBQXlCLENBQUM7Ozs7O1FBS3pDLGNBQVMsR0FBRyxlQUFlLENBQUM7UUFDNUIsa0JBQWEsR0FBRyxnQkFBZ0IsQ0FBQztRQUNqQyxVQUFLLEdBQUcsc0JBQXNCLENBQUM7O1FBRS9CLGFBQVEsR0FBRyxFQUFFLENBQUM7UUFDZCw2QkFBd0IsR0FBRyxzQ0FBc0MsQ0FBQztRQUNsRSx1QkFBa0IsR0FBRyxLQUFLLENBQUM7UUFDM0IsaUJBQVksR0FBRyxLQUFLLENBQUM7UUFDckIscUJBQWdCLEdBQUcseUJBQXlCLENBQUM7UUFDN0MsbUNBQThCLEdBQUcsQ0FBQyxDQUFDO1FBQ25DLHdCQUFtQixHQUFHLHlCQUF5QixDQUFDO1FBQ2hELHFCQUFnQixHQUFHLEdBQUcsQ0FBQzs7UUFFdkIsb0JBQWUsR0FBRyxZQUFZLENBQUM7O1FBRS9CLHVCQUFrQixHQUFHLGVBQWUsQ0FBQztRQUNyQyxrQkFBYSxHQUFHLElBQUksQ0FBQztRQUNyQiwwQ0FBcUMsR0FBRyxJQUFJLENBQUM7UUFDN0MsdUNBQWtDLEdBQUcsS0FBSyxDQUFDO1FBQzNDLCtCQUEwQixHQUFHLElBQUksQ0FBQztRQUNsQyw2QkFBd0IsR0FBRyxLQUFLLENBQUM7UUFDakMsdUJBQWtC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bSAnQGFuZ3VsYXIvY29yZSc7XHJcbmltcG9ydCB7IGlzUGxhdGZvcm1Ccm93c2VyIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uJztcclxuaW1wb3J0IHsgT2JzZXJ2YWJsZSwgU3ViamVjdCB9IGZyb20gJ3J4anMnO1xyXG5cclxuZXhwb3J0IGNsYXNzIE9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24ge1xyXG4gICAgc3RzU2VydmVyID0gJ2h0dHBzOi8vbG9jYWxob3N0OjQ0MzE4JztcclxuICAgIHJlZGlyZWN0X3VybCA9ICdodHRwczovL2xvY2FsaG9zdDo0NDMxMSc7XHJcbiAgICAvLyBUaGUgQ2xpZW50IE1VU1QgdmFsaWRhdGUgdGhhdCB0aGUgYXVkIChhdWRpZW5jZSkgQ2xhaW0gY29udGFpbnMgaXRzIGNsaWVudF9pZCB2YWx1ZSByZWdpc3RlcmVkIGF0IHRoZSBJc3N1ZXIgaWRlbnRpZmllZFxyXG4gICAgLy8gYnkgdGhlIGlzcyAoaXNzdWVyKSBDbGFpbSBhcyBhbiBhdWRpZW5jZS5cclxuICAgIC8vIFRoZSBJRCBUb2tlbiBNVVNUIGJlIHJlamVjdGVkIGlmIHRoZSBJRCBUb2tlbiBkb2VzIG5vdCBsaXN0IHRoZSBDbGllbnQgYXMgYSB2YWxpZCBhdWRpZW5jZSxcclxuICAgIC8vIG9yIGlmIGl0IGNvbnRhaW5zIGFkZGl0aW9uYWwgYXVkaWVuY2VzIG5vdCB0cnVzdGVkIGJ5IHRoZSBDbGllbnQuXHJcbiAgICBjbGllbnRfaWQgPSAnYW5ndWxhcmNsaWVudCc7XHJcbiAgICByZXNwb25zZV90eXBlID0gJ2lkX3Rva2VuIHRva2VuJztcclxuICAgIHNjb3BlID0gJ29wZW5pZCBlbWFpbCBwcm9maWxlJztcclxuICAgIC8vIE9ubHkgZm9yIEdvb2dsZSBBdXRoIHdpdGggcGFydGljdWxhciBHIFN1aXRlIGRvbWFpbiwgc2VlIGh0dHBzOi8vZGV2ZWxvcGVycy5nb29nbGUuY29tL2lkZW50aXR5L3Byb3RvY29scy9PcGVuSURDb25uZWN0I2hkLXBhcmFtXHJcbiAgICBoZF9wYXJhbSA9ICcnO1xyXG4gICAgcG9zdF9sb2dvdXRfcmVkaXJlY3RfdXJpID0gJ2h0dHBzOi8vbG9jYWxob3N0OjQ0MzExL3VuYXV0aG9yaXplZCc7XHJcbiAgICBzdGFydF9jaGVja3Nlc3Npb24gPSBmYWxzZTtcclxuICAgIHNpbGVudF9yZW5ldyA9IGZhbHNlO1xyXG4gICAgc2lsZW50X3JlbmV3X3VybCA9ICdodHRwczovL2xvY2FsaG9zdDo0NDMxMSc7XHJcbiAgICBzaWxlbnRfcmVuZXdfb2Zmc2V0X2luX3NlY29uZHMgPSAwO1xyXG4gICAgc2lsZW50X3JlZGlyZWN0X3VybCA9ICdodHRwczovL2xvY2FsaG9zdDo0NDMxMSc7XHJcbiAgICBwb3N0X2xvZ2luX3JvdXRlID0gJy8nO1xyXG4gICAgLy8gSFRUUCA0MDNcclxuICAgIGZvcmJpZGRlbl9yb3V0ZSA9ICcvZm9yYmlkZGVuJztcclxuICAgIC8vIEhUVFAgNDAxXHJcbiAgICB1bmF1dGhvcml6ZWRfcm91dGUgPSAnL3VuYXV0aG9yaXplZCc7XHJcbiAgICBhdXRvX3VzZXJpbmZvID0gdHJ1ZTtcclxuICAgIGF1dG9fY2xlYW5fc3RhdGVfYWZ0ZXJfYXV0aGVudGljYXRpb24gPSB0cnVlO1xyXG4gICAgdHJpZ2dlcl9hdXRob3JpemF0aW9uX3Jlc3VsdF9ldmVudCA9IGZhbHNlO1xyXG4gICAgbG9nX2NvbnNvbGVfd2FybmluZ19hY3RpdmUgPSB0cnVlO1xyXG4gICAgbG9nX2NvbnNvbGVfZGVidWdfYWN0aXZlID0gZmFsc2U7XHJcbiAgICBpc3NfdmFsaWRhdGlvbl9vZmYgPSBmYWxzZTtcclxuICAgIGhpc3RvcnlfY2xlYW51cF9vZmYgPSBmYWxzZTtcclxuXHJcbiAgICAvLyBpZF90b2tlbiBDODogVGhlIGlhdCBDbGFpbSBjYW4gYmUgdXNlZCB0byByZWplY3QgdG9rZW5zIHRoYXQgd2VyZSBpc3N1ZWQgdG9vIGZhciBhd2F5IGZyb20gdGhlIGN1cnJlbnQgdGltZSxcclxuICAgIC8vIGxpbWl0aW5nIHRoZSBhbW91bnQgb2YgdGltZSB0aGF0IG5vbmNlcyBuZWVkIHRvIGJlIHN0b3JlZCB0byBwcmV2ZW50IGF0dGFja3MuVGhlIGFjY2VwdGFibGUgcmFuZ2UgaXMgQ2xpZW50IHNwZWNpZmljLlxyXG4gICAgbWF4X2lkX3Rva2VuX2lhdF9vZmZzZXRfYWxsb3dlZF9pbl9zZWNvbmRzID0gMztcclxuICAgIGRpc2FibGVfaWF0X29mZnNldF92YWxpZGF0aW9uID0gZmFsc2U7XHJcblxyXG4gICAgc3RvcmFnZSA9IHR5cGVvZiBTdG9yYWdlICE9PSAndW5kZWZpbmVkJyA/IHNlc3Npb25TdG9yYWdlIDogbnVsbDtcclxufVxyXG5cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgQXV0aENvbmZpZ3VyYXRpb24ge1xyXG4gICAgcHJpdmF0ZSBvcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uOiBPcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uIHwgdW5kZWZpbmVkO1xyXG4gICAgcHJpdmF0ZSBkZWZhdWx0Q29uZmlnOiBPcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uO1xyXG5cclxuICAgIGdldCBzdHNTZXJ2ZXIoKTogc3RyaW5nIHtcclxuICAgICAgICBpZiAodGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24uc3RzU2VydmVyO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZGVmYXVsdENvbmZpZy5zdHNTZXJ2ZXI7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0IHJlZGlyZWN0X3VybCgpOiBzdHJpbmcge1xyXG4gICAgICAgIGlmICh0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24pIHtcclxuICAgICAgICAgICAgcmV0dXJuIHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbi5yZWRpcmVjdF91cmw7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5kZWZhdWx0Q29uZmlnLnJlZGlyZWN0X3VybDtcclxuICAgIH1cclxuXHJcbiAgICBnZXQgc2lsZW50X3JlZGlyZWN0X3VybCgpOiBzdHJpbmcge1xyXG4gICAgICAgIGlmICh0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24pIHtcclxuICAgICAgICAgICAgcmV0dXJuIHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbi5zaWxlbnRfcmVuZXdfdXJsO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZGVmYXVsdENvbmZpZy5zaWxlbnRfcmVuZXdfdXJsO1xyXG4gICAgfVxyXG5cclxuICAgIGdldCBjbGllbnRfaWQoKTogc3RyaW5nIHtcclxuICAgICAgICBpZiAodGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24uY2xpZW50X2lkO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZGVmYXVsdENvbmZpZy5jbGllbnRfaWQ7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0IHJlc3BvbnNlX3R5cGUoKTogc3RyaW5nIHtcclxuICAgICAgICBpZiAodGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24ucmVzcG9uc2VfdHlwZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0aGlzLmRlZmF1bHRDb25maWcucmVzcG9uc2VfdHlwZTtcclxuICAgIH1cclxuXHJcbiAgICBnZXQgc2NvcGUoKTogc3RyaW5nIHtcclxuICAgICAgICBpZiAodGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24uc2NvcGU7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5kZWZhdWx0Q29uZmlnLnNjb3BlO1xyXG4gICAgfVxyXG5cclxuICAgIGdldCBoZF9wYXJhbSgpOiBzdHJpbmcge1xyXG4gICAgICAgIGlmICh0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24pIHtcclxuICAgICAgICAgICAgcmV0dXJuIHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbi5oZF9wYXJhbTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0aGlzLmRlZmF1bHRDb25maWcuaGRfcGFyYW07XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0IHBvc3RfbG9nb3V0X3JlZGlyZWN0X3VyaSgpOiBzdHJpbmcge1xyXG4gICAgICAgIGlmICh0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24pIHtcclxuICAgICAgICAgICAgcmV0dXJuIHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbi5wb3N0X2xvZ291dF9yZWRpcmVjdF91cmk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5kZWZhdWx0Q29uZmlnLnBvc3RfbG9nb3V0X3JlZGlyZWN0X3VyaTtcclxuICAgIH1cclxuXHJcbiAgICBnZXQgc3RhcnRfY2hlY2tzZXNzaW9uKCk6IGJvb2xlYW4ge1xyXG4gICAgICAgIGlmICghaXNQbGF0Zm9ybUJyb3dzZXIodGhpcy5wbGF0Zm9ybUlkKSkge1xyXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAodGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24uc3RhcnRfY2hlY2tzZXNzaW9uO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZGVmYXVsdENvbmZpZy5zdGFydF9jaGVja3Nlc3Npb247XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0IHNpbGVudF9yZW5ldygpOiBib29sZWFuIHtcclxuICAgICAgICBpZiAoIWlzUGxhdGZvcm1Ccm93c2VyKHRoaXMucGxhdGZvcm1JZCkpIHtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbikge1xyXG4gICAgICAgICAgICByZXR1cm4gdGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uLnNpbGVudF9yZW5ldztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0aGlzLmRlZmF1bHRDb25maWcuc2lsZW50X3JlbmV3O1xyXG4gICAgfVxyXG5cclxuICAgIGdldCBzaWxlbnRfcmVuZXdfb2Zmc2V0X2luX3NlY29uZHMoKTogbnVtYmVyIHtcclxuICAgICAgICBpZiAodGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24uc2lsZW50X3JlbmV3X29mZnNldF9pbl9zZWNvbmRzO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZGVmYXVsdENvbmZpZy5zaWxlbnRfcmVuZXdfb2Zmc2V0X2luX3NlY29uZHM7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0IHBvc3RfbG9naW5fcm91dGUoKTogc3RyaW5nIHtcclxuICAgICAgICBpZiAodGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24ucG9zdF9sb2dpbl9yb3V0ZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0aGlzLmRlZmF1bHRDb25maWcucG9zdF9sb2dpbl9yb3V0ZTtcclxuICAgIH1cclxuXHJcbiAgICBnZXQgZm9yYmlkZGVuX3JvdXRlKCk6IHN0cmluZyB7XHJcbiAgICAgICAgaWYgKHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbikge1xyXG4gICAgICAgICAgICByZXR1cm4gdGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uLmZvcmJpZGRlbl9yb3V0ZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0aGlzLmRlZmF1bHRDb25maWcuZm9yYmlkZGVuX3JvdXRlO1xyXG4gICAgfVxyXG5cclxuICAgIGdldCB1bmF1dGhvcml6ZWRfcm91dGUoKTogc3RyaW5nIHtcclxuICAgICAgICBpZiAodGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24udW5hdXRob3JpemVkX3JvdXRlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZGVmYXVsdENvbmZpZy51bmF1dGhvcml6ZWRfcm91dGU7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0IGF1dG9fdXNlcmluZm8oKTogYm9vbGVhbiB7XHJcbiAgICAgICAgaWYgKHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbikge1xyXG4gICAgICAgICAgICByZXR1cm4gdGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uLmF1dG9fdXNlcmluZm87XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5kZWZhdWx0Q29uZmlnLmF1dG9fdXNlcmluZm87XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0IGF1dG9fY2xlYW5fc3RhdGVfYWZ0ZXJfYXV0aGVudGljYXRpb24oKTogYm9vbGVhbiB7XHJcbiAgICAgICAgaWYgKHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbikge1xyXG4gICAgICAgICAgICByZXR1cm4gdGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uLmF1dG9fY2xlYW5fc3RhdGVfYWZ0ZXJfYXV0aGVudGljYXRpb247XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5kZWZhdWx0Q29uZmlnLmF1dG9fY2xlYW5fc3RhdGVfYWZ0ZXJfYXV0aGVudGljYXRpb247XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0IHRyaWdnZXJfYXV0aG9yaXphdGlvbl9yZXN1bHRfZXZlbnQoKTogYm9vbGVhbiB7XHJcbiAgICAgICAgaWYgKHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbikge1xyXG4gICAgICAgICAgICByZXR1cm4gdGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uLnRyaWdnZXJfYXV0aG9yaXphdGlvbl9yZXN1bHRfZXZlbnQ7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5kZWZhdWx0Q29uZmlnLnRyaWdnZXJfYXV0aG9yaXphdGlvbl9yZXN1bHRfZXZlbnQ7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0IGlzTG9nTGV2ZWxXYXJuaW5nRW5hYmxlZCgpOiBib29sZWFuIHtcclxuICAgICAgICBpZiAodGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24ubG9nX2NvbnNvbGVfd2FybmluZ19hY3RpdmU7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5kZWZhdWx0Q29uZmlnLmxvZ19jb25zb2xlX3dhcm5pbmdfYWN0aXZlO1xyXG4gICAgfVxyXG5cclxuICAgIGdldCBpc0xvZ0xldmVsRGVidWdFbmFibGVkKCk6IGJvb2xlYW4ge1xyXG4gICAgICAgIGlmICh0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24pIHtcclxuICAgICAgICAgICAgcmV0dXJuIHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbi5sb2dfY29uc29sZV9kZWJ1Z19hY3RpdmU7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5kZWZhdWx0Q29uZmlnLmxvZ19jb25zb2xlX2RlYnVnX2FjdGl2ZTtcclxuICAgIH1cclxuXHJcbiAgICBnZXQgaXNzX3ZhbGlkYXRpb25fb2ZmKCk6IGJvb2xlYW4ge1xyXG4gICAgICAgIGlmICh0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24pIHtcclxuICAgICAgICAgICAgcmV0dXJuIHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbi5pc3NfdmFsaWRhdGlvbl9vZmY7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5kZWZhdWx0Q29uZmlnLmlzc192YWxpZGF0aW9uX29mZjtcclxuICAgIH1cclxuXHJcbiAgICBnZXQgaGlzdG9yeV9jbGVhbnVwX29mZigpOiBib29sZWFuIHtcclxuICAgICAgICBpZiAodGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24uaGlzdG9yeV9jbGVhbnVwX29mZjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0aGlzLmRlZmF1bHRDb25maWcuaGlzdG9yeV9jbGVhbnVwX29mZjtcclxuICAgIH1cclxuXHJcbiAgICBnZXQgbWF4X2lkX3Rva2VuX2lhdF9vZmZzZXRfYWxsb3dlZF9pbl9zZWNvbmRzKCk6IG51bWJlciB7XHJcbiAgICAgICAgaWYgKHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbikge1xyXG4gICAgICAgICAgICByZXR1cm4gdGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uLm1heF9pZF90b2tlbl9pYXRfb2Zmc2V0X2FsbG93ZWRfaW5fc2Vjb25kcztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0aGlzLmRlZmF1bHRDb25maWcubWF4X2lkX3Rva2VuX2lhdF9vZmZzZXRfYWxsb3dlZF9pbl9zZWNvbmRzO1xyXG4gICAgfVxyXG5cclxuICAgIGdldCBkaXNhYmxlX2lhdF9vZmZzZXRfdmFsaWRhdGlvbigpOiBib29sZWFuIHtcclxuICAgICAgICBpZiAodGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24uZGlzYWJsZV9pYXRfb2Zmc2V0X3ZhbGlkYXRpb247XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5kZWZhdWx0Q29uZmlnLmRpc2FibGVfaWF0X29mZnNldF92YWxpZGF0aW9uO1xyXG4gICAgfVxyXG5cclxuICAgIGdldCBzdG9yYWdlKCk6IGFueSB7XHJcbiAgICAgICAgaWYgKHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbikge1xyXG4gICAgICAgICAgICByZXR1cm4gdGhpcy5vcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uLnN0b3JhZ2U7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5kZWZhdWx0Q29uZmlnLnN0b3JhZ2U7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3RydWN0b3IoQEluamVjdChQTEFURk9STV9JRCkgcHJpdmF0ZSBwbGF0Zm9ybUlkOiBPYmplY3QpIHtcclxuICAgICAgICB0aGlzLmRlZmF1bHRDb25maWcgPSBuZXcgT3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbigpO1xyXG4gICAgfVxyXG5cclxuICAgIGluaXQob3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbjogT3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbikge1xyXG4gICAgICAgIHRoaXMub3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbiA9IG9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb247XHJcbiAgICAgICAgdGhpcy5fb25Db25maWd1cmF0aW9uQ2hhbmdlLm5leHQob3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbik7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBfb25Db25maWd1cmF0aW9uQ2hhbmdlID0gbmV3IFN1YmplY3Q8T3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbj4oKTtcclxuICAgIGdldCBvbkNvbmZpZ3VyYXRpb25DaGFuZ2UoKTogT2JzZXJ2YWJsZTxPcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uPiB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuX29uQ29uZmlndXJhdGlvbkNoYW5nZS5hc09ic2VydmFibGUoKTtcclxuICAgIH1cclxufVxyXG4iXX0=