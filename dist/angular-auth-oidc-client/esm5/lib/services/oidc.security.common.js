/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
import { OidcSecurityStorage } from './oidc.security.storage';
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
         */
        function () {
            return this.retrieve(this.storage_auth_result);
        },
        set: /**
         * @param {?} value
         * @return {?}
         */
        function (value) {
            this.store(this.storage_auth_result, value);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityCommon.prototype, "accessToken", {
        get: /**
         * @return {?}
         */
        function () {
            return this.retrieve(this.storage_access_token) || '';
        },
        set: /**
         * @param {?} value
         * @return {?}
         */
        function (value) {
            this.store(this.storage_access_token, value);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityCommon.prototype, "idToken", {
        get: /**
         * @return {?}
         */
        function () {
            return this.retrieve(this.storage_id_token) || '';
        },
        set: /**
         * @param {?} value
         * @return {?}
         */
        function (value) {
            this.store(this.storage_id_token, value);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityCommon.prototype, "isAuthorized", {
        get: /**
         * @return {?}
         */
        function () {
            return this.retrieve(this.storage_is_authorized);
        },
        set: /**
         * @param {?} value
         * @return {?}
         */
        function (value) {
            this.store(this.storage_is_authorized, value);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityCommon.prototype, "userData", {
        get: /**
         * @return {?}
         */
        function () {
            return this.retrieve(this.storage_user_data);
        },
        set: /**
         * @param {?} value
         * @return {?}
         */
        function (value) {
            this.store(this.storage_user_data, value);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityCommon.prototype, "authNonce", {
        get: /**
         * @return {?}
         */
        function () {
            return this.retrieve(this.storage_auth_nonce) || '';
        },
        set: /**
         * @param {?} value
         * @return {?}
         */
        function (value) {
            this.store(this.storage_auth_nonce, value);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityCommon.prototype, "code_verifier", {
        get: /**
         * @return {?}
         */
        function () {
            return this.retrieve(this.storage_code_verifier) || '';
        },
        set: /**
         * @param {?} value
         * @return {?}
         */
        function (value) {
            this.store(this.storage_code_verifier, value);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityCommon.prototype, "authStateControl", {
        get: /**
         * @return {?}
         */
        function () {
            return this.retrieve(this.storage_auth_state_control) || '';
        },
        set: /**
         * @param {?} value
         * @return {?}
         */
        function (value) {
            this.store(this.storage_auth_state_control, value);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityCommon.prototype, "sessionState", {
        get: /**
         * @return {?}
         */
        function () {
            return this.retrieve(this.storage_session_state);
        },
        set: /**
         * @param {?} value
         * @return {?}
         */
        function (value) {
            this.store(this.storage_session_state, value);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityCommon.prototype, "silentRenewRunning", {
        get: /**
         * @return {?}
         */
        function () {
            return this.retrieve(this.storage_silent_renew_running) || '';
        },
        set: /**
         * @param {?} value
         * @return {?}
         */
        function (value) {
            this.store(this.storage_silent_renew_running, value);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityCommon.prototype, "customRequestParams", {
        get: /**
         * @return {?}
         */
        function () {
            return this.retrieve(this.storage_custom_request_params);
        },
        set: /**
         * @param {?} value
         * @return {?}
         */
        function (value) {
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
        { type: Injectable }
    ];
    /** @nocollapse */
    OidcSecurityCommon.ctorParameters = function () { return [
        { type: OidcSecurityStorage }
    ]; };
    return OidcSecurityCommon;
}());
export { OidcSecurityCommon };
if (false) {
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.storage_auth_result;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.storage_access_token;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.storage_id_token;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.storage_is_authorized;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.storage_user_data;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.storage_auth_nonce;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.storage_code_verifier;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.storage_auth_state_control;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.storage_session_state;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.storage_silent_renew_running;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.storage_custom_request_params;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCommon.prototype.oidcSecurityStorage;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS5jb21tb24uanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLWF1dGgtb2lkYy1jbGllbnQvIiwic291cmNlcyI6WyJsaWIvc2VydmljZXMvb2lkYy5zZWN1cml0eS5jb21tb24udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7OztBQUFBLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLG1CQUFtQixFQUFFLE1BQU0seUJBQXlCLENBQUM7QUFJOUQ7SUFrSEksNEJBQW9CLG1CQUF3QztRQUF4Qyx3QkFBbUIsR0FBbkIsbUJBQW1CLENBQXFCO1FBaEhwRCx3QkFBbUIsR0FBRyxxQkFBcUIsQ0FBQztRQVU1Qyx5QkFBb0IsR0FBRyxtQkFBbUIsQ0FBQztRQVUzQyxxQkFBZ0IsR0FBRywwQkFBMEIsQ0FBQztRQVU5QywwQkFBcUIsR0FBRyxlQUFlLENBQUM7UUFVeEMsc0JBQWlCLEdBQUcsVUFBVSxDQUFDO1FBVS9CLHVCQUFrQixHQUFHLFdBQVcsQ0FBQztRQVVqQywwQkFBcUIsR0FBRyxlQUFlLENBQUM7UUFVeEMsK0JBQTBCLEdBQUcsa0JBQWtCLENBQUM7UUFVaEQsMEJBQXFCLEdBQUcsZUFBZSxDQUFDO1FBVXhDLGlDQUE0QixHQUFHLDhCQUE4QixDQUFDO1FBVTlELGtDQUE2QixHQUFHLCtCQUErQixDQUFDO0lBWVQsQ0FBQztJQTlHaEUsc0JBQVcsMENBQVU7Ozs7UUFBckI7WUFDSSxPQUFPLElBQUksQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLG1CQUFtQixDQUFDLENBQUM7UUFDbkQsQ0FBQzs7Ozs7UUFFRCxVQUFzQixLQUFVO1lBQzVCLElBQUksQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLG1CQUFtQixFQUFFLEtBQUssQ0FBQyxDQUFDO1FBQ2hELENBQUM7OztPQUpBO0lBUUQsc0JBQVcsMkNBQVc7Ozs7UUFBdEI7WUFDSSxPQUFPLElBQUksQ0FBQyxRQUFRLENBQUMsSUFB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QUFDLEtBQUssQ0FBQyxJQUFJLENBQUMscUJBQXFCLEVBQUUsRUFBRSxDQUFDLENBQUM7U0FDOUM7SUFDTCxDQUFDOzs7O0lBRUQsMkNBQWM7OztJQUFkO1FBQ0ksT0FBTyxJQUFJLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxvQkFBb0IsQ0FBQyxDQUFDO0lBQ3BELENBQUM7Ozs7SUFFRCx1Q0FBVTs7O0lBQVY7UUFDSSxPQUFPLElBQUksQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLGdCQUFnQixDQUFDLENBQUM7SUFDaEQsQ0FBQzs7Z0JBL0lKLFVBQVU7Ozs7Z0JBSkYsbUJBQW1COztJQW9KNUIseUJBQUM7Q0FBQSxBQWhKRCxJQWdKQztTQS9JWSxrQkFBa0I7Ozs7OztJQUMzQixpREFBb0Q7Ozs7O0lBVXBELGtEQUFtRDs7Ozs7SUFVbkQsOENBQXNEOzs7OztJQVV0RCxtREFBZ0Q7Ozs7O0lBVWhELCtDQUF1Qzs7Ozs7SUFVdkMsZ0RBQXlDOzs7OztJQVV6QyxtREFBZ0Q7Ozs7O0lBVWhELHdEQUF3RDs7Ozs7SUFVeEQsbURBQWdEOzs7OztJQVVoRCwwREFBc0U7Ozs7O0lBVXRFLDJEQUF3RTs7Ozs7SUFZNUQsaURBQWdEIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xyXG5pbXBvcnQgeyBPaWRjU2VjdXJpdHlTdG9yYWdlIH0gZnJvbSAnLi9vaWRjLnNlY3VyaXR5LnN0b3JhZ2UnO1xyXG5cclxuZXhwb3J0IHR5cGUgU2lsZW50UmVuZXdTdGF0ZSA9ICdydW5uaW5nJyB8ICcnO1xyXG5cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgT2lkY1NlY3VyaXR5Q29tbW9uIHtcclxuICAgIHByaXZhdGUgc3RvcmFnZV9hdXRoX3Jlc3VsdCA9ICdhdXRob3JpemF0aW9uUmVzdWx0JztcclxuXHJcbiAgICBwdWJsaWMgZ2V0IGF1dGhSZXN1bHQoKTogYW55IHtcclxuICAgICAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLnN0b3JhZ2VfYXV0aF9yZXN1bHQpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBzZXQgYXV0aFJlc3VsdCh2YWx1ZTogYW55KSB7XHJcbiAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2VfYXV0aF9yZXN1bHQsIHZhbHVlKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHN0b3JhZ2VfYWNjZXNzX3Rva2VuID0gJ2F1dGhvcml6YXRpb25EYXRhJztcclxuXHJcbiAgICBwdWJsaWMgZ2V0IGFjY2Vzc1Rva2VuKCk6IHN0cmluZyB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMucmV0cmlldmUodGhpcy5zdG9yYWdlX2FjY2Vzc190b2tlbikgfHwgJyc7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIHNldCBhY2Nlc3NUb2tlbih2YWx1ZTogc3RyaW5nKSB7XHJcbiAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2VfYWNjZXNzX3Rva2VuLCB2YWx1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzdG9yYWdlX2lkX3Rva2VuID0gJ2F1dGhvcml6YXRpb25EYXRhSWRUb2tlbic7XHJcblxyXG4gICAgcHVibGljIGdldCBpZFRva2VuKCk6IHN0cmluZyB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMucmV0cmlldmUodGhpcy5zdG9yYWdlX2lkX3Rva2VuKSB8fCAnJztcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgc2V0IGlkVG9rZW4odmFsdWU6IHN0cmluZykge1xyXG4gICAgICAgIHRoaXMuc3RvcmUodGhpcy5zdG9yYWdlX2lkX3Rva2VuLCB2YWx1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzdG9yYWdlX2lzX2F1dGhvcml6ZWQgPSAnX2lzQXV0aG9yaXplZCc7XHJcblxyXG4gICAgcHVibGljIGdldCBpc0F1dGhvcml6ZWQoKTogYm9vbGVhbiB8IHVuZGVmaW5lZCB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMucmV0cmlldmUodGhpcy5zdG9yYWdlX2lzX2F1dGhvcml6ZWQpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBzZXQgaXNBdXRob3JpemVkKHZhbHVlOiBib29sZWFuIHwgdW5kZWZpbmVkKSB7XHJcbiAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2VfaXNfYXV0aG9yaXplZCwgdmFsdWUpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgc3RvcmFnZV91c2VyX2RhdGEgPSAndXNlckRhdGEnO1xyXG5cclxuICAgIHB1YmxpYyBnZXQgdXNlckRhdGEoKTogYW55IHtcclxuICAgICAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLnN0b3JhZ2VfdXNlcl9kYXRhKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgc2V0IHVzZXJEYXRhKHZhbHVlOiBhbnkpIHtcclxuICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV91c2VyX2RhdGEsIHZhbHVlKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHN0b3JhZ2VfYXV0aF9ub25jZSA9ICdhdXRoTm9uY2UnO1xyXG5cclxuICAgIHB1YmxpYyBnZXQgYXV0aE5vbmNlKCk6IHN0cmluZyB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMucmV0cmlldmUodGhpcy5zdG9yYWdlX2F1dGhfbm9uY2UpIHx8ICcnO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBzZXQgYXV0aE5vbmNlKHZhbHVlOiBzdHJpbmcpIHtcclxuICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9hdXRoX25vbmNlLCB2YWx1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzdG9yYWdlX2NvZGVfdmVyaWZpZXIgPSAnY29kZV92ZXJpZmllcic7XHJcblxyXG4gICAgcHVibGljIGdldCBjb2RlX3ZlcmlmaWVyKCk6IHN0cmluZyB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMucmV0cmlldmUodGhpcy5zdG9yYWdlX2NvZGVfdmVyaWZpZXIpIHx8ICcnO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBzZXQgY29kZV92ZXJpZmllcih2YWx1ZTogc3RyaW5nKSB7XHJcbiAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2VfY29kZV92ZXJpZmllciwgdmFsdWUpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgc3RvcmFnZV9hdXRoX3N0YXRlX2NvbnRyb2wgPSAnYXV0aFN0YXRlQ29udHJvbCc7XHJcblxyXG4gICAgcHVibGljIGdldCBhdXRoU3RhdGVDb250cm9sKCk6IHN0cmluZyB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMucmV0cmlldmUodGhpcy5zdG9yYWdlX2F1dGhfc3RhdGVfY29udHJvbCkgfHwgJyc7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIHNldCBhdXRoU3RhdGVDb250cm9sKHZhbHVlOiBzdHJpbmcpIHtcclxuICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9hdXRoX3N0YXRlX2NvbnRyb2wsIHZhbHVlKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHN0b3JhZ2Vfc2Vzc2lvbl9zdGF0ZSA9ICdzZXNzaW9uX3N0YXRlJztcclxuXHJcbiAgICBwdWJsaWMgZ2V0IHNlc3Npb25TdGF0ZSgpOiBhbnkge1xyXG4gICAgICAgIHJldHVybiB0aGlzLnJldHJpZXZlKHRoaXMuc3RvcmFnZV9zZXNzaW9uX3N0YXRlKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgc2V0IHNlc3Npb25TdGF0ZSh2YWx1ZTogYW55KSB7XHJcbiAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2Vfc2Vzc2lvbl9zdGF0ZSwgdmFsdWUpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgc3RvcmFnZV9zaWxlbnRfcmVuZXdfcnVubmluZyA9ICdzdG9yYWdlX3NpbGVudF9yZW5ld19ydW5uaW5nJztcclxuXHJcbiAgICBwdWJsaWMgZ2V0IHNpbGVudFJlbmV3UnVubmluZygpOiBTaWxlbnRSZW5ld1N0YXRlIHtcclxuICAgICAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLnN0b3JhZ2Vfc2lsZW50X3JlbmV3X3J1bm5pbmcpIHx8ICcnO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBzZXQgc2lsZW50UmVuZXdSdW5uaW5nKHZhbHVlOiBTaWxlbnRSZW5ld1N0YXRlKSB7XHJcbiAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2Vfc2lsZW50X3JlbmV3X3J1bm5pbmcsIHZhbHVlKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHN0b3JhZ2VfY3VzdG9tX3JlcXVlc3RfcGFyYW1zID0gJ3N0b3JhZ2VfY3VzdG9tX3JlcXVlc3RfcGFyYW1zJztcclxuXHJcbiAgICBwdWJsaWMgZ2V0IGN1c3RvbVJlcXVlc3RQYXJhbXMoKToge1xyXG4gICAgICAgIFtrZXk6IHN0cmluZ106IHN0cmluZyB8IG51bWJlciB8IGJvb2xlYW47XHJcbiAgICB9IHtcclxuICAgICAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLnN0b3JhZ2VfY3VzdG9tX3JlcXVlc3RfcGFyYW1zKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgc2V0IGN1c3RvbVJlcXVlc3RQYXJhbXModmFsdWU6IHsgW2tleTogc3RyaW5nXTogc3RyaW5nIHwgbnVtYmVyIHwgYm9vbGVhbiB9KSB7XHJcbiAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2VfY3VzdG9tX3JlcXVlc3RfcGFyYW1zLCB2YWx1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBvaWRjU2VjdXJpdHlTdG9yYWdlOiBPaWRjU2VjdXJpdHlTdG9yYWdlKSB7fVxyXG5cclxuICAgIHByaXZhdGUgcmV0cmlldmUoa2V5OiBzdHJpbmcpOiBhbnkge1xyXG4gICAgICAgIHJldHVybiB0aGlzLm9pZGNTZWN1cml0eVN0b3JhZ2UucmVhZChrZXkpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgc3RvcmUoa2V5OiBzdHJpbmcsIHZhbHVlOiBhbnkpIHtcclxuICAgICAgICB0aGlzLm9pZGNTZWN1cml0eVN0b3JhZ2Uud3JpdGUoa2V5LCB2YWx1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmVzZXRTdG9yYWdlRGF0YShpc1JlbmV3UHJvY2VzczogYm9vbGVhbikge1xyXG4gICAgICAgIGlmICghaXNSZW5ld1Byb2Nlc3MpIHtcclxuICAgICAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2VfYXV0aF9yZXN1bHQsICcnKTtcclxuICAgICAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2Vfc2Vzc2lvbl9zdGF0ZSwgJycpO1xyXG4gICAgICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9zaWxlbnRfcmVuZXdfcnVubmluZywgJycpO1xyXG4gICAgICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9pc19hdXRob3JpemVkLCBmYWxzZSk7XHJcbiAgICAgICAgICAgIHRoaXMuc3RvcmUodGhpcy5zdG9yYWdlX2FjY2Vzc190b2tlbiwgJycpO1xyXG4gICAgICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9pZF90b2tlbiwgJycpO1xyXG4gICAgICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV91c2VyX2RhdGEsICcnKTtcclxuICAgICAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2VfY29kZV92ZXJpZmllciwgJycpO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBnZXRBY2Nlc3NUb2tlbigpOiBhbnkge1xyXG4gICAgICAgIHJldHVybiB0aGlzLnJldHJpZXZlKHRoaXMuc3RvcmFnZV9hY2Nlc3NfdG9rZW4pO1xyXG4gICAgfVxyXG5cclxuICAgIGdldElkVG9rZW4oKTogYW55IHtcclxuICAgICAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLnN0b3JhZ2VfaWRfdG9rZW4pO1xyXG4gICAgfVxyXG59XHJcbiJdfQ==