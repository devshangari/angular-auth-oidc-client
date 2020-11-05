/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
import { OidcSecurityStorage } from './oidc.security.storage';
export class OidcSecurityCommon {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS5jb21tb24uanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLWF1dGgtb2lkYy1jbGllbnQvIiwic291cmNlcyI6WyJsaWIvc2VydmljZXMvb2lkYy5zZWN1cml0eS5jb21tb24udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7OztBQUFBLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLG1CQUFtQixFQUFFLE1BQU0seUJBQXlCLENBQUM7QUFLOUQsTUFBTSxPQUFPLGtCQUFrQjs7OztJQWlIM0IsWUFBb0IsbUJBQXdDO1FBQXhDLHdCQUFtQixHQUFuQixtQkFBbUIsQ0FBcUI7UUFoSHBELHdCQUFtQixHQUFHLHFCQUFxQixDQUFDO1FBVTVDLHlCQUFvQixHQUFHLG1CQUFtQixDQUFDO1FBVTNDLHFCQUFnQixHQUFHLDBCQUEwQixDQUFDO1FBVTlDLDBCQUFxQixHQUFHLGVBQWUsQ0FBQztRQVV4QyxzQkFBaUIsR0FBRyxVQUFVLENBQUM7UUFVL0IsdUJBQWtCLEdBQUcsV0FBVyxDQUFDO1FBVWpDLDBCQUFxQixHQUFHLGVBQWUsQ0FBQztRQVV4QywrQkFBMEIsR0FBRyxrQkFBa0IsQ0FBQztRQVVoRCwwQkFBcUIsR0FBRyxlQUFlLENBQUM7UUFVeEMsaUNBQTRCLEdBQUcsOEJBQThCLENBQUM7UUFVOUQsa0NBQTZCLEdBQUcsK0JBQStCLENBQUM7SUFZVCxDQUFDOzs7O0lBOUdoRSxJQUFXLFVBQVU7UUFDakIsT0FBTyxJQUFJLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxDQUFDO0lBQ25ELENBQUM7Ozs7O0lBRUQsSUFBVyxVQUFVLENBQUMsS0FBVTtRQUM1QixJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxtQkFBbUIsRUFBRSxLQUFLLENBQUMsQ0FBQztJQUNoRCxDQUFDOzs7O0lBSUQsSUFBVyxXQUFXO1FBQ2xCLE9BQU8sSUFBSSxDQUFDLFFBQVEs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LENBQUM7Ozs7SUFFRCxjQUFjO1FBQ1YsT0FBTyxJQUFJLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxvQkFBb0IsQ0FBQyxDQUFDO0lBQ3BELENBQUM7Ozs7SUFFRCxVQUFVO1FBQ04sT0FBTyxJQUFJLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO0lBQ2hELENBQUM7OztZQS9JSixVQUFVOzs7O1lBSkYsbUJBQW1COzs7Ozs7O0lBTXhCLGlEQUFvRDs7Ozs7SUFVcEQsa0RBQW1EOzs7OztJQVVuRCw4Q0FBc0Q7Ozs7O0lBVXRELG1EQUFnRDs7Ozs7SUFVaEQsK0NBQXVDOzs7OztJQVV2QyxnREFBeUM7Ozs7O0lBVXpDLG1EQUFnRDs7Ozs7SUFVaEQsd0RBQXdEOzs7OztJQVV4RCxtREFBZ0Q7Ozs7O0lBVWhELDBEQUFzRTs7Ozs7SUFVdEUsMkRBQXdFOzs7OztJQVk1RCxpREFBZ0QiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcbmltcG9ydCB7IE9pZGNTZWN1cml0eVN0b3JhZ2UgfSBmcm9tICcuL29pZGMuc2VjdXJpdHkuc3RvcmFnZSc7XHJcblxyXG5leHBvcnQgdHlwZSBTaWxlbnRSZW5ld1N0YXRlID0gJ3J1bm5pbmcnIHwgJyc7XHJcblxyXG5ASW5qZWN0YWJsZSgpXHJcbmV4cG9ydCBjbGFzcyBPaWRjU2VjdXJpdHlDb21tb24ge1xyXG4gICAgcHJpdmF0ZSBzdG9yYWdlX2F1dGhfcmVzdWx0ID0gJ2F1dGhvcml6YXRpb25SZXN1bHQnO1xyXG5cclxuICAgIHB1YmxpYyBnZXQgYXV0aFJlc3VsdCgpOiBhbnkge1xyXG4gICAgICAgIHJldHVybiB0aGlzLnJldHJpZXZlKHRoaXMuc3RvcmFnZV9hdXRoX3Jlc3VsdCk7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIHNldCBhdXRoUmVzdWx0KHZhbHVlOiBhbnkpIHtcclxuICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9hdXRoX3Jlc3VsdCwgdmFsdWUpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgc3RvcmFnZV9hY2Nlc3NfdG9rZW4gPSAnYXV0aG9yaXphdGlvbkRhdGEnO1xyXG5cclxuICAgIHB1YmxpYyBnZXQgYWNjZXNzVG9rZW4oKTogc3RyaW5nIHtcclxuICAgICAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLnN0b3JhZ2VfYWNjZXNzX3Rva2VuKSB8fCAnJztcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgc2V0IGFjY2Vzc1Rva2VuKHZhbHVlOiBzdHJpbmcpIHtcclxuICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9hY2Nlc3NfdG9rZW4sIHZhbHVlKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHN0b3JhZ2VfaWRfdG9rZW4gPSAnYXV0aG9yaXphdGlvbkRhdGFJZFRva2VuJztcclxuXHJcbiAgICBwdWJsaWMgZ2V0IGlkVG9rZW4oKTogc3RyaW5nIHtcclxuICAgICAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLnN0b3JhZ2VfaWRfdG9rZW4pIHx8ICcnO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBzZXQgaWRUb2tlbih2YWx1ZTogc3RyaW5nKSB7XHJcbiAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2VfaWRfdG9rZW4sIHZhbHVlKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHN0b3JhZ2VfaXNfYXV0aG9yaXplZCA9ICdfaXNBdXRob3JpemVkJztcclxuXHJcbiAgICBwdWJsaWMgZ2V0IGlzQXV0aG9yaXplZCgpOiBib29sZWFuIHwgdW5kZWZpbmVkIHtcclxuICAgICAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLnN0b3JhZ2VfaXNfYXV0aG9yaXplZCk7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIHNldCBpc0F1dGhvcml6ZWQodmFsdWU6IGJvb2xlYW4gfCB1bmRlZmluZWQpIHtcclxuICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9pc19hdXRob3JpemVkLCB2YWx1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzdG9yYWdlX3VzZXJfZGF0YSA9ICd1c2VyRGF0YSc7XHJcblxyXG4gICAgcHVibGljIGdldCB1c2VyRGF0YSgpOiBhbnkge1xyXG4gICAgICAgIHJldHVybiB0aGlzLnJldHJpZXZlKHRoaXMuc3RvcmFnZV91c2VyX2RhdGEpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBzZXQgdXNlckRhdGEodmFsdWU6IGFueSkge1xyXG4gICAgICAgIHRoaXMuc3RvcmUodGhpcy5zdG9yYWdlX3VzZXJfZGF0YSwgdmFsdWUpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgc3RvcmFnZV9hdXRoX25vbmNlID0gJ2F1dGhOb25jZSc7XHJcblxyXG4gICAgcHVibGljIGdldCBhdXRoTm9uY2UoKTogc3RyaW5nIHtcclxuICAgICAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLnN0b3JhZ2VfYXV0aF9ub25jZSkgfHwgJyc7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIHNldCBhdXRoTm9uY2UodmFsdWU6IHN0cmluZykge1xyXG4gICAgICAgIHRoaXMuc3RvcmUodGhpcy5zdG9yYWdlX2F1dGhfbm9uY2UsIHZhbHVlKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHN0b3JhZ2VfY29kZV92ZXJpZmllciA9ICdjb2RlX3ZlcmlmaWVyJztcclxuXHJcbiAgICBwdWJsaWMgZ2V0IGNvZGVfdmVyaWZpZXIoKTogc3RyaW5nIHtcclxuICAgICAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLnN0b3JhZ2VfY29kZV92ZXJpZmllcikgfHwgJyc7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIHNldCBjb2RlX3ZlcmlmaWVyKHZhbHVlOiBzdHJpbmcpIHtcclxuICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9jb2RlX3ZlcmlmaWVyLCB2YWx1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzdG9yYWdlX2F1dGhfc3RhdGVfY29udHJvbCA9ICdhdXRoU3RhdGVDb250cm9sJztcclxuXHJcbiAgICBwdWJsaWMgZ2V0IGF1dGhTdGF0ZUNvbnRyb2woKTogc3RyaW5nIHtcclxuICAgICAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLnN0b3JhZ2VfYXV0aF9zdGF0ZV9jb250cm9sKSB8fCAnJztcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgc2V0IGF1dGhTdGF0ZUNvbnRyb2wodmFsdWU6IHN0cmluZykge1xyXG4gICAgICAgIHRoaXMuc3RvcmUodGhpcy5zdG9yYWdlX2F1dGhfc3RhdGVfY29udHJvbCwgdmFsdWUpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgc3RvcmFnZV9zZXNzaW9uX3N0YXRlID0gJ3Nlc3Npb25fc3RhdGUnO1xyXG5cclxuICAgIHB1YmxpYyBnZXQgc2Vzc2lvblN0YXRlKCk6IGFueSB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMucmV0cmlldmUodGhpcy5zdG9yYWdlX3Nlc3Npb25fc3RhdGUpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBzZXQgc2Vzc2lvblN0YXRlKHZhbHVlOiBhbnkpIHtcclxuICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9zZXNzaW9uX3N0YXRlLCB2YWx1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzdG9yYWdlX3NpbGVudF9yZW5ld19ydW5uaW5nID0gJ3N0b3JhZ2Vfc2lsZW50X3JlbmV3X3J1bm5pbmcnO1xyXG5cclxuICAgIHB1YmxpYyBnZXQgc2lsZW50UmVuZXdSdW5uaW5nKCk6IFNpbGVudFJlbmV3U3RhdGUge1xyXG4gICAgICAgIHJldHVybiB0aGlzLnJldHJpZXZlKHRoaXMuc3RvcmFnZV9zaWxlbnRfcmVuZXdfcnVubmluZykgfHwgJyc7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIHNldCBzaWxlbnRSZW5ld1J1bm5pbmcodmFsdWU6IFNpbGVudFJlbmV3U3RhdGUpIHtcclxuICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9zaWxlbnRfcmVuZXdfcnVubmluZywgdmFsdWUpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgc3RvcmFnZV9jdXN0b21fcmVxdWVzdF9wYXJhbXMgPSAnc3RvcmFnZV9jdXN0b21fcmVxdWVzdF9wYXJhbXMnO1xyXG5cclxuICAgIHB1YmxpYyBnZXQgY3VzdG9tUmVxdWVzdFBhcmFtcygpOiB7XHJcbiAgICAgICAgW2tleTogc3RyaW5nXTogc3RyaW5nIHwgbnVtYmVyIHwgYm9vbGVhbjtcclxuICAgIH0ge1xyXG4gICAgICAgIHJldHVybiB0aGlzLnJldHJpZXZlKHRoaXMuc3RvcmFnZV9jdXN0b21fcmVxdWVzdF9wYXJhbXMpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBzZXQgY3VzdG9tUmVxdWVzdFBhcmFtcyh2YWx1ZTogeyBba2V5OiBzdHJpbmddOiBzdHJpbmcgfCBudW1iZXIgfCBib29sZWFuIH0pIHtcclxuICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9jdXN0b21fcmVxdWVzdF9wYXJhbXMsIHZhbHVlKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIG9pZGNTZWN1cml0eVN0b3JhZ2U6IE9pZGNTZWN1cml0eVN0b3JhZ2UpIHt9XHJcblxyXG4gICAgcHJpdmF0ZSByZXRyaWV2ZShrZXk6IHN0cmluZyk6IGFueSB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMub2lkY1NlY3VyaXR5U3RvcmFnZS5yZWFkKGtleSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzdG9yZShrZXk6IHN0cmluZywgdmFsdWU6IGFueSkge1xyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5U3RvcmFnZS53cml0ZShrZXksIHZhbHVlKTtcclxuICAgIH1cclxuXHJcbiAgICByZXNldFN0b3JhZ2VEYXRhKGlzUmVuZXdQcm9jZXNzOiBib29sZWFuKSB7XHJcbiAgICAgICAgaWYgKCFpc1JlbmV3UHJvY2Vzcykge1xyXG4gICAgICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9hdXRoX3Jlc3VsdCwgJycpO1xyXG4gICAgICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9zZXNzaW9uX3N0YXRlLCAnJyk7XHJcbiAgICAgICAgICAgIHRoaXMuc3RvcmUodGhpcy5zdG9yYWdlX3NpbGVudF9yZW5ld19ydW5uaW5nLCAnJyk7XHJcbiAgICAgICAgICAgIHRoaXMuc3RvcmUodGhpcy5zdG9yYWdlX2lzX2F1dGhvcml6ZWQsIGZhbHNlKTtcclxuICAgICAgICAgICAgdGhpcy5zdG9yZSh0aGlzLnN0b3JhZ2VfYWNjZXNzX3Rva2VuLCAnJyk7XHJcbiAgICAgICAgICAgIHRoaXMuc3RvcmUodGhpcy5zdG9yYWdlX2lkX3Rva2VuLCAnJyk7XHJcbiAgICAgICAgICAgIHRoaXMuc3RvcmUodGhpcy5zdG9yYWdlX3VzZXJfZGF0YSwgJycpO1xyXG4gICAgICAgICAgICB0aGlzLnN0b3JlKHRoaXMuc3RvcmFnZV9jb2RlX3ZlcmlmaWVyLCAnJyk7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGdldEFjY2Vzc1Rva2VuKCk6IGFueSB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMucmV0cmlldmUodGhpcy5zdG9yYWdlX2FjY2Vzc190b2tlbik7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0SWRUb2tlbigpOiBhbnkge1xyXG4gICAgICAgIHJldHVybiB0aGlzLnJldHJpZXZlKHRoaXMuc3RvcmFnZV9pZF90b2tlbik7XHJcbiAgICB9XHJcbn1cclxuIl19