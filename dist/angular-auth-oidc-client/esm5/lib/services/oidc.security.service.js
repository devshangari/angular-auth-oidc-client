/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { HttpParams, HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable, NgZone } from '@angular/core';
import { Router } from '@angular/router';
import { BehaviorSubject, from, Observable, Subject, throwError as observableThrowError, timer, of } from 'rxjs';
import { catchError, filter, map, race, shareReplay, switchMap, switchMapTo, take, tap } from 'rxjs/operators';
import { OidcDataService } from '../data-services/oidc-data.service';
import { AuthorizationResult } from '../models/authorization-result';
import { AuthorizationState } from '../models/authorization-state.enum';
import { ValidateStateResult } from '../models/validate-state-result.model';
import { ValidationResult } from '../models/validation-result.enum';
import { AuthConfiguration } from '../modules/auth.configuration';
import { StateValidationService } from './oidc-security-state-validation.service';
import { TokenHelperService } from './oidc-token-helper.service';
import { LoggerService } from './oidc.logger.service';
import { OidcSecurityCheckSession } from './oidc.security.check-session';
import { OidcSecurityCommon } from './oidc.security.common';
import { OidcSecuritySilentRenew } from './oidc.security.silent-renew';
import { OidcSecurityUserService } from './oidc.security.user-service';
import { OidcSecurityValidation } from './oidc.security.validation';
import { UriEncoder } from './uri-encoder';
var OidcSecurityService = /** @class */ (function () {
    function OidcSecurityService(oidcDataService, stateValidationService, authConfiguration, router, oidcSecurityCheckSession, oidcSecuritySilentRenew, oidcSecurityUserService, oidcSecurityCommon, oidcSecurityValidation, tokenHelperService, loggerService, zone, httpClient) {
        var _this = this;
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
        function () {
            _this.moduleSetup = true;
            _this._isModuleSetup.next(true);
        }));
        this._isSetupAndAuthorized = this._isModuleSetup.pipe(filter((/**
         * @param {?} isModuleSetup
         * @return {?}
         */
        function (isModuleSetup) { return isModuleSetup; })), switchMap((/**
         * @return {?}
         */
        function () {
            if (!_this.authConfiguration.silent_renew) {
                return from([true]).pipe(tap((/**
                 * @return {?}
                 */
                function () { return _this.loggerService.logDebug("IsAuthorizedRace: Silent Renew Not Active. Emitting."); })));
            }
            /** @type {?} */
            var race$ = _this._isAuthorized.asObservable().pipe(filter((/**
             * @param {?} isAuthorized
             * @return {?}
             */
            function (isAuthorized) { return isAuthorized; })), take(1), tap((/**
             * @return {?}
             */
            function () { return _this.loggerService.logDebug('IsAuthorizedRace: Existing token is still authorized.'); })), race(_this._onAuthorizationResult.pipe(take(1), tap((/**
             * @return {?}
             */
            function () { return _this.loggerService.logDebug('IsAuthorizedRace: Silent Renew Refresh Session Complete'); })), map((/**
             * @return {?}
             */
            function () { return true; }))), timer(5000).pipe(
            // backup, if nothing happens after 5 seconds stop waiting and emit
            tap((/**
             * @return {?}
             */
            function () {
                _this.resetAuthorizationData(false);
                _this.oidcSecurityCommon.authNonce = '';
                _this.loggerService.logWarning('IsAuthorizedRace: Timeout reached. Emitting.');
            })), map((/**
             * @return {?}
             */
            function () { return true; })))));
            _this.loggerService.logDebug('Silent Renew is active, check if token in storage is active');
            if (_this.oidcSecurityCommon.authNonce === '' || _this.oidcSecurityCommon.authNonce === undefined) {
                // login not running, or a second silent renew, user must login first before this will work.
                _this.loggerService.logDebug('Silent Renew or login not running, try to refresh the session');
                _this.refreshSession();
            }
            return race$;
        })), tap((/**
         * @return {?}
         */
        function () { return _this.loggerService.logDebug('IsAuthorizedRace: Completed'); })), switchMapTo(this._isAuthorized.asObservable()), tap((/**
         * @param {?} isAuthorized
         * @return {?}
         */
        function (isAuthorized) { return _this.loggerService.logDebug("getIsAuthorized: " + isAuthorized); })), shareReplay(1));
        this._isSetupAndAuthorized.pipe(filter((/**
         * @return {?}
         */
        function () { return _this.authConfiguration.start_checksession; }))).subscribe((/**
         * @param {?} isSetupAndAuthorized
         * @return {?}
         */
        function (isSetupAndAuthorized) {
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
         */
        function () {
            return this._onModuleSetup.asObservable();
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityService.prototype, "onAuthorizationResult", {
        get: /**
         * @return {?}
         */
        function () {
            return this._onAuthorizationResult.asObservable();
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityService.prototype, "onCheckSessionChanged", {
        get: /**
         * @return {?}
         */
        function () {
            return this._onCheckSessionChanged.asObservable();
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OidcSecurityService.prototype, "onConfigurationChange", {
        get: /**
         * @return {?}
         */
        function () {
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
        this.oidcSecurityCheckSession.onCheckSessionChanged.subscribe((/**
         * @return {?}
         */
        function () {
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
            var boundSilentRenewInitEvent_1 = ((/**
             * @param {?} e
             * @return {?}
             */
            function (e) {
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
        if (encode === void 0) { encode = false; }
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
        var params = new HttpParams({
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
            .pipe(filter((/**
         * @param {?} isModuleSetup
         * @return {?}
         */
        function (isModuleSetup) { return isModuleSetup; })), take(1))
            .subscribe((/**
         * @return {?}
         */
        function () {
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
        var headers = new HttpHeaders();
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
            .pipe(map((/**
         * @param {?} response
         * @return {?}
         */
        function (response) {
            /** @type {?} */
            var obj = new Object;
            obj = response;
            obj.state = state;
            obj.session_state = session_state;
            _this.authorizedCodeFlowCallbackProcedure(obj);
        })), catchError((/**
         * @param {?} error
         * @return {?}
         */
        function (error) {
            _this.loggerService.logError(error);
            _this.loggerService.logError("OidcService code request " + _this.authConfiguration.stsServer);
            return of(false);
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
        var result = hash.split('&').reduce((/**
         * @param {?} resultData
         * @param {?} item
         * @return {?}
         */
        function (resultData, item) {
            /** @type {?} */
            var parts = item.split('=');
            resultData[(/** @type {?} */ (parts.shift()))] = parts.join('=');
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
            .pipe(filter((/**
         * @param {?} isModuleSetup
         * @return {?}
         */
        function (isModuleSetup) { return isModuleSetup; })), take(1))
            .subscribe((/**
         * @return {?}
         */
        function () {
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
            function (jwtKeys) {
                /** @type {?} */
                var validationResult = _this.getValidatedStateResult(result, jwtKeys);
                if (validationResult.authResponseIsValid) {
                    _this.setAuthorizationData(validationResult.access_token, validationResult.id_token);
                    _this.oidcSecurityCommon.silentRenewRunning = '';
                    if (_this.authConfiguration.auto_userinfo) {
                        _this.getUserinfo(isRenewProcess, result, validationResult.id_token, validationResult.decoded_id_token).subscribe((/**
                         * @param {?} response
                         * @return {?}
                         */
                        function (response) {
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
                        }), (/**
                         * @param {?} err
                         * @return {?}
                         */
                        function (err) {
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
            }), (/**
             * @param {?} err
             * @return {?}
             */
            function (err) {
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
        if (isRenewProcess === void 0) { isRenewProcess = false; }
        result = result ? result : this.oidcSecurityCommon.authResult;
        id_token = id_token ? id_token : this.oidcSecurityCommon.idToken;
        decoded_id_token = decoded_id_token ? decoded_id_token : this.tokenHelperService.getPayloadFromToken(id_token, false);
        return new Observable((/**
         * @param {?} observer
         * @return {?}
         */
        function (observer) {
            // flow id_token token
            if (_this.authConfiguration.response_type === 'id_token token' || _this.authConfiguration.response_type === 'code') {
                if (isRenewProcess && _this._userData.value) {
                    _this.oidcSecurityCommon.sessionState = result.session_state;
                    observer.next(true);
                    observer.complete();
                }
                else {
                    _this.oidcSecurityUserService.initUserData().subscribe((/**
                     * @return {?}
                     */
                    function () {
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
            return from([false]);
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
        var params = new HttpParams({
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
        Object.keys(customParams).forEach((/**
         * @param {?} key
         * @return {?}
         */
        function (key) {
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
        var params = new HttpParams({
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
            return this.oidcDataService.get(this.authWellKnownEndpoints.jwks_uri).pipe(catchError(this.handleErrorGetSigningKeys));
        }
        else {
            this.loggerService.logWarning('getSigningKeys: authWellKnownEndpoints is undefined');
        }
        return this.oidcDataService.get('undefined').pipe(catchError(this.handleErrorGetSigningKeys));
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
        return observableThrowError(errMsg);
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
        var silentRenewHeartBeatCheck = (/**
         * @return {?}
         */
        function () {
            _this.loggerService.logDebug('silentRenewHeartBeatCheck\r\n' +
                ("\tsilentRenewRunning: " + (_this.oidcSecurityCommon.silentRenewRunning === 'running') + "\r\n") +
                ("\tidToken: " + !!_this.getIdToken() + "\r\n") +
                ("\t_userData.value: " + !!_this._userData.value));
            if (_this._userData.value && _this.oidcSecurityCommon.silentRenewRunning !== 'running' && _this.getIdToken()) {
                if (_this.oidcSecurityValidation.isTokenExpired(_this.oidcSecurityCommon.idToken, _this.authConfiguration.silent_renew_offset_in_seconds)) {
                    _this.loggerService.logDebug('IsAuthorized: id_token isTokenExpired, start silent renew if active');
                    if (_this.authConfiguration.silent_renew) {
                        _this.refreshSession().subscribe((/**
                         * @return {?}
                         */
                        function () {
                            _this._scheduledHeartBeat = setTimeout(silentRenewHeartBeatCheck, 3000);
                        }), (/**
                         * @param {?} err
                         * @return {?}
                         */
                        function (err) {
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
        this.zone.runOutsideAngular((/**
         * @return {?}
         */
        function () {
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
            var params = new HttpParams({
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
        { type: Injectable }
    ];
    /** @nocollapse */
    OidcSecurityService.ctorParameters = function () { return [
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
    ]; };
    return OidcSecurityService;
}());
export { OidcSecurityService };
if (false) {
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype._onModuleSetup;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype._onCheckSessionChanged;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype._onAuthorizationResult;
    /** @type {?} */
    OidcSecurityService.prototype.checkSessionChanged;
    /** @type {?} */
    OidcSecurityService.prototype.moduleSetup;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype._isModuleSetup;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.authWellKnownEndpoints;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype._isAuthorized;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype._isSetupAndAuthorized;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype._userData;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.authWellKnownEndpointsLoaded;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.runTokenValidationRunning;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype._scheduledHeartBeat;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.boundSilentRenewEvent;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.oidcDataService;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.stateValidationService;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.authConfiguration;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.router;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.oidcSecurityCheckSession;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.oidcSecuritySilentRenew;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.oidcSecurityUserService;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.oidcSecurityCommon;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.oidcSecurityValidation;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.tokenHelperService;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.loggerService;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.zone;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityService.prototype.httpClient;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1hdXRoLW9pZGMtY2xpZW50LyIsInNvdXJjZXMiOlsibGliL3NlcnZpY2VzL29pZGMuc2VjdXJpdHkuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxVQUFVLEVBQUUsV0FBVyxFQUFFLE1BQU0sc0JBQXNCLENBQUM7QUFDM0UsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDbkQsT0FBTyxFQUFFLE1BQU0sRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQ3pDLE9BQU8sRUFBRSxlQUFlLEVBQUUsSUFBSSxFQUFFLFVBQVUsRUFBRSxPQUFPLEVBQUUsVUFBVSxJQUFJLG9CQUFvQixFQUFFLEtBQUssRUFBRSxFQUFFLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFDakgsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUUsU0FBUyxFQUFFLFdBQVcsRUFBRSxJQUFJLEVBQUUsR0FBRyxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFDL0csT0FBTyxFQUFFLGVBQWUsRUFBRSxNQUFNLG9DQUFvQyxDQUFDO0FBRXJFLE9BQU8sRUFBRSxtQkFBbUIsRUFBRSxNQUFNLGdDQUFnQyxDQUFDO0FBQ3JFLE9BQU8sRUFBRSxrQkFBa0IsRUFBRSxNQUFNLG9DQUFvQyxDQUFDO0FBRXhFLE9BQU8sRUFBRSxtQkFBbUIsRUFBRSxNQUFNLHVDQUF1QyxDQUFDO0FBQzVFLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLGtDQUFrQyxDQUFDO0FBQ3BFLE9BQU8sRUFBRSxpQkFBaUIsRUFBbUMsTUFBTSwrQkFBK0IsQ0FBQztBQUNuRyxPQUFPLEVBQUUsc0JBQXNCLEVBQUUsTUFBTSwwQ0FBMEMsQ0FBQztBQUNsRixPQUFPLEVBQUUsa0JBQWtC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REFBaUM7Ozs7O0lBQ2pDLG9EQUFtQzs7Ozs7SUFHL0IsOENBQXdDOzs7OztJQUN4QyxxREFBc0Q7Ozs7O0lBQ3RELGdEQUE0Qzs7Ozs7SUFDNUMscUNBQXNCOzs7OztJQUN0Qix1REFBMEQ7Ozs7O0lBQzFELHNEQUF3RDs7Ozs7SUFDeEQsc0RBQXdEOzs7OztJQUN4RCxpREFBOEM7Ozs7O0lBQzlDLHFEQUFzRDs7Ozs7SUFDdEQsaURBQThDOzs7OztJQUM5Qyw0Q0FBb0M7Ozs7O0lBQ3BDLG1DQUFvQjs7Ozs7SUFDcEIseUNBQXVDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSHR0cFBhcmFtcywgSHR0cENsaWVudCwgSHR0cEhlYWRlcnMgfSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XHJcbmltcG9ydCB7IEluamVjdGFibGUsIE5nWm9uZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xyXG5pbXBvcnQgeyBSb3V0ZXIgfSBmcm9tICdAYW5ndWxhci9yb3V0ZXInO1xyXG5pbXBvcnQgeyBCZWhhdmlvclN1YmplY3QsIGZyb20sIE9ic2VydmFibGUsIFN1YmplY3QsIHRocm93RXJyb3IgYXMgb2JzZXJ2YWJsZVRocm93RXJyb3IsIHRpbWVyLCBvZiB9IGZyb20gJ3J4anMnO1xyXG5pbXBvcnQgeyBjYXRjaEVycm9yLCBmaWx0ZXIsIG1hcCwgcmFjZSwgc2hhcmVSZXBsYXksIHN3aXRjaE1hcCwgc3dpdGNoTWFwVG8sIHRha2UsIHRhcCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcclxuaW1wb3J0IHsgT2lkY0RhdGFTZXJ2aWNlIH0gZnJvbSAnLi4vZGF0YS1zZXJ2aWNlcy9vaWRjLWRhdGEuc2VydmljZSc7XHJcbmltcG9ydCB7IEF1dGhXZWxsS25vd25FbmRwb2ludHMgfSBmcm9tICcuLi9tb2RlbHMvYXV0aC53ZWxsLWtub3duLWVuZHBvaW50cyc7XHJcbmltcG9ydCB7IEF1dGhvcml6YXRpb25SZXN1bHQgfSBmcm9tICcuLi9tb2RlbHMvYXV0aG9yaXphdGlvbi1yZXN1bHQnO1xyXG5pbXBvcnQgeyBBdXRob3JpemF0aW9uU3RhdGUgfSBmcm9tICcuLi9tb2RlbHMvYXV0aG9yaXphdGlvbi1zdGF0ZS5lbnVtJztcclxuaW1wb3J0IHsgSnd0S2V5cyB9IGZyb20gJy4uL21vZGVscy9qd3RrZXlzJztcclxuaW1wb3J0IHsgVmFsaWRhdGVTdGF0ZVJlc3VsdCB9IGZyb20gJy4uL21vZGVscy92YWxpZGF0ZS1zdGF0ZS1yZXN1bHQubW9kZWwnO1xyXG5pbXBvcnQgeyBWYWxpZGF0aW9uUmVzdWx0IH0gZnJvbSAnLi4vbW9kZWxzL3ZhbGlkYXRpb24tcmVzdWx0LmVudW0nO1xyXG5pbXBvcnQgeyBBdXRoQ29uZmlndXJhdGlvbiwgT3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbiB9IGZyb20gJy4uL21vZHVsZXMvYXV0aC5jb25maWd1cmF0aW9uJztcclxuaW1wb3J0IHsgU3RhdGVWYWxpZGF0aW9uU2VydmljZSB9IGZyb20gJy4vb2lkYy1zZWN1cml0eS1zdGF0ZS12YWxpZGF0aW9uLnNlcnZpY2UnO1xyXG5pbXBvcnQgeyBUb2tlbkhlbHBlclNlcnZpY2UgfSBmcm9tICcuL29pZGMtdG9rZW4taGVscGVyLnNlcnZpY2UnO1xyXG5pbXBvcnQgeyBMb2dnZXJTZXJ2aWNlIH0gZnJvbSAnLi9vaWRjLmxvZ2dlci5zZXJ2aWNlJztcclxuaW1wb3J0IHsgT2lkY1NlY3VyaXR5Q2hlY2tTZXNzaW9uIH0gZnJvbSAnLi9vaWRjLnNlY3VyaXR5LmNoZWNrLXNlc3Npb24nO1xyXG5pbXBvcnQgeyBPaWRjU2VjdXJpdHlDb21tb24gfSBmcm9tICcuL29pZGMuc2VjdXJpdHkuY29tbW9uJztcclxuaW1wb3J0IHsgT2lkY1NlY3VyaXR5U2lsZW50UmVuZXcgfSBmcm9tICcuL29pZGMuc2VjdXJpdHkuc2lsZW50LXJlbmV3JztcclxuaW1wb3J0IHsgT2lkY1NlY3VyaXR5VXNlclNlcnZpY2UgfSBmcm9tICcuL29pZGMuc2VjdXJpdHkudXNlci1zZXJ2aWNlJztcclxuaW1wb3J0IHsgT2lkY1NlY3VyaXR5VmFsaWRhdGlvbiB9IGZyb20gJy4vb2lkYy5zZWN1cml0eS52YWxpZGF0aW9uJztcclxuaW1wb3J0IHsgVXJpRW5jb2RlciB9IGZyb20gJy4vdXJpLWVuY29kZXInO1xyXG5cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgT2lkY1NlY3VyaXR5U2VydmljZSB7XHJcbiAgICBwcml2YXRlIF9vbk1vZHVsZVNldHVwID0gbmV3IFN1YmplY3Q8Ym9vbGVhbj4oKTtcclxuICAgIHByaXZhdGUgX29uQ2hlY2tTZXNzaW9uQ2hhbmdlZCA9IG5ldyBTdWJqZWN0PGJvb2xlYW4+KCk7XHJcbiAgICBwcml2YXRlIF9vbkF1dGhvcml6YXRpb25SZXN1bHQgPSBuZXcgU3ViamVjdDxBdXRob3JpemF0aW9uUmVzdWx0PigpO1xyXG5cclxuICAgIHB1YmxpYyBnZXQgb25Nb2R1bGVTZXR1cCgpOiBPYnNlcnZhYmxlPGJvb2xlYW4+IHtcclxuICAgICAgICByZXR1cm4gdGhpcy5fb25Nb2R1bGVTZXR1cC5hc09ic2VydmFibGUoKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZ2V0IG9uQXV0aG9yaXphdGlvblJlc3VsdCgpOiBPYnNlcnZhYmxlPEF1dGhvcml6YXRpb25SZXN1bHQ+IHtcclxuICAgICAgICByZXR1cm4gdGhpcy5fb25BdXRob3JpemF0aW9uUmVzdWx0LmFzT2JzZXJ2YWJsZSgpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBnZXQgb25DaGVja1Nlc3Npb25DaGFuZ2VkKCk6IE9ic2VydmFibGU8Ym9vbGVhbj4ge1xyXG4gICAgICAgIHJldHVybiB0aGlzLl9vbkNoZWNrU2Vzc2lvbkNoYW5nZWQuYXNPYnNlcnZhYmxlKCk7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIGdldCBvbkNvbmZpZ3VyYXRpb25DaGFuZ2UoKTogT2JzZXJ2YWJsZTxPcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uPiB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ub25Db25maWd1cmF0aW9uQ2hhbmdlO1xyXG4gICAgfVxyXG5cclxuICAgIGNoZWNrU2Vzc2lvbkNoYW5nZWQgPSBmYWxzZTtcclxuICAgIG1vZHVsZVNldHVwID0gZmFsc2U7XHJcblxyXG4gICAgcHJpdmF0ZSBfaXNNb2R1bGVTZXR1cCA9IG5ldyBCZWhhdmlvclN1YmplY3Q8Ym9vbGVhbj4oZmFsc2UpO1xyXG5cclxuICAgIHByaXZhdGUgYXV0aFdlbGxLbm93bkVuZHBvaW50czogQXV0aFdlbGxLbm93bkVuZHBvaW50cyB8IHVuZGVmaW5lZDtcclxuICAgIHByaXZhdGUgX2lzQXV0aG9yaXplZCA9IG5ldyBCZWhhdmlvclN1YmplY3Q8Ym9vbGVhbj4oZmFsc2UpO1xyXG4gICAgcHJpdmF0ZSBfaXNTZXR1cEFuZEF1dGhvcml6ZWQ6IE9ic2VydmFibGU8Ym9vbGVhbj47XHJcblxyXG4gICAgcHJpdmF0ZSBfdXNlckRhdGEgPSBuZXcgQmVoYXZpb3JTdWJqZWN0PGFueT4oJycpO1xyXG4gICAgcHJpdmF0ZSBhdXRoV2VsbEtub3duRW5kcG9pbnRzTG9hZGVkID0gZmFsc2U7XHJcbiAgICBwcml2YXRlIHJ1blRva2VuVmFsaWRhdGlvblJ1bm5pbmcgPSBmYWxzZTtcclxuICAgIHByaXZhdGUgX3NjaGVkdWxlZEhlYXJ0QmVhdDogYW55O1xyXG4gICAgcHJpdmF0ZSBib3VuZFNpbGVudFJlbmV3RXZlbnQ6IGFueTtcclxuXHJcbiAgICBjb25zdHJ1Y3RvcihcclxuICAgICAgICBwcml2YXRlIG9pZGNEYXRhU2VydmljZTogT2lkY0RhdGFTZXJ2aWNlLFxyXG4gICAgICAgIHByaXZhdGUgc3RhdGVWYWxpZGF0aW9uU2VydmljZTogU3RhdGVWYWxpZGF0aW9uU2VydmljZSxcclxuICAgICAgICBwcml2YXRlIGF1dGhDb25maWd1cmF0aW9uOiBBdXRoQ29uZmlndXJhdGlvbixcclxuICAgICAgICBwcml2YXRlIHJvdXRlcjogUm91dGVyLFxyXG4gICAgICAgIHByaXZhdGUgb2lkY1NlY3VyaXR5Q2hlY2tTZXNzaW9uOiBPaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24sXHJcbiAgICAgICAgcHJpdmF0ZSBvaWRjU2VjdXJpdHlTaWxlbnRSZW5ldzogT2lkY1NlY3VyaXR5U2lsZW50UmVuZXcsXHJcbiAgICAgICAgcHJpdmF0ZSBvaWRjU2VjdXJpdHlVc2VyU2VydmljZTogT2lkY1NlY3VyaXR5VXNlclNlcnZpY2UsXHJcbiAgICAgICAgcHJpdmF0ZSBvaWRjU2VjdXJpdHlDb21tb246IE9pZGNTZWN1cml0eUNvbW1vbixcclxuICAgICAgICBwcml2YXRlIG9pZGNTZWN1cml0eVZhbGlkYXRpb246IE9pZGNTZWN1cml0eVZhbGlkYXRpb24sXHJcbiAgICAgICAgcHJpdmF0ZSB0b2tlbkhlbHBlclNlcnZpY2U6IFRva2VuSGVscGVyU2VydmljZSxcclxuICAgICAgICBwcml2YXRlIGxvZ2dlclNlcnZpY2U6IExvZ2dlclNlcnZpY2UsXHJcbiAgICAgICAgcHJpdmF0ZSB6b25lOiBOZ1pvbmUsXHJcbiAgICAgICAgcHJpdmF0ZSByZWFkb25seSBodHRwQ2xpZW50OiBIdHRwQ2xpZW50XHJcbiAgICApIHtcclxuICAgICAgICB0aGlzLm9uTW9kdWxlU2V0dXAucGlwZSh0YWtlKDEpKS5zdWJzY3JpYmUoKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLm1vZHVsZVNldHVwID0gdHJ1ZTtcclxuICAgICAgICAgICAgdGhpcy5faXNNb2R1bGVTZXR1cC5uZXh0KHRydWUpO1xyXG4gICAgICAgIH0pO1xyXG5cclxuICAgICAgICB0aGlzLl9pc1NldHVwQW5kQXV0aG9yaXplZCA9IHRoaXMuX2lzTW9kdWxlU2V0dXAucGlwZShcclxuICAgICAgICAgICAgZmlsdGVyKChpc01vZHVsZVNldHVwOiBib29sZWFuKSA9PiBpc01vZHVsZVNldHVwKSxcclxuICAgICAgICAgICAgc3dpdGNoTWFwKCgpID0+IHtcclxuICAgICAgICAgICAgICAgIGlmICghdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zaWxlbnRfcmVuZXcpIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZnJvbShbdHJ1ZV0pLnBpcGUodGFwKCgpID0+IHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZyhgSXNBdXRob3JpemVkUmFjZTogU2lsZW50IFJlbmV3IE5vdCBBY3RpdmUuIEVtaXR0aW5nLmApKSk7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgY29uc3QgcmFjZSQgPSB0aGlzLl9pc0F1dGhvcml6ZWQuYXNPYnNlcnZhYmxlKCkucGlwZShcclxuICAgICAgICAgICAgICAgICAgICBmaWx0ZXIoKGlzQXV0aG9yaXplZDogYm9vbGVhbikgPT4gaXNBdXRob3JpemVkKSxcclxuICAgICAgICAgICAgICAgICAgICB0YWtlKDEpLFxyXG4gICAgICAgICAgICAgICAgICAgIHRhcCgoKSA9PiB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ0lzQXV0aG9yaXplZFJhY2U6IEV4aXN0aW5nIHRva2VuIGlzIHN0aWxsIGF1dGhvcml6ZWQuJykpLFxyXG4gICAgICAgICAgICAgICAgICAgIHJhY2UoXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX29uQXV0aG9yaXphdGlvblJlc3VsdC5waXBlKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGFrZSgxKSxcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRhcCgoKSA9PiB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ0lzQXV0aG9yaXplZFJhY2U6IFNpbGVudCBSZW5ldyBSZWZyZXNoIFNlc3Npb24gQ29tcGxldGUnKSksXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBtYXAoKCkgPT4gdHJ1ZSlcclxuICAgICAgICAgICAgICAgICAgICAgICAgKSxcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGltZXIoNTAwMCkucGlwZShcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIGJhY2t1cCwgaWYgbm90aGluZyBoYXBwZW5zIGFmdGVyIDUgc2Vjb25kcyBzdG9wIHdhaXRpbmcgYW5kIGVtaXRcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRhcCgoKSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yZXNldEF1dGhvcml6YXRpb25EYXRhKGZhbHNlKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoTm9uY2UgPSAnJztcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnSXNBdXRob3JpemVkUmFjZTogVGltZW91dCByZWFjaGVkLiBFbWl0dGluZy4nKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pLFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbWFwKCgpID0+IHRydWUpXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIClcclxuICAgICAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgICApO1xyXG5cclxuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnU2lsZW50IFJlbmV3IGlzIGFjdGl2ZSwgY2hlY2sgaWYgdG9rZW4gaW4gc3RvcmFnZSBpcyBhY3RpdmUnKTtcclxuICAgICAgICAgICAgICAgIGlmICh0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoTm9uY2UgPT09ICcnIHx8IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhOb25jZSA9PT0gdW5kZWZpbmVkKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgLy8gbG9naW4gbm90IHJ1bm5pbmcsIG9yIGEgc2Vjb25kIHNpbGVudCByZW5ldywgdXNlciBtdXN0IGxvZ2luIGZpcnN0IGJlZm9yZSB0aGlzIHdpbGwgd29yay5cclxuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ1NpbGVudCBSZW5ldyBvciBsb2dpbiBub3QgcnVubmluZywgdHJ5IHRvIHJlZnJlc2ggdGhlIHNlc3Npb24nKTtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLnJlZnJlc2hTZXNzaW9uKCk7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJhY2UkO1xyXG4gICAgICAgICAgICB9KSxcclxuICAgICAgICAgICAgdGFwKCgpID0+IHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnSXNBdXRob3JpemVkUmFjZTogQ29tcGxldGVkJykpLFxyXG4gICAgICAgICAgICBzd2l0Y2hNYXBUbyh0aGlzLl9pc0F1dGhvcml6ZWQuYXNPYnNlcnZhYmxlKCkpLFxyXG4gICAgICAgICAgICB0YXAoKGlzQXV0aG9yaXplZDogYm9vbGVhbikgPT4gdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKGBnZXRJc0F1dGhvcml6ZWQ6ICR7aXNBdXRob3JpemVkfWApKSxcclxuICAgICAgICAgICAgc2hhcmVSZXBsYXkoMSlcclxuICAgICAgICApO1xyXG5cclxuICAgICAgICB0aGlzLl9pc1NldHVwQW5kQXV0aG9yaXplZC5waXBlKGZpbHRlcigoKSA9PiB0aGlzLmF1dGhDb25maWd1cmF0aW9uLnN0YXJ0X2NoZWNrc2Vzc2lvbikpLnN1YnNjcmliZShpc1NldHVwQW5kQXV0aG9yaXplZCA9PiB7XHJcbiAgICAgICAgICAgIGlmIChpc1NldHVwQW5kQXV0aG9yaXplZCkge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24uc3RhcnRDaGVja2luZ1Nlc3Npb24odGhpcy5hdXRoQ29uZmlndXJhdGlvbi5jbGllbnRfaWQpO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24uc3RvcENoZWNraW5nU2Vzc2lvbigpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgc2V0dXBNb2R1bGUob3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbjogT3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbiwgYXV0aFdlbGxLbm93bkVuZHBvaW50czogQXV0aFdlbGxLbm93bkVuZHBvaW50cyk6IHZvaWQge1xyXG4gICAgICAgIHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cyA9IE9iamVjdC5hc3NpZ24oe30sIGF1dGhXZWxsS25vd25FbmRwb2ludHMpO1xyXG4gICAgICAgIHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uaW5pdChvcGVuSURJbXBsaWNpdEZsb3dDb25maWd1cmF0aW9uKTtcclxuICAgICAgICB0aGlzLnN0YXRlVmFsaWRhdGlvblNlcnZpY2Uuc2V0dXBNb2R1bGUoYXV0aFdlbGxLbm93bkVuZHBvaW50cyk7XHJcbiAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24uc2V0dXBNb2R1bGUoYXV0aFdlbGxLbm93bkVuZHBvaW50cyk7XHJcbiAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlVc2VyU2VydmljZS5zZXR1cE1vZHVsZShhdXRoV2VsbEtub3duRW5kcG9pbnRzKTtcclxuXHJcbiAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24ub25DaGVja1Nlc3Npb25DaGFuZ2VkLnN1YnNjcmliZSgoKSA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1Zygnb25DaGVja1Nlc3Npb25DaGFuZ2VkJyk7XHJcbiAgICAgICAgICAgIHRoaXMuY2hlY2tTZXNzaW9uQ2hhbmdlZCA9IHRydWU7XHJcbiAgICAgICAgICAgIHRoaXMuX29uQ2hlY2tTZXNzaW9uQ2hhbmdlZC5uZXh0KHRoaXMuY2hlY2tTZXNzaW9uQ2hhbmdlZCk7XHJcbiAgICAgICAgfSk7XHJcblxyXG4gICAgICAgIGNvbnN0IHVzZXJEYXRhID0gdGhpcy5vaWRjU2VjdXJpdHlDb21tb24udXNlckRhdGE7XHJcbiAgICAgICAgaWYgKHVzZXJEYXRhKSB7XHJcbiAgICAgICAgICAgIHRoaXMuc2V0VXNlckRhdGEodXNlckRhdGEpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3QgaXNBdXRob3JpemVkID0gdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uaXNBdXRob3JpemVkO1xyXG4gICAgICAgIGlmIChpc0F1dGhvcml6ZWQpIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdJc0F1dGhvcml6ZWQgc2V0dXAgbW9kdWxlJyk7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1Zyh0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5pZFRva2VuKTtcclxuICAgICAgICAgICAgaWYgKHRoaXMub2lkY1NlY3VyaXR5VmFsaWRhdGlvbi5pc1Rva2VuRXhwaXJlZCh0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5pZFRva2VuLCB0aGlzLmF1dGhDb25maWd1cmF0aW9uLnNpbGVudF9yZW5ld19vZmZzZXRfaW5fc2Vjb25kcykpIHtcclxuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnSXNBdXRob3JpemVkIHNldHVwIG1vZHVsZTsgaWRfdG9rZW4gaXNUb2tlbkV4cGlyZWQnKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnSXNBdXRob3JpemVkIHNldHVwIG1vZHVsZTsgaWRfdG9rZW4gaXMgdmFsaWQnKTtcclxuICAgICAgICAgICAgICAgIHRoaXMuc2V0SXNBdXRob3JpemVkKGlzQXV0aG9yaXplZCk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgdGhpcy5ydW5Ub2tlblZhbGlkYXRpb24oKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnU1RTIHNlcnZlcjogJyArIHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uc3RzU2VydmVyKTtcclxuXHJcbiAgICAgICAgdGhpcy5fb25Nb2R1bGVTZXR1cC5uZXh0KCk7XHJcblxyXG4gICAgICAgIGlmICh0aGlzLmF1dGhDb25maWd1cmF0aW9uLnNpbGVudF9yZW5ldykge1xyXG4gICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eVNpbGVudFJlbmV3LmluaXRSZW5ldygpO1xyXG5cclxuICAgICAgICAgICAgLy8gU3VwcG9ydCBhdXRob3JpemF0aW9uIHZpYSBET00gZXZlbnRzLlxyXG4gICAgICAgICAgICAvLyBEZXJlZ2lzdGVyIGlmIE9pZGNTZWN1cml0eVNlcnZpY2Uuc2V0dXBNb2R1bGUgaXMgY2FsbGVkIGFnYWluIGJ5IGFueSBpbnN0YW5jZS5cclxuICAgICAgICAgICAgLy8gICAgICBXZSBvbmx5IGV2ZXIgd2FudCB0aGUgbGF0ZXN0IHNldHVwIHNlcnZpY2UgdG8gYmUgcmVhY3RpbmcgdG8gdGhpcyBldmVudC5cclxuICAgICAgICAgICAgdGhpcy5ib3VuZFNpbGVudFJlbmV3RXZlbnQgPSB0aGlzLnNpbGVudFJlbmV3RXZlbnRIYW5kbGVyLmJpbmQodGhpcyk7XHJcblxyXG4gICAgICAgICAgICBjb25zdCBpbnN0YW5jZUlkID0gTWF0aC5yYW5kb20oKTtcclxuXHJcbiAgICAgICAgICAgIGNvbnN0IGJvdW5kU2lsZW50UmVuZXdJbml0RXZlbnQgPSAoKGU6IEN1c3RvbUV2ZW50KSA9PiB7XHJcbiAgICAgICAgICAgICAgICBpZiAoZS5kZXRhaWwgIT09IGluc3RhbmNlSWQpIHtcclxuICAgICAgICAgICAgICAgICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcignb2lkYy1zaWxlbnQtcmVuZXctbWVzc2FnZScsIHRoaXMuYm91bmRTaWxlbnRSZW5ld0V2ZW50KTtcclxuICAgICAgICAgICAgICAgICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcignb2lkYy1zaWxlbnQtcmVuZXctaW5pdCcsIGJvdW5kU2lsZW50UmVuZXdJbml0RXZlbnQpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9KS5iaW5kKHRoaXMpO1xyXG5cclxuICAgICAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ29pZGMtc2lsZW50LXJlbmV3LWluaXQnLCBib3VuZFNpbGVudFJlbmV3SW5pdEV2ZW50LCBmYWxzZSk7XHJcbiAgICAgICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdvaWRjLXNpbGVudC1yZW5ldy1tZXNzYWdlJywgdGhpcy5ib3VuZFNpbGVudFJlbmV3RXZlbnQsIGZhbHNlKTtcclxuXHJcbiAgICAgICAgICAgIHdpbmRvdy5kaXNwYXRjaEV2ZW50KFxyXG4gICAgICAgICAgICAgICAgbmV3IEN1c3RvbUV2ZW50KCdvaWRjLXNpbGVudC1yZW5ldy1pbml0Jywge1xyXG4gICAgICAgICAgICAgICAgICAgIGRldGFpbDogaW5zdGFuY2VJZCxcclxuICAgICAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGdldFVzZXJEYXRhKCk6IE9ic2VydmFibGU8YW55PiB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuX3VzZXJEYXRhLmFzT2JzZXJ2YWJsZSgpO1xyXG4gICAgfVxyXG5cclxuICAgIGdldElzTW9kdWxlU2V0dXAoKTogT2JzZXJ2YWJsZTxib29sZWFuPiB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuX2lzTW9kdWxlU2V0dXAuYXNPYnNlcnZhYmxlKCk7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0SXNBdXRob3JpemVkKCk6IE9ic2VydmFibGU8Ym9vbGVhbj4ge1xyXG4gICAgICAgIHJldHVybiB0aGlzLl9pc1NldHVwQW5kQXV0aG9yaXplZDtcclxuICAgIH1cclxuXHJcbiAgICBnZXRUb2tlbigpOiBzdHJpbmcge1xyXG4gICAgICAgIGlmICghdGhpcy5faXNBdXRob3JpemVkLmdldFZhbHVlKCkpIHtcclxuICAgICAgICAgICAgcmV0dXJuICcnO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3QgdG9rZW4gPSB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5nZXRBY2Nlc3NUb2tlbigpO1xyXG4gICAgICAgIHJldHVybiBkZWNvZGVVUklDb21wb25lbnQodG9rZW4pO1xyXG4gICAgfVxyXG5cclxuICAgIGdldElkVG9rZW4oKTogc3RyaW5nIHtcclxuICAgICAgICBpZiAoIXRoaXMuX2lzQXV0aG9yaXplZC5nZXRWYWx1ZSgpKSB7XHJcbiAgICAgICAgICAgIHJldHVybiAnJztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IHRva2VuID0gdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uZ2V0SWRUb2tlbigpO1xyXG4gICAgICAgIHJldHVybiBkZWNvZGVVUklDb21wb25lbnQodG9rZW4pO1xyXG4gICAgfVxyXG5cclxuICAgIGdldFBheWxvYWRGcm9tSWRUb2tlbihlbmNvZGUgPSBmYWxzZSk6IGFueSB7XHJcbiAgICAgICAgY29uc3QgdG9rZW4gPSB0aGlzLmdldElkVG9rZW4oKTtcclxuICAgICAgICByZXR1cm4gdGhpcy50b2tlbkhlbHBlclNlcnZpY2UuZ2V0UGF5bG9hZEZyb21Ub2tlbih0b2tlbiwgZW5jb2RlKTtcclxuICAgIH1cclxuXHJcbiAgICBzZXRTdGF0ZShzdGF0ZTogc3RyaW5nKTogdm9pZCB7XHJcbiAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aFN0YXRlQ29udHJvbCA9IHN0YXRlO1xyXG4gICAgfVxyXG5cclxuICAgIGdldFN0YXRlKCk6IHN0cmluZyB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhTdGF0ZUNvbnRyb2w7XHJcbiAgICB9XHJcblxyXG4gICAgc2V0Q3VzdG9tUmVxdWVzdFBhcmFtZXRlcnMocGFyYW1zOiB7IFtrZXk6IHN0cmluZ106IHN0cmluZyB8IG51bWJlciB8IGJvb2xlYW4gfSkge1xyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmN1c3RvbVJlcXVlc3RQYXJhbXMgPSBwYXJhbXM7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gQ29kZSBGbG93IHdpdGggUENLRSBvciBJbXBsaWNpdCBGbG93XHJcbiAgICBhdXRob3JpemUodXJsSGFuZGxlcj86ICh1cmw6IHN0cmluZykgPT4gYW55KSB7XHJcbiAgICAgICAgaWYgKHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cykge1xyXG4gICAgICAgICAgICB0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHNMb2FkZWQgPSB0cnVlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKCF0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHNMb2FkZWQpIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0Vycm9yKCdXZWxsIGtub3duIGVuZHBvaW50cyBtdXN0IGJlIGxvYWRlZCBiZWZvcmUgdXNlciBjYW4gbG9naW4hJyk7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmICghdGhpcy5vaWRjU2VjdXJpdHlWYWxpZGF0aW9uLmNvbmZpZ192YWxpZGF0ZV9yZXNwb25zZV90eXBlKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ucmVzcG9uc2VfdHlwZSkpIHtcclxuICAgICAgICAgICAgLy8gaW52YWxpZCByZXNwb25zZV90eXBlXHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHRoaXMucmVzZXRBdXRob3JpemF0aW9uRGF0YShmYWxzZSk7XHJcblxyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnQkVHSU4gQXV0aG9yaXplIENvZGUgRmxvdywgbm8gYXV0aCBkYXRhJyk7XHJcblxyXG4gICAgICAgIGxldCBzdGF0ZSA9IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhTdGF0ZUNvbnRyb2w7XHJcbiAgICAgICAgaWYgKCFzdGF0ZSkge1xyXG4gICAgICAgICAgICBzdGF0ZSA9IERhdGUubm93KCkgKyAnJyArIE1hdGgucmFuZG9tKCkgKyBNYXRoLnJhbmRvbSgpO1xyXG4gICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoU3RhdGVDb250cm9sID0gc3RhdGU7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBub25jZSA9ICdOJyArIE1hdGgucmFuZG9tKCkgKyAnJyArIERhdGUubm93KCk7XHJcbiAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aE5vbmNlID0gbm9uY2U7XHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdBdXRob3JpemVkQ29udHJvbGxlciBjcmVhdGVkLiBsb2NhbCBzdGF0ZTogJyArIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhTdGF0ZUNvbnRyb2wpO1xyXG5cclxuICAgICAgICBsZXQgdXJsID0gJyc7XHJcbiAgICAgICAgLy8gQ29kZSBGbG93XHJcbiAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ucmVzcG9uc2VfdHlwZSA9PT0gJ2NvZGUnKSB7XHJcblxyXG4gICAgICAgICAgICAvLyBjb2RlX2NoYWxsZW5nZSB3aXRoIFwiUzI1NlwiXHJcbiAgICAgICAgICAgIGNvbnN0IGNvZGVfdmVyaWZpZXIgPSAnQycgKyBNYXRoLnJhbmRvbSgpICsgJycgKyBEYXRlLm5vdygpICsgJycgKyBEYXRlLm5vdygpICsgTWF0aC5yYW5kb20oKTtcclxuICAgICAgICAgICAgY29uc3QgY29kZV9jaGFsbGVuZ2UgPSB0aGlzLm9pZGNTZWN1cml0eVZhbGlkYXRpb24uZ2VuZXJhdGVfY29kZV92ZXJpZmllcihjb2RlX3ZlcmlmaWVyKTtcclxuXHJcbiAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmNvZGVfdmVyaWZpZXIgPSBjb2RlX3ZlcmlmaWVyO1xyXG5cclxuICAgICAgICAgICAgaWYgKHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cykge1xyXG4gICAgICAgICAgICAgICAgdXJsID0gdGhpcy5jcmVhdGVBdXRob3JpemVVcmwodHJ1ZSwgY29kZV9jaGFsbGVuZ2UsXHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5yZWRpcmVjdF91cmwsXHJcbiAgICAgICAgICAgICAgICAgICAgbm9uY2UsXHJcbiAgICAgICAgICAgICAgICAgICAgc3RhdGUsXHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLmF1dGhvcml6YXRpb25fZW5kcG9pbnRcclxuICAgICAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRXJyb3IoJ2F1dGhXZWxsS25vd25FbmRwb2ludHMgaXMgdW5kZWZpbmVkJyk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9IGVsc2UgeyAvLyBJbXBsaWNpdCBGbG93XHJcblxyXG4gICAgICAgICAgICBpZiAodGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzKSB7XHJcbiAgICAgICAgICAgICAgICB1cmwgPSB0aGlzLmNyZWF0ZUF1dGhvcml6ZVVybChmYWxzZSwgJycsXHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5yZWRpcmVjdF91cmwsXHJcbiAgICAgICAgICAgICAgICAgICAgbm9uY2UsXHJcbiAgICAgICAgICAgICAgICAgICAgc3RhdGUsXHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLmF1dGhvcml6YXRpb25fZW5kcG9pbnRcclxuICAgICAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRXJyb3IoJ2F1dGhXZWxsS25vd25FbmRwb2ludHMgaXMgdW5kZWZpbmVkJyk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmICh1cmxIYW5kbGVyKSB7XHJcbiAgICAgICAgICAgIHVybEhhbmRsZXIodXJsKTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICB0aGlzLnJlZGlyZWN0VG8odXJsKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgLy8gQ29kZSBGbG93XHJcbiAgICBhdXRob3JpemVkQ2FsbGJhY2tXaXRoQ29kZSh1cmxUb0NoZWNrOiBzdHJpbmcpIHtcclxuICAgICAgICBjb25zdCB1cmxQYXJ0cyA9IHVybFRvQ2hlY2suc3BsaXQoJz8nKTtcclxuICAgICAgICBjb25zdCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcyh7XHJcbiAgICAgICAgICAgIGZyb21TdHJpbmc6IHVybFBhcnRzWzFdXHJcbiAgICAgICAgfSk7XHJcbiAgICAgICAgY29uc3QgY29kZSA9IHBhcmFtcy5nZXQoJ2NvZGUnKTtcclxuICAgICAgICBjb25zdCBzdGF0ZSA9IHBhcmFtcy5nZXQoJ3N0YXRlJyk7XHJcbiAgICAgICAgY29uc3Qgc2Vzc2lvbl9zdGF0ZSA9IHBhcmFtcy5nZXQoJ3Nlc3Npb25fc3RhdGUnKTtcclxuXHJcbiAgICAgICAgaWYgKGNvZGUgJiYgc3RhdGUpIHtcclxuICAgICAgICAgICAgdGhpcy5yZXF1ZXN0VG9rZW5zV2l0aENvZGUoY29kZSwgc3RhdGUsIHNlc3Npb25fc3RhdGUpO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICAvLyBDb2RlIEZsb3dcclxuICAgIHJlcXVlc3RUb2tlbnNXaXRoQ29kZShjb2RlOiBzdHJpbmcsIHN0YXRlOiBzdHJpbmcsIHNlc3Npb25fc3RhdGU6IHN0cmluZyB8IG51bGwpIHtcclxuICAgICAgICB0aGlzLl9pc01vZHVsZVNldHVwXHJcbiAgICAgICAgICAgIC5waXBlKFxyXG4gICAgICAgICAgICAgICAgZmlsdGVyKChpc01vZHVsZVNldHVwOiBib29sZWFuKSA9PiBpc01vZHVsZVNldHVwKSxcclxuICAgICAgICAgICAgICAgIHRha2UoMSlcclxuICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAuc3Vic2NyaWJlKCgpID0+IHtcclxuICAgICAgICAgICAgICAgIHRoaXMucmVxdWVzdFRva2Vuc1dpdGhDb2RlUHJvY2VkdXJlKGNvZGUsIHN0YXRlLCBzZXNzaW9uX3N0YXRlKTtcclxuICAgICAgICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gQ29kZSBGbG93IHdpdGggUENLRVxyXG4gICAgcmVxdWVzdFRva2Vuc1dpdGhDb2RlUHJvY2VkdXJlKGNvZGU6IHN0cmluZywgc3RhdGU6IHN0cmluZywgc2Vzc2lvbl9zdGF0ZTogc3RyaW5nIHwgbnVsbCkge1xyXG4gICAgICAgIGxldCB0b2tlblJlcXVlc3RVcmwgPSAnJztcclxuICAgICAgICBpZiAodGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzICYmIHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cy50b2tlbl9lbmRwb2ludCkge1xyXG4gICAgICAgICAgICB0b2tlblJlcXVlc3RVcmwgPSBgJHt0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMudG9rZW5fZW5kcG9pbnR9YDtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmICghdGhpcy5vaWRjU2VjdXJpdHlWYWxpZGF0aW9uLnZhbGlkYXRlU3RhdGVGcm9tSGFzaENhbGxiYWNrKHN0YXRlLCB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoU3RhdGVDb250cm9sKSkge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnYXV0aG9yaXplZENhbGxiYWNrIGluY29ycmVjdCBzdGF0ZScpO1xyXG4gICAgICAgICAgICAvLyBWYWxpZGF0aW9uUmVzdWx0LlN0YXRlc0RvTm90TWF0Y2g7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGxldCBoZWFkZXJzOiBIdHRwSGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpO1xyXG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQ29udGVudC1UeXBlJywgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCcpO1xyXG5cclxuICAgICAgICBsZXQgZGF0YSA9IGBncmFudF90eXBlPWF1dGhvcml6YXRpb25fY29kZSZjbGllbnRfaWQ9JHt0aGlzLmF1dGhDb25maWd1cmF0aW9uLmNsaWVudF9pZH1gXHJcbiAgICAgICAgICAgICsgYCZjb2RlX3ZlcmlmaWVyPSR7dGhpcy5vaWRjU2VjdXJpdHlDb21tb24uY29kZV92ZXJpZmllcn0mY29kZT0ke2NvZGV9JnJlZGlyZWN0X3VyaT0ke3RoaXMuYXV0aENvbmZpZ3VyYXRpb24ucmVkaXJlY3RfdXJsfWA7XHJcbiAgICAgICAgaWYgKHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLnNpbGVudFJlbmV3UnVubmluZyA9PT0gJ3J1bm5pbmcnKSB7XHJcbiAgICAgICAgICAgIGRhdGEgPSBgZ3JhbnRfdHlwZT1hdXRob3JpemF0aW9uX2NvZGUmY2xpZW50X2lkPSR7dGhpcy5hdXRoQ29uZmlndXJhdGlvbi5jbGllbnRfaWR9YFxyXG4gICAgICAgICAgICAgICAgKyBgJmNvZGVfdmVyaWZpZXI9JHt0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5jb2RlX3ZlcmlmaWVyfSZjb2RlPSR7Y29kZX0mcmVkaXJlY3RfdXJpPSR7dGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zaWxlbnRfcmVkaXJlY3RfdXJsfWA7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICB0aGlzLmh0dHBDbGllbnRcclxuICAgICAgICAgICAgLnBvc3QodG9rZW5SZXF1ZXN0VXJsLCBkYXRhLCB7IGhlYWRlcnM6IGhlYWRlcnMgfSlcclxuICAgICAgICAgICAgLnBpcGUoXHJcbiAgICAgICAgICAgIG1hcChyZXNwb25zZSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgbGV0IG9iajogYW55ID0gbmV3IE9iamVjdDtcclxuICAgICAgICAgICAgICAgICAgICBvYmogPSByZXNwb25zZTtcclxuICAgICAgICAgICAgICAgICAgICBvYmouc3RhdGUgPSBzdGF0ZTtcclxuICAgICAgICAgICAgICAgICAgICBvYmouc2Vzc2lvbl9zdGF0ZSA9IHNlc3Npb25fc3RhdGU7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuYXV0aG9yaXplZENvZGVGbG93Q2FsbGJhY2tQcm9jZWR1cmUob2JqKTtcclxuICAgICAgICAgICAgICAgIH0pLFxyXG4gICAgICAgICAgICBjYXRjaEVycm9yKGVycm9yID0+IHtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRXJyb3IoZXJyb3IpO1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dFcnJvcihgT2lkY1NlcnZpY2UgY29kZSByZXF1ZXN0ICR7dGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zdHNTZXJ2ZXJ9YCk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG9mKGZhbHNlKTtcclxuICAgICAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgIClcclxuICAgICAgICAgICAgLnN1YnNjcmliZSgpO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIENvZGUgRmxvd1xyXG4gICAgcHJpdmF0ZSBhdXRob3JpemVkQ29kZUZsb3dDYWxsYmFja1Byb2NlZHVyZShyZXN1bHQ6IGFueSkge1xyXG4gICAgICAgIGNvbnN0IHNpbGVudFJlbmV3ID0gdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uc2lsZW50UmVuZXdSdW5uaW5nO1xyXG4gICAgICAgIGNvbnN0IGlzUmVuZXdQcm9jZXNzID0gc2lsZW50UmVuZXcgPT09ICdydW5uaW5nJztcclxuXHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdCRUdJTiBhdXRob3JpemVkIENvZGUgRmxvdyBDYWxsYmFjaywgbm8gYXV0aCBkYXRhJyk7XHJcbiAgICAgICAgdGhpcy5yZXNldEF1dGhvcml6YXRpb25EYXRhKGlzUmVuZXdQcm9jZXNzKTtcclxuXHJcbiAgICAgICAgdGhpcy5hdXRob3JpemVkQ2FsbGJhY2tQcm9jZWR1cmUocmVzdWx0LCBpc1JlbmV3UHJvY2Vzcyk7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gSW1wbGljaXQgRmxvd1xyXG4gICAgcHJpdmF0ZSBhdXRob3JpemVkSW1wbGljaXRGbG93Q2FsbGJhY2tQcm9jZWR1cmUoaGFzaD86IHN0cmluZykge1xyXG4gICAgICAgIGNvbnN0IHNpbGVudFJlbmV3ID0gdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uc2lsZW50UmVuZXdSdW5uaW5nO1xyXG4gICAgICAgIGNvbnN0IGlzUmVuZXdQcm9jZXNzID0gc2lsZW50UmVuZXcgPT09ICdydW5uaW5nJztcclxuXHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdCRUdJTiBhdXRob3JpemVkQ2FsbGJhY2ssIG5vIGF1dGggZGF0YScpO1xyXG4gICAgICAgIHRoaXMucmVzZXRBdXRob3JpemF0aW9uRGF0YShpc1JlbmV3UHJvY2Vzcyk7XHJcblxyXG4gICAgICAgIGhhc2ggPSBoYXNoIHx8IHdpbmRvdy5sb2NhdGlvbi5oYXNoLnN1YnN0cigxKTtcclxuXHJcbiAgICAgICAgY29uc3QgcmVzdWx0OiBhbnkgPSBoYXNoLnNwbGl0KCcmJykucmVkdWNlKGZ1bmN0aW9uIChyZXN1bHREYXRhOiBhbnksIGl0ZW06IHN0cmluZykge1xyXG4gICAgICAgICAgICBjb25zdCBwYXJ0cyA9IGl0ZW0uc3BsaXQoJz0nKTtcclxuICAgICAgICAgICAgcmVzdWx0RGF0YVs8c3RyaW5nPnBhcnRzLnNoaWZ0KCldID0gcGFydHMuam9pbignPScpO1xyXG4gICAgICAgICAgICByZXR1cm4gcmVzdWx0RGF0YTtcclxuICAgICAgICB9LCB7fSk7XHJcblxyXG4gICAgICAgIHRoaXMuYXV0aG9yaXplZENhbGxiYWNrUHJvY2VkdXJlKHJlc3VsdCwgaXNSZW5ld1Byb2Nlc3MpO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIEltcGxpY2l0IEZsb3dcclxuICAgIGF1dGhvcml6ZWRJbXBsaWNpdEZsb3dDYWxsYmFjayhoYXNoPzogc3RyaW5nKSB7XHJcbiAgICAgICAgdGhpcy5faXNNb2R1bGVTZXR1cFxyXG4gICAgICAgICAgICAucGlwZShcclxuICAgICAgICAgICAgICAgIGZpbHRlcigoaXNNb2R1bGVTZXR1cDogYm9vbGVhbikgPT4gaXNNb2R1bGVTZXR1cCksXHJcbiAgICAgICAgICAgICAgICB0YWtlKDEpXHJcbiAgICAgICAgICAgIClcclxuICAgICAgICAgICAgLnN1YnNjcmliZSgoKSA9PiB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmF1dGhvcml6ZWRJbXBsaWNpdEZsb3dDYWxsYmFja1Byb2NlZHVyZShoYXNoKTtcclxuICAgICAgICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSByZWRpcmVjdFRvKHVybDogc3RyaW5nKSB7XHJcbiAgICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSB1cmw7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gSW1wbGljaXQgRmxvd1xyXG4gICAgcHJpdmF0ZSBhdXRob3JpemVkQ2FsbGJhY2tQcm9jZWR1cmUocmVzdWx0OiBhbnksIGlzUmVuZXdQcm9jZXNzOiBib29sZWFuKSB7XHJcbiAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aFJlc3VsdCA9IHJlc3VsdDtcclxuXHJcbiAgICAgICAgaWYgKCF0aGlzLmF1dGhDb25maWd1cmF0aW9uLmhpc3RvcnlfY2xlYW51cF9vZmYgJiYgIWlzUmVuZXdQcm9jZXNzKSB7XHJcbiAgICAgICAgICAgIC8vIHJlc2V0IHRoZSBoaXN0b3J5IHRvIHJlbW92ZSB0aGUgdG9rZW5zXHJcbiAgICAgICAgICAgIHdpbmRvdy5oaXN0b3J5LnJlcGxhY2VTdGF0ZSh7fSwgd2luZG93LmRvY3VtZW50LnRpdGxlLCB3aW5kb3cubG9jYXRpb24ub3JpZ2luICsgd2luZG93LmxvY2F0aW9uLnBhdGhuYW1lKTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ2hpc3RvcnkgY2xlYW4gdXAgaW5hY3RpdmUnKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmIChyZXN1bHQuZXJyb3IpIHtcclxuICAgICAgICAgICAgaWYgKGlzUmVuZXdQcm9jZXNzKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcocmVzdWx0KTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKHJlc3VsdCk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIGlmICgocmVzdWx0LmVycm9yIGFzIHN0cmluZykgPT09ICdsb2dpbl9yZXF1aXJlZCcpIHtcclxuICAgICAgICAgICAgICAgIHRoaXMuX29uQXV0aG9yaXphdGlvblJlc3VsdC5uZXh0KG5ldyBBdXRob3JpemF0aW9uUmVzdWx0KEF1dGhvcml6YXRpb25TdGF0ZS51bmF1dGhvcml6ZWQsIFZhbGlkYXRpb25SZXN1bHQuTG9naW5SZXF1aXJlZCkpO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5fb25BdXRob3JpemF0aW9uUmVzdWx0Lm5leHQobmV3IEF1dGhvcml6YXRpb25SZXN1bHQoQXV0aG9yaXphdGlvblN0YXRlLnVuYXV0aG9yaXplZCwgVmFsaWRhdGlvblJlc3VsdC5TZWN1cmVUb2tlblNlcnZlckVycm9yKSk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHRoaXMucmVzZXRBdXRob3JpemF0aW9uRGF0YShmYWxzZSk7XHJcbiAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhOb25jZSA9ICcnO1xyXG5cclxuICAgICAgICAgICAgaWYgKCF0aGlzLmF1dGhDb25maWd1cmF0aW9uLnRyaWdnZXJfYXV0aG9yaXphdGlvbl9yZXN1bHRfZXZlbnQgJiYgIWlzUmVuZXdQcm9jZXNzKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLnJvdXRlci5uYXZpZ2F0ZShbdGhpcy5hdXRoQ29uZmlndXJhdGlvbi51bmF1dGhvcml6ZWRfcm91dGVdKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZyhyZXN1bHQpO1xyXG5cclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdhdXRob3JpemVkQ2FsbGJhY2sgY3JlYXRlZCwgYmVnaW4gdG9rZW4gdmFsaWRhdGlvbicpO1xyXG5cclxuICAgICAgICAgICAgdGhpcy5nZXRTaWduaW5nS2V5cygpLnN1YnNjcmliZShcclxuICAgICAgICAgICAgICAgIGp3dEtleXMgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IHZhbGlkYXRpb25SZXN1bHQgPSB0aGlzLmdldFZhbGlkYXRlZFN0YXRlUmVzdWx0KHJlc3VsdCwgand0S2V5cyk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh2YWxpZGF0aW9uUmVzdWx0LmF1dGhSZXNwb25zZUlzVmFsaWQpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXRBdXRob3JpemF0aW9uRGF0YSh2YWxpZGF0aW9uUmVzdWx0LmFjY2Vzc190b2tlbiwgdmFsaWRhdGlvblJlc3VsdC5pZF90b2tlbik7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLnNpbGVudFJlbmV3UnVubmluZyA9ICcnO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uYXV0b191c2VyaW5mbykge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5nZXRVc2VyaW5mbyhpc1JlbmV3UHJvY2VzcywgcmVzdWx0LCB2YWxpZGF0aW9uUmVzdWx0LmlkX3Rva2VuLCB2YWxpZGF0aW9uUmVzdWx0LmRlY29kZWRfaWRfdG9rZW4pLnN1YnNjcmliZShcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNwb25zZSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZSkge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fb25BdXRob3JpemF0aW9uUmVzdWx0Lm5leHQoXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IEF1dGhvcml6YXRpb25SZXN1bHQoQXV0aG9yaXphdGlvblN0YXRlLmF1dGhvcml6ZWQsIHZhbGlkYXRpb25SZXN1bHQuc3RhdGUpXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLmF1dGhDb25maWd1cmF0aW9uLnRyaWdnZXJfYXV0aG9yaXphdGlvbl9yZXN1bHRfZXZlbnQgJiYgIWlzUmVuZXdQcm9jZXNzKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yb3V0ZXIubmF2aWdhdGUoW3RoaXMuYXV0aENvbmZpZ3VyYXRpb24ucG9zdF9sb2dpbl9yb3V0ZV0pO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fb25BdXRob3JpemF0aW9uUmVzdWx0Lm5leHQoXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IEF1dGhvcml6YXRpb25SZXN1bHQoQXV0aG9yaXphdGlvblN0YXRlLnVuYXV0aG9yaXplZCwgdmFsaWRhdGlvblJlc3VsdC5zdGF0ZSlcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMuYXV0aENvbmZpZ3VyYXRpb24udHJpZ2dlcl9hdXRob3JpemF0aW9uX3Jlc3VsdF9ldmVudCAmJiAhaXNSZW5ld1Byb2Nlc3MpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnJvdXRlci5uYXZpZ2F0ZShbdGhpcy5hdXRoQ29uZmlndXJhdGlvbi51bmF1dGhvcml6ZWRfcm91dGVdKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0sXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXJyID0+IHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyogU29tZXRoaW5nIHdlbnQgd3Jvbmcgd2hpbGUgZ2V0dGluZyBzaWduaW5nIGtleSAqL1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnRmFpbGVkIHRvIHJldHJlaXZlIHVzZXIgaW5mbyB3aXRoIGVycm9yOiAnICsgSlNPTi5zdHJpbmdpZnkoZXJyKSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICghaXNSZW5ld1Byb2Nlc3MpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyB1c2VyRGF0YSBpcyBzZXQgdG8gdGhlIGlkX3Rva2VuIGRlY29kZWQsIGF1dG8gZ2V0IHVzZXIgZGF0YSBzZXQgdG8gZmFsc2VcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eVVzZXJTZXJ2aWNlLnNldFVzZXJEYXRhKHZhbGlkYXRpb25SZXN1bHQuZGVjb2RlZF9pZF90b2tlbik7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXRVc2VyRGF0YSh0aGlzLm9pZGNTZWN1cml0eVVzZXJTZXJ2aWNlLmdldFVzZXJEYXRhKCkpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucnVuVG9rZW5WYWxpZGF0aW9uKCk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fb25BdXRob3JpemF0aW9uUmVzdWx0Lm5leHQobmV3IEF1dGhvcml6YXRpb25SZXN1bHQoQXV0aG9yaXphdGlvblN0YXRlLmF1dGhvcml6ZWQsIHZhbGlkYXRpb25SZXN1bHQuc3RhdGUpKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5hdXRoQ29uZmlndXJhdGlvbi50cmlnZ2VyX2F1dGhvcml6YXRpb25fcmVzdWx0X2V2ZW50ICYmICFpc1JlbmV3UHJvY2Vzcykge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucm91dGVyLm5hdmlnYXRlKFt0aGlzLmF1dGhDb25maWd1cmF0aW9uLnBvc3RfbG9naW5fcm91dGVdKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIHNvbWV0aGluZyB3ZW50IHdyb25nXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdhdXRob3JpemVkQ2FsbGJhY2ssIHRva2VuKHMpIHZhbGlkYXRpb24gZmFpbGVkLCByZXNldHRpbmcnKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcod2luZG93LmxvY2F0aW9uLmhhc2gpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnJlc2V0QXV0aG9yaXphdGlvbkRhdGEoZmFsc2UpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zaWxlbnRSZW5ld1J1bm5pbmcgPSAnJztcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX29uQXV0aG9yaXphdGlvblJlc3VsdC5uZXh0KG5ldyBBdXRob3JpemF0aW9uUmVzdWx0KEF1dGhvcml6YXRpb25TdGF0ZS51bmF1dGhvcml6ZWQsIHZhbGlkYXRpb25SZXN1bHQuc3RhdGUpKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLmF1dGhDb25maWd1cmF0aW9uLnRyaWdnZXJfYXV0aG9yaXphdGlvbl9yZXN1bHRfZXZlbnQgJiYgIWlzUmVuZXdQcm9jZXNzKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnJvdXRlci5uYXZpZ2F0ZShbdGhpcy5hdXRoQ29uZmlndXJhdGlvbi51bmF1dGhvcml6ZWRfcm91dGVdKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH0sXHJcbiAgICAgICAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIC8qIFNvbWV0aGluZyB3ZW50IHdyb25nIHdoaWxlIGdldHRpbmcgc2lnbmluZyBrZXkgKi9cclxuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnRmFpbGVkIHRvIHJldHJlaXZlIHNpZ2luZyBrZXkgd2l0aCBlcnJvcjogJyArIEpTT04uc3RyaW5naWZ5KGVycikpO1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLnNpbGVudFJlbmV3UnVubmluZyA9ICcnO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBnZXRVc2VyaW5mbyhpc1JlbmV3UHJvY2VzcyA9IGZhbHNlLCByZXN1bHQ/OiBhbnksIGlkX3Rva2VuPzogYW55LCBkZWNvZGVkX2lkX3Rva2VuPzogYW55KTogT2JzZXJ2YWJsZTxib29sZWFuPiB7XHJcbiAgICAgICAgcmVzdWx0ID0gcmVzdWx0ID8gcmVzdWx0IDogdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aFJlc3VsdDtcclxuICAgICAgICBpZF90b2tlbiA9IGlkX3Rva2VuID8gaWRfdG9rZW4gOiB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5pZFRva2VuO1xyXG4gICAgICAgIGRlY29kZWRfaWRfdG9rZW4gPSBkZWNvZGVkX2lkX3Rva2VuID8gZGVjb2RlZF9pZF90b2tlbiA6IHRoaXMudG9rZW5IZWxwZXJTZXJ2aWNlLmdldFBheWxvYWRGcm9tVG9rZW4oaWRfdG9rZW4sIGZhbHNlKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIG5ldyBPYnNlcnZhYmxlPGJvb2xlYW4+KG9ic2VydmVyID0+IHtcclxuICAgICAgICAgICAgLy8gZmxvdyBpZF90b2tlbiB0b2tlblxyXG4gICAgICAgICAgICBpZiAodGhpcy5hdXRoQ29uZmlndXJhdGlvbi5yZXNwb25zZV90eXBlID09PSAnaWRfdG9rZW4gdG9rZW4nIHx8IHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ucmVzcG9uc2VfdHlwZSA9PT0gJ2NvZGUnKSB7XHJcbiAgICAgICAgICAgICAgICBpZiAoaXNSZW5ld1Byb2Nlc3MgJiYgdGhpcy5fdXNlckRhdGEudmFsdWUpIHtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zZXNzaW9uU3RhdGUgPSByZXN1bHQuc2Vzc2lvbl9zdGF0ZTtcclxuICAgICAgICAgICAgICAgICAgICBvYnNlcnZlci5uZXh0KHRydWUpO1xyXG4gICAgICAgICAgICAgICAgICAgIG9ic2VydmVyLmNvbXBsZXRlKCk7XHJcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5VXNlclNlcnZpY2UuaW5pdFVzZXJEYXRhKCkuc3Vic2NyaWJlKCgpID0+IHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdhdXRob3JpemVkQ2FsbGJhY2sgKGlkX3Rva2VuIHRva2VuIHx8IGNvZGUpIGZsb3cnKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHVzZXJEYXRhID0gdGhpcy5vaWRjU2VjdXJpdHlVc2VyU2VydmljZS5nZXRVc2VyRGF0YSgpO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMub2lkY1NlY3VyaXR5VmFsaWRhdGlvbi52YWxpZGF0ZV91c2VyZGF0YV9zdWJfaWRfdG9rZW4oZGVjb2RlZF9pZF90b2tlbi5zdWIsIHVzZXJEYXRhLnN1YikpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc2V0VXNlckRhdGEodXNlckRhdGEpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmFjY2Vzc1Rva2VuKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1Zyh0aGlzLm9pZGNTZWN1cml0eVVzZXJTZXJ2aWNlLmdldFVzZXJEYXRhKCkpO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLnNlc3Npb25TdGF0ZSA9IHJlc3VsdC5zZXNzaW9uX3N0YXRlO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucnVuVG9rZW5WYWxpZGF0aW9uKCk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvYnNlcnZlci5uZXh0KHRydWUpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gc29tZXRoaW5nIHdlbnQgd3JvbmcsIHVzZXJkYXRhIHN1YiBkb2VzIG5vdCBtYXRjaCB0aGF0IGZyb20gaWRfdG9rZW5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdhdXRob3JpemVkQ2FsbGJhY2ssIFVzZXIgZGF0YSBzdWIgZG9lcyBub3QgbWF0Y2ggc3ViIGluIGlkX3Rva2VuJyk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ2F1dGhvcml6ZWRDYWxsYmFjaywgdG9rZW4ocykgdmFsaWRhdGlvbiBmYWlsZWQsIHJlc2V0dGluZycpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yZXNldEF1dGhvcml6YXRpb25EYXRhKGZhbHNlKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9ic2VydmVyLm5leHQoZmFsc2UpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9ic2VydmVyLmNvbXBsZXRlKCk7XHJcbiAgICAgICAgICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICAvLyBmbG93IGlkX3Rva2VuXHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ2F1dGhvcml6ZWRDYWxsYmFjayBpZF90b2tlbiBmbG93Jyk7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcodGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYWNjZXNzVG9rZW4pO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIHVzZXJEYXRhIGlzIHNldCB0byB0aGUgaWRfdG9rZW4gZGVjb2RlZC4gTm8gYWNjZXNzX3Rva2VuLlxyXG4gICAgICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlVc2VyU2VydmljZS5zZXRVc2VyRGF0YShkZWNvZGVkX2lkX3Rva2VuKTtcclxuICAgICAgICAgICAgICAgIHRoaXMuc2V0VXNlckRhdGEodGhpcy5vaWRjU2VjdXJpdHlVc2VyU2VydmljZS5nZXRVc2VyRGF0YSgpKTtcclxuXHJcbiAgICAgICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zZXNzaW9uU3RhdGUgPSByZXN1bHQuc2Vzc2lvbl9zdGF0ZTtcclxuXHJcbiAgICAgICAgICAgICAgICB0aGlzLnJ1blRva2VuVmFsaWRhdGlvbigpO1xyXG5cclxuICAgICAgICAgICAgICAgIG9ic2VydmVyLm5leHQodHJ1ZSk7XHJcbiAgICAgICAgICAgICAgICBvYnNlcnZlci5jb21wbGV0ZSgpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgbG9nb2ZmKHVybEhhbmRsZXI/OiAodXJsOiBzdHJpbmcpID0+IGFueSkge1xyXG4gICAgICAgIC8vIC9jb25uZWN0L2VuZHNlc3Npb24/aWRfdG9rZW5faGludD0uLi4mcG9zdF9sb2dvdXRfcmVkaXJlY3RfdXJpPWh0dHBzOi8vbXlhcHAuY29tXHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdCRUdJTiBBdXRob3JpemUsIG5vIGF1dGggZGF0YScpO1xyXG5cclxuICAgICAgICBpZiAodGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzKSB7XHJcbiAgICAgICAgICAgIGlmICh0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMuZW5kX3Nlc3Npb25fZW5kcG9pbnQpIHtcclxuICAgICAgICAgICAgICAgIGNvbnN0IGVuZF9zZXNzaW9uX2VuZHBvaW50ID0gdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLmVuZF9zZXNzaW9uX2VuZHBvaW50O1xyXG4gICAgICAgICAgICAgICAgY29uc3QgaWRfdG9rZW5faGludCA9IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmlkVG9rZW47XHJcbiAgICAgICAgICAgICAgICBjb25zdCB1cmwgPSB0aGlzLmNyZWF0ZUVuZFNlc3Npb25VcmwoZW5kX3Nlc3Npb25fZW5kcG9pbnQsIGlkX3Rva2VuX2hpbnQpO1xyXG5cclxuICAgICAgICAgICAgICAgIHRoaXMucmVzZXRBdXRob3JpemF0aW9uRGF0YShmYWxzZSk7XHJcblxyXG4gICAgICAgICAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uc3RhcnRfY2hlY2tzZXNzaW9uICYmIHRoaXMuY2hlY2tTZXNzaW9uQ2hhbmdlZCkge1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1Zygnb25seSBsb2NhbCBsb2dpbiBjbGVhbmVkIHVwLCBzZXJ2ZXIgc2Vzc2lvbiBoYXMgY2hhbmdlZCcpO1xyXG4gICAgICAgICAgICAgICAgfSBlbHNlIGlmICh1cmxIYW5kbGVyKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgdXJsSGFuZGxlcih1cmwpO1xyXG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLnJlZGlyZWN0VG8odXJsKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgIHRoaXMucmVzZXRBdXRob3JpemF0aW9uRGF0YShmYWxzZSk7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ29ubHkgbG9jYWwgbG9naW4gY2xlYW5lZCB1cCwgbm8gZW5kX3Nlc3Npb25fZW5kcG9pbnQnKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdhdXRoV2VsbEtub3duRW5kcG9pbnRzIGlzIHVuZGVmaW5lZCcpO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZWZyZXNoU2Vzc2lvbigpOiBPYnNlcnZhYmxlPGFueT4ge1xyXG4gICAgICAgIGlmICghdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zaWxlbnRfcmVuZXcpIHtcclxuICAgICAgICAgICAgcmV0dXJuIGZyb20oW2ZhbHNlXSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ0JFR0lOIHJlZnJlc2ggc2Vzc2lvbiBBdXRob3JpemUnKTtcclxuXHJcbiAgICAgICAgbGV0IHN0YXRlID0gdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aFN0YXRlQ29udHJvbDtcclxuICAgICAgICBpZiAoc3RhdGUgPT09ICcnIHx8IHN0YXRlID09PSBudWxsKSB7XHJcbiAgICAgICAgICAgIHN0YXRlID0gRGF0ZS5ub3coKSArICcnICsgTWF0aC5yYW5kb20oKSArIE1hdGgucmFuZG9tKCk7XHJcbiAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhTdGF0ZUNvbnRyb2wgPSBzdGF0ZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IG5vbmNlID0gJ04nICsgTWF0aC5yYW5kb20oKSArICcnICsgRGF0ZS5ub3coKTtcclxuICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoTm9uY2UgPSBub25jZTtcclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ1JlZnJlc2hTZXNzaW9uIGNyZWF0ZWQuIGFkZGluZyBteWF1dG9zdGF0ZTogJyArIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhTdGF0ZUNvbnRyb2wpO1xyXG5cclxuICAgICAgICBsZXQgdXJsID0gJyc7XHJcblxyXG4gICAgICAgIC8vIENvZGUgRmxvd1xyXG4gICAgICAgIGlmICh0aGlzLmF1dGhDb25maWd1cmF0aW9uLnJlc3BvbnNlX3R5cGUgPT09ICdjb2RlJykge1xyXG5cclxuICAgICAgICAgICAgLy8gY29kZV9jaGFsbGVuZ2Ugd2l0aCBcIlMyNTZcIlxyXG4gICAgICAgICAgICBjb25zdCBjb2RlX3ZlcmlmaWVyID0gJ0MnICsgTWF0aC5yYW5kb20oKSArICcnICsgRGF0ZS5ub3coKSArICcnICsgRGF0ZS5ub3coKSArIE1hdGgucmFuZG9tKCk7XHJcbiAgICAgICAgICAgIGNvbnN0IGNvZGVfY2hhbGxlbmdlID0gdGhpcy5vaWRjU2VjdXJpdHlWYWxpZGF0aW9uLmdlbmVyYXRlX2NvZGVfdmVyaWZpZXIoY29kZV92ZXJpZmllcik7XHJcblxyXG4gICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5jb2RlX3ZlcmlmaWVyID0gY29kZV92ZXJpZmllcjtcclxuXHJcbiAgICAgICAgICAgIGlmICh0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMpIHtcclxuICAgICAgICAgICAgICAgIHVybCA9IHRoaXMuY3JlYXRlQXV0aG9yaXplVXJsKHRydWUsIGNvZGVfY2hhbGxlbmdlLFxyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uc2lsZW50X3JlZGlyZWN0X3VybCxcclxuICAgICAgICAgICAgICAgICAgICBub25jZSxcclxuICAgICAgICAgICAgICAgICAgICBzdGF0ZSxcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMuYXV0aG9yaXphdGlvbl9lbmRwb2ludCxcclxuICAgICAgICAgICAgICAgICAgICAnbm9uZSdcclxuICAgICAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnYXV0aFdlbGxLbm93bkVuZHBvaW50cyBpcyB1bmRlZmluZWQnKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgIGlmICh0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMpIHtcclxuICAgICAgICAgICAgICAgIHVybCA9IHRoaXMuY3JlYXRlQXV0aG9yaXplVXJsKGZhbHNlLCAnJyxcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLmF1dGhDb25maWd1cmF0aW9uLnNpbGVudF9yZWRpcmVjdF91cmwsXHJcbiAgICAgICAgICAgICAgICAgICAgbm9uY2UsXHJcbiAgICAgICAgICAgICAgICAgICAgc3RhdGUsXHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLmF1dGhvcml6YXRpb25fZW5kcG9pbnQsXHJcbiAgICAgICAgICAgICAgICAgICAgJ25vbmUnXHJcbiAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2F1dGhXZWxsS25vd25FbmRwb2ludHMgaXMgdW5kZWZpbmVkJyk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLnNpbGVudFJlbmV3UnVubmluZyA9ICdydW5uaW5nJztcclxuICAgICAgICByZXR1cm4gdGhpcy5vaWRjU2VjdXJpdHlTaWxlbnRSZW5ldy5zdGFydFJlbmV3KHVybCk7XHJcbiAgICB9XHJcblxyXG4gICAgaGFuZGxlRXJyb3IoZXJyb3I6IGFueSkge1xyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dFcnJvcihlcnJvcik7XHJcbiAgICAgICAgaWYgKGVycm9yLnN0YXR1cyA9PT0gNDAzIHx8IGVycm9yLnN0YXR1cyA9PT0gJzQwMycpIHtcclxuICAgICAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24udHJpZ2dlcl9hdXRob3JpemF0aW9uX3Jlc3VsdF9ldmVudCkge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5fb25BdXRob3JpemF0aW9uUmVzdWx0Lm5leHQobmV3IEF1dGhvcml6YXRpb25SZXN1bHQoQXV0aG9yaXphdGlvblN0YXRlLnVuYXV0aG9yaXplZCwgVmFsaWRhdGlvblJlc3VsdC5Ob3RTZXQpKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgIHRoaXMucm91dGVyLm5hdmlnYXRlKFt0aGlzLmF1dGhDb25maWd1cmF0aW9uLmZvcmJpZGRlbl9yb3V0ZV0pO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfSBlbHNlIGlmIChlcnJvci5zdGF0dXMgPT09IDQwMSB8fCBlcnJvci5zdGF0dXMgPT09ICc0MDEnKSB7XHJcbiAgICAgICAgICAgIGNvbnN0IHNpbGVudFJlbmV3ID0gdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uc2lsZW50UmVuZXdSdW5uaW5nO1xyXG5cclxuICAgICAgICAgICAgdGhpcy5yZXNldEF1dGhvcml6YXRpb25EYXRhKCEhc2lsZW50UmVuZXcpO1xyXG5cclxuICAgICAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24udHJpZ2dlcl9hdXRob3JpemF0aW9uX3Jlc3VsdF9ldmVudCkge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5fb25BdXRob3JpemF0aW9uUmVzdWx0Lm5leHQobmV3IEF1dGhvcml6YXRpb25SZXN1bHQoQXV0aG9yaXphdGlvblN0YXRlLnVuYXV0aG9yaXplZCwgVmFsaWRhdGlvblJlc3VsdC5Ob3RTZXQpKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgIHRoaXMucm91dGVyLm5hdmlnYXRlKFt0aGlzLmF1dGhDb25maWd1cmF0aW9uLnVuYXV0aG9yaXplZF9yb3V0ZV0pO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHN0YXJ0Q2hlY2tpbmdTaWxlbnRSZW5ldygpOiB2b2lkIHtcclxuICAgICAgICB0aGlzLnJ1blRva2VuVmFsaWRhdGlvbigpO1xyXG4gICAgfVxyXG5cclxuICAgIHN0b3BDaGVja2luZ1NpbGVudFJlbmV3KCk6IHZvaWQge1xyXG4gICAgICAgIGlmICh0aGlzLl9zY2hlZHVsZWRIZWFydEJlYXQpIHtcclxuICAgICAgICAgICAgY2xlYXJUaW1lb3V0KHRoaXMuX3NjaGVkdWxlZEhlYXJ0QmVhdCk7XHJcbiAgICAgICAgICAgIHRoaXMuX3NjaGVkdWxlZEhlYXJ0QmVhdCA9IG51bGw7XHJcbiAgICAgICAgICAgIHRoaXMucnVuVG9rZW5WYWxpZGF0aW9uUnVubmluZyA9IGZhbHNlO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXNldEF1dGhvcml6YXRpb25EYXRhKGlzUmVuZXdQcm9jZXNzOiBib29sZWFuKTogdm9pZCB7XHJcbiAgICAgICAgaWYgKCFpc1JlbmV3UHJvY2Vzcykge1xyXG4gICAgICAgICAgICBpZiAodGhpcy5hdXRoQ29uZmlndXJhdGlvbi5hdXRvX3VzZXJpbmZvKSB7XHJcbiAgICAgICAgICAgICAgICAvLyBDbGVhciB1c2VyIGRhdGEuIEZpeGVzICM5Ny5cclxuICAgICAgICAgICAgICAgIHRoaXMuc2V0VXNlckRhdGEoJycpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5yZXNldFN0b3JhZ2VEYXRhKGlzUmVuZXdQcm9jZXNzKTtcclxuICAgICAgICAgICAgdGhpcy5jaGVja1Nlc3Npb25DaGFuZ2VkID0gZmFsc2U7XHJcbiAgICAgICAgICAgIHRoaXMuc2V0SXNBdXRob3JpemVkKGZhbHNlKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0RW5kU2Vzc2lvblVybCgpOiBzdHJpbmcgfCB1bmRlZmluZWQge1xyXG4gICAgICAgIGlmICh0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMpIHtcclxuICAgICAgICAgICAgaWYgKHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cy5lbmRfc2Vzc2lvbl9lbmRwb2ludCkge1xyXG4gICAgICAgICAgICAgICAgY29uc3QgZW5kX3Nlc3Npb25fZW5kcG9pbnQgPSB0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMuZW5kX3Nlc3Npb25fZW5kcG9pbnQ7XHJcbiAgICAgICAgICAgICAgICBjb25zdCBpZF90b2tlbl9oaW50ID0gdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uaWRUb2tlbjtcclxuICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLmNyZWF0ZUVuZFNlc3Npb25VcmwoZW5kX3Nlc3Npb25fZW5kcG9pbnQsIGlkX3Rva2VuX2hpbnQpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgZ2V0VmFsaWRhdGVkU3RhdGVSZXN1bHQocmVzdWx0OiBhbnksIGp3dEtleXM6IEp3dEtleXMpOiBWYWxpZGF0ZVN0YXRlUmVzdWx0IHtcclxuICAgICAgICBpZiAocmVzdWx0LmVycm9yKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGVTdGF0ZVJlc3VsdCgnJywgJycsIGZhbHNlLCB7fSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5zdGF0ZVZhbGlkYXRpb25TZXJ2aWNlLnZhbGlkYXRlU3RhdGUocmVzdWx0LCBqd3RLZXlzKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHNldFVzZXJEYXRhKHVzZXJEYXRhOiBhbnkpOiB2b2lkIHtcclxuICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi51c2VyRGF0YSA9IHVzZXJEYXRhO1xyXG4gICAgICAgIHRoaXMuX3VzZXJEYXRhLm5leHQodXNlckRhdGEpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgc2V0SXNBdXRob3JpemVkKGlzQXV0aG9yaXplZDogYm9vbGVhbik6IHZvaWQge1xyXG4gICAgICAgIHRoaXMuX2lzQXV0aG9yaXplZC5uZXh0KGlzQXV0aG9yaXplZCk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzZXRBdXRob3JpemF0aW9uRGF0YShhY2Nlc3NfdG9rZW46IGFueSwgaWRfdG9rZW46IGFueSkge1xyXG4gICAgICAgIGlmICh0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hY2Nlc3NUb2tlbiAhPT0gJycpIHtcclxuICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYWNjZXNzVG9rZW4gPSAnJztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZyhhY2Nlc3NfdG9rZW4pO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZyhpZF90b2tlbik7XHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdzdG9yaW5nIHRvIHN0b3JhZ2UsIGdldHRpbmcgdGhlIHJvbGVzJyk7XHJcbiAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYWNjZXNzVG9rZW4gPSBhY2Nlc3NfdG9rZW47XHJcbiAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uaWRUb2tlbiA9IGlkX3Rva2VuO1xyXG4gICAgICAgIHRoaXMuc2V0SXNBdXRob3JpemVkKHRydWUpO1xyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmlzQXV0aG9yaXplZCA9IHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBjcmVhdGVBdXRob3JpemVVcmwoaXNDb2RlRmxvdzogYm9vbGVhbiwgY29kZV9jaGFsbGVuZ2U6IHN0cmluZywgcmVkaXJlY3RfdXJsOiBzdHJpbmcsIG5vbmNlOiBzdHJpbmcsIHN0YXRlOiBzdHJpbmcsIGF1dGhvcml6YXRpb25fZW5kcG9pbnQ6IHN0cmluZywgcHJvbXB0Pzogc3RyaW5nKTogc3RyaW5nIHtcclxuICAgICAgICBjb25zdCB1cmxQYXJ0cyA9IGF1dGhvcml6YXRpb25fZW5kcG9pbnQuc3BsaXQoJz8nKTtcclxuICAgICAgICBjb25zdCBhdXRob3JpemF0aW9uVXJsID0gdXJsUGFydHNbMF07XHJcbiAgICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKHtcclxuICAgICAgICAgICAgZnJvbVN0cmluZzogdXJsUGFydHNbMV0sXHJcbiAgICAgICAgICAgIGVuY29kZXI6IG5ldyBVcmlFbmNvZGVyKCksXHJcbiAgICAgICAgfSk7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5jbGllbnRfaWQpO1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5hcHBlbmQoJ3JlZGlyZWN0X3VyaScsIHJlZGlyZWN0X3VybCk7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLmFwcGVuZCgncmVzcG9uc2VfdHlwZScsIHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ucmVzcG9uc2VfdHlwZSk7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLmFwcGVuZCgnc2NvcGUnLCB0aGlzLmF1dGhDb25maWd1cmF0aW9uLnNjb3BlKTtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuYXBwZW5kKCdub25jZScsIG5vbmNlKTtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuYXBwZW5kKCdzdGF0ZScsIHN0YXRlKTtcclxuXHJcbiAgICAgICAgaWYgKGlzQ29kZUZsb3cpIHtcclxuXHJcbiAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5hcHBlbmQoJ2NvZGVfY2hhbGxlbmdlJywgY29kZV9jaGFsbGVuZ2UpO1xyXG4gICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuYXBwZW5kKCdjb2RlX2NoYWxsZW5nZV9tZXRob2QnLCAnUzI1NicpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKHByb21wdCkge1xyXG4gICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuYXBwZW5kKCdwcm9tcHQnLCBwcm9tcHQpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uaGRfcGFyYW0pIHtcclxuICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLmFwcGVuZCgnaGQnLCB0aGlzLmF1dGhDb25maWd1cmF0aW9uLmhkX3BhcmFtKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IGN1c3RvbVBhcmFtcyA9IE9iamVjdC5hc3NpZ24oe30sIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmN1c3RvbVJlcXVlc3RQYXJhbXMpO1xyXG5cclxuICAgICAgICBPYmplY3Qua2V5cyhjdXN0b21QYXJhbXMpLmZvckVhY2goa2V5ID0+IHtcclxuICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLmFwcGVuZChrZXksIGN1c3RvbVBhcmFtc1trZXldLnRvU3RyaW5nKCkpO1xyXG4gICAgICAgIH0pO1xyXG5cclxuICAgICAgICByZXR1cm4gYCR7YXV0aG9yaXphdGlvblVybH0/JHtwYXJhbXN9YDtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIGNyZWF0ZUVuZFNlc3Npb25VcmwoZW5kX3Nlc3Npb25fZW5kcG9pbnQ6IHN0cmluZywgaWRfdG9rZW5faGludDogc3RyaW5nKSB7XHJcbiAgICAgICAgY29uc3QgdXJsUGFydHMgPSBlbmRfc2Vzc2lvbl9lbmRwb2ludC5zcGxpdCgnPycpO1xyXG5cclxuICAgICAgICBjb25zdCBhdXRob3JpemF0aW9uRW5kc2Vzc2lvblVybCA9IHVybFBhcnRzWzBdO1xyXG5cclxuICAgICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoe1xyXG4gICAgICAgICAgICBmcm9tU3RyaW5nOiB1cmxQYXJ0c1sxXSxcclxuICAgICAgICAgICAgZW5jb2RlcjogbmV3IFVyaUVuY29kZXIoKSxcclxuICAgICAgICB9KTtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdpZF90b2tlbl9oaW50JywgaWRfdG9rZW5faGludCk7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLmFwcGVuZCgncG9zdF9sb2dvdXRfcmVkaXJlY3RfdXJpJywgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5wb3N0X2xvZ291dF9yZWRpcmVjdF91cmkpO1xyXG5cclxuICAgICAgICByZXR1cm4gYCR7YXV0aG9yaXphdGlvbkVuZHNlc3Npb25Vcmx9PyR7cGFyYW1zfWA7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBnZXRTaWduaW5nS2V5cygpOiBPYnNlcnZhYmxlPEp3dEtleXM+IHtcclxuICAgICAgICBpZiAodGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1Zygnandrc191cmk6ICcgKyB0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMuandrc191cmkpO1xyXG5cclxuICAgICAgICAgICAgcmV0dXJuIHRoaXMub2lkY0RhdGFTZXJ2aWNlLmdldDxKd3RLZXlzPih0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMuandrc191cmkpLnBpcGUoY2F0Y2hFcnJvcih0aGlzLmhhbmRsZUVycm9yR2V0U2lnbmluZ0tleXMpKTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnZ2V0U2lnbmluZ0tleXM6IGF1dGhXZWxsS25vd25FbmRwb2ludHMgaXMgdW5kZWZpbmVkJyk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5vaWRjRGF0YVNlcnZpY2UuZ2V0PEp3dEtleXM+KCd1bmRlZmluZWQnKS5waXBlKGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvckdldFNpZ25pbmdLZXlzKSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBoYW5kbGVFcnJvckdldFNpZ25pbmdLZXlzKGVycm9yOiBSZXNwb25zZSB8IGFueSkge1xyXG4gICAgICAgIGxldCBlcnJNc2c6IHN0cmluZztcclxuICAgICAgICBpZiAoZXJyb3IgaW5zdGFuY2VvZiBSZXNwb25zZSkge1xyXG4gICAgICAgICAgICBjb25zdCBib2R5ID0gZXJyb3IuanNvbigpIHx8IHt9O1xyXG4gICAgICAgICAgICBjb25zdCBlcnIgPSBKU09OLnN0cmluZ2lmeShib2R5KTtcclxuICAgICAgICAgICAgZXJyTXNnID0gYCR7ZXJyb3Iuc3RhdHVzfSAtICR7ZXJyb3Iuc3RhdHVzVGV4dCB8fCAnJ30gJHtlcnJ9YDtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICBlcnJNc2cgPSBlcnJvci5tZXNzYWdlID8gZXJyb3IubWVzc2FnZSA6IGVycm9yLnRvU3RyaW5nKCk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyTXNnKTtcclxuICAgICAgICByZXR1cm4gb2JzZXJ2YWJsZVRocm93RXJyb3IoZXJyTXNnKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHJ1blRva2VuVmFsaWRhdGlvbigpIHtcclxuICAgICAgICBpZiAodGhpcy5ydW5Ub2tlblZhbGlkYXRpb25SdW5uaW5nIHx8ICF0aGlzLmF1dGhDb25maWd1cmF0aW9uLnNpbGVudF9yZW5ldykge1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHRoaXMucnVuVG9rZW5WYWxpZGF0aW9uUnVubmluZyA9IHRydWU7XHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdydW5Ub2tlblZhbGlkYXRpb24gc2lsZW50LXJlbmV3IHJ1bm5pbmcnKTtcclxuXHJcbiAgICAgICAgLyoqXHJcbiAgICAgICAgICAgIEZpcnN0IHRpbWU6IGRlbGF5IDEwIHNlY29uZHMgdG8gY2FsbCBzaWxlbnRSZW5ld0hlYXJ0QmVhdENoZWNrXHJcbiAgICAgICAgICAgIEFmdGVyd2FyZHM6IFJ1biB0aGlzIGNoZWNrIGluIGEgNSBzZWNvbmQgaW50ZXJ2YWwgb25seSBBRlRFUiB0aGUgcHJldmlvdXMgb3BlcmF0aW9uIGVuZHMuXHJcbiAgICAgICAgICovXHJcbiAgICAgICAgY29uc3Qgc2lsZW50UmVuZXdIZWFydEJlYXRDaGVjayA9ICgpID0+IHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKFxyXG4gICAgICAgICAgICAgICAgJ3NpbGVudFJlbmV3SGVhcnRCZWF0Q2hlY2tcXHJcXG4nICtcclxuICAgICAgICAgICAgICAgICAgICBgXFx0c2lsZW50UmVuZXdSdW5uaW5nOiAke3RoaXMub2lkY1NlY3VyaXR5Q29tbW9uLnNpbGVudFJlbmV3UnVubmluZyA9PT0gJ3J1bm5pbmcnfVxcclxcbmAgK1xyXG4gICAgICAgICAgICAgICAgICAgIGBcXHRpZFRva2VuOiAkeyEhdGhpcy5nZXRJZFRva2VuKCl9XFxyXFxuYCArXHJcbiAgICAgICAgICAgICAgICAgICAgYFxcdF91c2VyRGF0YS52YWx1ZTogJHshIXRoaXMuX3VzZXJEYXRhLnZhbHVlfWBcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgaWYgKHRoaXMuX3VzZXJEYXRhLnZhbHVlICYmIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLnNpbGVudFJlbmV3UnVubmluZyAhPT0gJ3J1bm5pbmcnICYmIHRoaXMuZ2V0SWRUb2tlbigpKSB7XHJcbiAgICAgICAgICAgICAgICBpZiAoXHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlWYWxpZGF0aW9uLmlzVG9rZW5FeHBpcmVkKHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmlkVG9rZW4sIHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uc2lsZW50X3JlbmV3X29mZnNldF9pbl9zZWNvbmRzKVxyXG4gICAgICAgICAgICAgICAgKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdJc0F1dGhvcml6ZWQ6IGlkX3Rva2VuIGlzVG9rZW5FeHBpcmVkLCBzdGFydCBzaWxlbnQgcmVuZXcgaWYgYWN0aXZlJyk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLmF1dGhDb25maWd1cmF0aW9uLnNpbGVudF9yZW5ldykge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnJlZnJlc2hTZXNzaW9uKCkuc3Vic2NyaWJlKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgKCkgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3NjaGVkdWxlZEhlYXJ0QmVhdCA9IHNldFRpbWVvdXQoc2lsZW50UmVuZXdIZWFydEJlYXRDaGVjaywgMzAwMCk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9LFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgKGVycjogYW55KSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0Vycm9yKCdFcnJvcjogJyArIGVycik7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fc2NoZWR1bGVkSGVhcnRCZWF0ID0gc2V0VGltZW91dChzaWxlbnRSZW5ld0hlYXJ0QmVhdENoZWNrLCAzMDAwKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgLyogSW4gdGhpcyBzaXR1YXRpb24sIHdlIHNjaGVkdWxlIGEgaGVhdGJlYXQgY2hlY2sgb25seSB3aGVuIHNpbGVudFJlbmV3IGlzIGZpbmlzaGVkLlxyXG4gICAgICAgICAgICAgICAgICAgICAgICBXZSBkb24ndCB3YW50IHRvIHNjaGVkdWxlIGFub3RoZXIgY2hlY2sgc28gd2UgaGF2ZSB0byByZXR1cm4gaGVyZSAqL1xyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yZXNldEF1dGhvcml6YXRpb25EYXRhKGZhbHNlKTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIC8qIERlbGF5IDMgc2Vjb25kcyBhbmQgZG8gdGhlIG5leHQgY2hlY2sgKi9cclxuICAgICAgICAgICAgdGhpcy5fc2NoZWR1bGVkSGVhcnRCZWF0ID0gc2V0VGltZW91dChzaWxlbnRSZW5ld0hlYXJ0QmVhdENoZWNrLCAzMDAwKTtcclxuICAgICAgICB9O1xyXG5cclxuICAgICAgICB0aGlzLnpvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xyXG4gICAgICAgICAgICAvKiBJbml0aWFsIGhlYXJ0YmVhdCBjaGVjayAqL1xyXG4gICAgICAgICAgICB0aGlzLl9zY2hlZHVsZWRIZWFydEJlYXQgPSBzZXRUaW1lb3V0KHNpbGVudFJlbmV3SGVhcnRCZWF0Q2hlY2ssIDEwMDAwKTtcclxuICAgICAgICB9KTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHNpbGVudFJlbmV3RXZlbnRIYW5kbGVyKGU6IEN1c3RvbUV2ZW50KSB7XHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdzaWxlbnRSZW5ld0V2ZW50SGFuZGxlcicpO1xyXG5cclxuICAgICAgICBpZiAodGhpcy5hdXRoQ29uZmlndXJhdGlvbi5yZXNwb25zZV90eXBlID09PSAnY29kZScpIHtcclxuXHJcbiAgICAgICAgICAgIGNvbnN0IHVybFBhcnRzID0gZS5kZXRhaWwudG9TdHJpbmcoKS5zcGxpdCgnPycpO1xyXG4gICAgICAgICAgICBjb25zdCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcyh7XHJcbiAgICAgICAgICAgICAgICBmcm9tU3RyaW5nOiB1cmxQYXJ0c1sxXVxyXG4gICAgICAgICAgICB9KTtcclxuICAgICAgICAgICAgY29uc3QgY29kZSA9IHBhcmFtcy5nZXQoJ2NvZGUnKTtcclxuICAgICAgICAgICAgY29uc3Qgc3RhdGUgPSBwYXJhbXMuZ2V0KCdzdGF0ZScpO1xyXG4gICAgICAgICAgICBjb25zdCBzZXNzaW9uX3N0YXRlID0gcGFyYW1zLmdldCgnc2Vzc2lvbl9zdGF0ZScpO1xyXG4gICAgICAgICAgICBjb25zdCBlcnJvciA9IHBhcmFtcy5nZXQoJ2Vycm9yJyk7XHJcbiAgICAgICAgICAgIGlmIChjb2RlICYmIHN0YXRlKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLnJlcXVlc3RUb2tlbnNXaXRoQ29kZVByb2NlZHVyZShjb2RlLCBzdGF0ZSwgc2Vzc2lvbl9zdGF0ZSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgaWYgKGVycm9yKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLl9vbkF1dGhvcml6YXRpb25SZXN1bHQubmV4dChuZXcgQXV0aG9yaXphdGlvblJlc3VsdChBdXRob3JpemF0aW9uU3RhdGUudW5hdXRob3JpemVkLCBWYWxpZGF0aW9uUmVzdWx0LkxvZ2luUmVxdWlyZWQpKTtcclxuICAgICAgICAgICAgICAgIHRoaXMucmVzZXRBdXRob3JpemF0aW9uRGF0YShmYWxzZSk7XHJcbiAgICAgICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoTm9uY2UgPSAnJztcclxuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZyhlLmRldGFpbC50b1N0cmluZygpKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAvLyBJbXBsaWNpdEZsb3dcclxuICAgICAgICAgICAgdGhpcy5hdXRob3JpemVkSW1wbGljaXRGbG93Q2FsbGJhY2soZS5kZXRhaWwpO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxufVxyXG4iXX0=