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
export class OidcSecurityService {
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
        return observableThrowError(errMsg);
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1hdXRoLW9pZGMtY2xpZW50LyIsInNvdXJjZXMiOlsibGliL3NlcnZpY2VzL29pZGMuc2VjdXJpdHkuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxVQUFVLEVBQUUsV0FBVyxFQUFFLE1BQU0sc0JBQXNCLENBQUM7QUFDM0UsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDbkQsT0FBTyxFQUFFLE1BQU0sRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQ3pDLE9BQU8sRUFBRSxlQUFlLEVBQUUsSUFBSSxFQUFFLFVBQVUsRUFBRSxPQUFPLEVBQUUsVUFBVSxJQUFJLG9CQUFvQixFQUFFLEtBQUssRUFBRSxFQUFFLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFDakgsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUUsU0FBUyxFQUFFLFdBQVcsRUFBRSxJQUFJLEVBQUUsR0FBRyxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFDL0csT0FBTyxFQUFFLGVBQWUsRUFBRSxNQUFNLG9DQUFvQyxDQUFDO0FBRXJFLE9BQU8sRUFBRSxtQkFBbUIsRUFBRSxNQUFNLGdDQUFnQyxDQUFDO0FBQ3JFLE9BQU8sRUFBRSxrQkFBa0IsRUFBRSxNQUFNLG9DQUFvQyxDQUFDO0FBRXhFLE9BQU8sRUFBRSxtQkFBbUIsRUFBRSxNQUFNLHVDQUF1QyxDQUFDO0FBQzVFLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLGtDQUFrQyxDQUFDO0FBQ3BFLE9BQU8sRUFBRSxpQkFBaUIsRUFBbUMsTUFBTSwrQkFBK0IsQ0FBQztBQUNuRyxPQUFPLEVBQUUsc0JBQXNCLEVBQUUsTUFBTSwwQ0FBMEMsQ0FBQztBQUNsRixPQUFPLEVBQUUsa0JBQWtC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QXNCO1lBRHRCLGlCQUFpQjtZQVZqQixNQUFNO1lBY04sd0JBQXdCO1lBRXhCLHVCQUF1QjtZQUN2Qix1QkFBdUI7WUFGdkIsa0JBQWtCO1lBR2xCLHNCQUFzQjtZQU50QixrQkFBa0I7WUFDbEIsYUFBYTtZQWRELE1BQU07WUFETixVQUFVOzs7Ozs7O0lBeUIzQiw2Q0FBZ0Q7Ozs7O0lBQ2hELHFEQUF3RDs7Ozs7SUFDeEQscURBQW9FOztJQWtCcEUsa0RBQTRCOztJQUM1QiwwQ0FBb0I7Ozs7O0lBRXBCLDZDQUE2RDs7Ozs7SUFFN0QscURBQW1FOzs7OztJQUNuRSw0Q0FBNEQ7Ozs7O0lBQzVELG9EQUFtRDs7Ozs7SUFFbkQsd0NBQWlEOzs7OztJQUNqRCwyREFBNkM7Ozs7O0lBQzdDLHdEQUEwQzs7Ozs7SUFDMUMsa0RBQWlDOzs7OztJQUNqQyxvREFBbUM7Ozs7O0lBRy9CLDhDQUF3Qzs7Ozs7SUFDeEMscURBQXNEOzs7OztJQUN0RCxnREFBNEM7Ozs7O0lBQzVDLHFDQUFzQjs7Ozs7SUFDdEIsdURBQTBEOzs7OztJQUMxRCxzREFBd0Q7Ozs7O0lBQ3hELHNEQUF3RDs7Ozs7SUFDeEQsaURBQThDOzs7OztJQUM5QyxxREFBc0Q7Ozs7O0lBQ3RELGlEQUE4Qzs7Ozs7SUFDOUMsNENBQW9DOzs7OztJQUNwQyxtQ0FBb0I7Ozs7O0lBQ3BCLHlDQUF1QyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEh0dHBQYXJhbXMsIEh0dHBDbGllbnQsIEh0dHBIZWFkZXJzIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xyXG5pbXBvcnQgeyBJbmplY3RhYmxlLCBOZ1pvbmUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcclxuaW1wb3J0IHsgUm91dGVyIH0gZnJvbSAnQGFuZ3VsYXIvcm91dGVyJztcclxuaW1wb3J0IHsgQmVoYXZpb3JTdWJqZWN0LCBmcm9tLCBPYnNlcnZhYmxlLCBTdWJqZWN0LCB0aHJvd0Vycm9yIGFzIG9ic2VydmFibGVUaHJvd0Vycm9yLCB0aW1lciwgb2YgfSBmcm9tICdyeGpzJztcclxuaW1wb3J0IHsgY2F0Y2hFcnJvciwgZmlsdGVyLCBtYXAsIHJhY2UsIHNoYXJlUmVwbGF5LCBzd2l0Y2hNYXAsIHN3aXRjaE1hcFRvLCB0YWtlLCB0YXAgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XHJcbmltcG9ydCB7IE9pZGNEYXRhU2VydmljZSB9IGZyb20gJy4uL2RhdGEtc2VydmljZXMvb2lkYy1kYXRhLnNlcnZpY2UnO1xyXG5pbXBvcnQgeyBBdXRoV2VsbEtub3duRW5kcG9pbnRzIH0gZnJvbSAnLi4vbW9kZWxzL2F1dGgud2VsbC1rbm93bi1lbmRwb2ludHMnO1xyXG5pbXBvcnQgeyBBdXRob3JpemF0aW9uUmVzdWx0IH0gZnJvbSAnLi4vbW9kZWxzL2F1dGhvcml6YXRpb24tcmVzdWx0JztcclxuaW1wb3J0IHsgQXV0aG9yaXphdGlvblN0YXRlIH0gZnJvbSAnLi4vbW9kZWxzL2F1dGhvcml6YXRpb24tc3RhdGUuZW51bSc7XHJcbmltcG9ydCB7IEp3dEtleXMgfSBmcm9tICcuLi9tb2RlbHMvand0a2V5cyc7XHJcbmltcG9ydCB7IFZhbGlkYXRlU3RhdGVSZXN1bHQgfSBmcm9tICcuLi9tb2RlbHMvdmFsaWRhdGUtc3RhdGUtcmVzdWx0Lm1vZGVsJztcclxuaW1wb3J0IHsgVmFsaWRhdGlvblJlc3VsdCB9IGZyb20gJy4uL21vZGVscy92YWxpZGF0aW9uLXJlc3VsdC5lbnVtJztcclxuaW1wb3J0IHsgQXV0aENvbmZpZ3VyYXRpb24sIE9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi9tb2R1bGVzL2F1dGguY29uZmlndXJhdGlvbic7XHJcbmltcG9ydCB7IFN0YXRlVmFsaWRhdGlvblNlcnZpY2UgfSBmcm9tICcuL29pZGMtc2VjdXJpdHktc3RhdGUtdmFsaWRhdGlvbi5zZXJ2aWNlJztcclxuaW1wb3J0IHsgVG9rZW5IZWxwZXJTZXJ2aWNlIH0gZnJvbSAnLi9vaWRjLXRva2VuLWhlbHBlci5zZXJ2aWNlJztcclxuaW1wb3J0IHsgTG9nZ2VyU2VydmljZSB9IGZyb20gJy4vb2lkYy5sb2dnZXIuc2VydmljZSc7XHJcbmltcG9ydCB7IE9pZGNTZWN1cml0eUNoZWNrU2Vzc2lvbiB9IGZyb20gJy4vb2lkYy5zZWN1cml0eS5jaGVjay1zZXNzaW9uJztcclxuaW1wb3J0IHsgT2lkY1NlY3VyaXR5Q29tbW9uIH0gZnJvbSAnLi9vaWRjLnNlY3VyaXR5LmNvbW1vbic7XHJcbmltcG9ydCB7IE9pZGNTZWN1cml0eVNpbGVudFJlbmV3IH0gZnJvbSAnLi9vaWRjLnNlY3VyaXR5LnNpbGVudC1yZW5ldyc7XHJcbmltcG9ydCB7IE9pZGNTZWN1cml0eVVzZXJTZXJ2aWNlIH0gZnJvbSAnLi9vaWRjLnNlY3VyaXR5LnVzZXItc2VydmljZSc7XHJcbmltcG9ydCB7IE9pZGNTZWN1cml0eVZhbGlkYXRpb24gfSBmcm9tICcuL29pZGMuc2VjdXJpdHkudmFsaWRhdGlvbic7XHJcbmltcG9ydCB7IFVyaUVuY29kZXIgfSBmcm9tICcuL3VyaS1lbmNvZGVyJztcclxuXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGNsYXNzIE9pZGNTZWN1cml0eVNlcnZpY2Uge1xyXG4gICAgcHJpdmF0ZSBfb25Nb2R1bGVTZXR1cCA9IG5ldyBTdWJqZWN0PGJvb2xlYW4+KCk7XHJcbiAgICBwcml2YXRlIF9vbkNoZWNrU2Vzc2lvbkNoYW5nZWQgPSBuZXcgU3ViamVjdDxib29sZWFuPigpO1xyXG4gICAgcHJpdmF0ZSBfb25BdXRob3JpemF0aW9uUmVzdWx0ID0gbmV3IFN1YmplY3Q8QXV0aG9yaXphdGlvblJlc3VsdD4oKTtcclxuXHJcbiAgICBwdWJsaWMgZ2V0IG9uTW9kdWxlU2V0dXAoKTogT2JzZXJ2YWJsZTxib29sZWFuPiB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuX29uTW9kdWxlU2V0dXAuYXNPYnNlcnZhYmxlKCk7XHJcbiAgICB9XHJcblxyXG4gICAgcHVibGljIGdldCBvbkF1dGhvcml6YXRpb25SZXN1bHQoKTogT2JzZXJ2YWJsZTxBdXRob3JpemF0aW9uUmVzdWx0PiB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuX29uQXV0aG9yaXphdGlvblJlc3VsdC5hc09ic2VydmFibGUoKTtcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgZ2V0IG9uQ2hlY2tTZXNzaW9uQ2hhbmdlZCgpOiBPYnNlcnZhYmxlPGJvb2xlYW4+IHtcclxuICAgICAgICByZXR1cm4gdGhpcy5fb25DaGVja1Nlc3Npb25DaGFuZ2VkLmFzT2JzZXJ2YWJsZSgpO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyBnZXQgb25Db25maWd1cmF0aW9uQ2hhbmdlKCk6IE9ic2VydmFibGU8T3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbj4ge1xyXG4gICAgICAgIHJldHVybiB0aGlzLmF1dGhDb25maWd1cmF0aW9uLm9uQ29uZmlndXJhdGlvbkNoYW5nZTtcclxuICAgIH1cclxuXHJcbiAgICBjaGVja1Nlc3Npb25DaGFuZ2VkID0gZmFsc2U7XHJcbiAgICBtb2R1bGVTZXR1cCA9IGZhbHNlO1xyXG5cclxuICAgIHByaXZhdGUgX2lzTW9kdWxlU2V0dXAgPSBuZXcgQmVoYXZpb3JTdWJqZWN0PGJvb2xlYW4+KGZhbHNlKTtcclxuXHJcbiAgICBwcml2YXRlIGF1dGhXZWxsS25vd25FbmRwb2ludHM6IEF1dGhXZWxsS25vd25FbmRwb2ludHMgfCB1bmRlZmluZWQ7XHJcbiAgICBwcml2YXRlIF9pc0F1dGhvcml6ZWQgPSBuZXcgQmVoYXZpb3JTdWJqZWN0PGJvb2xlYW4+KGZhbHNlKTtcclxuICAgIHByaXZhdGUgX2lzU2V0dXBBbmRBdXRob3JpemVkOiBPYnNlcnZhYmxlPGJvb2xlYW4+O1xyXG5cclxuICAgIHByaXZhdGUgX3VzZXJEYXRhID0gbmV3IEJlaGF2aW9yU3ViamVjdDxhbnk+KCcnKTtcclxuICAgIHByaXZhdGUgYXV0aFdlbGxLbm93bkVuZHBvaW50c0xvYWRlZCA9IGZhbHNlO1xyXG4gICAgcHJpdmF0ZSBydW5Ub2tlblZhbGlkYXRpb25SdW5uaW5nID0gZmFsc2U7XHJcbiAgICBwcml2YXRlIF9zY2hlZHVsZWRIZWFydEJlYXQ6IGFueTtcclxuICAgIHByaXZhdGUgYm91bmRTaWxlbnRSZW5ld0V2ZW50OiBhbnk7XHJcblxyXG4gICAgY29uc3RydWN0b3IoXHJcbiAgICAgICAgcHJpdmF0ZSBvaWRjRGF0YVNlcnZpY2U6IE9pZGNEYXRhU2VydmljZSxcclxuICAgICAgICBwcml2YXRlIHN0YXRlVmFsaWRhdGlvblNlcnZpY2U6IFN0YXRlVmFsaWRhdGlvblNlcnZpY2UsXHJcbiAgICAgICAgcHJpdmF0ZSBhdXRoQ29uZmlndXJhdGlvbjogQXV0aENvbmZpZ3VyYXRpb24sXHJcbiAgICAgICAgcHJpdmF0ZSByb3V0ZXI6IFJvdXRlcixcclxuICAgICAgICBwcml2YXRlIG9pZGNTZWN1cml0eUNoZWNrU2Vzc2lvbjogT2lkY1NlY3VyaXR5Q2hlY2tTZXNzaW9uLFxyXG4gICAgICAgIHByaXZhdGUgb2lkY1NlY3VyaXR5U2lsZW50UmVuZXc6IE9pZGNTZWN1cml0eVNpbGVudFJlbmV3LFxyXG4gICAgICAgIHByaXZhdGUgb2lkY1NlY3VyaXR5VXNlclNlcnZpY2U6IE9pZGNTZWN1cml0eVVzZXJTZXJ2aWNlLFxyXG4gICAgICAgIHByaXZhdGUgb2lkY1NlY3VyaXR5Q29tbW9uOiBPaWRjU2VjdXJpdHlDb21tb24sXHJcbiAgICAgICAgcHJpdmF0ZSBvaWRjU2VjdXJpdHlWYWxpZGF0aW9uOiBPaWRjU2VjdXJpdHlWYWxpZGF0aW9uLFxyXG4gICAgICAgIHByaXZhdGUgdG9rZW5IZWxwZXJTZXJ2aWNlOiBUb2tlbkhlbHBlclNlcnZpY2UsXHJcbiAgICAgICAgcHJpdmF0ZSBsb2dnZXJTZXJ2aWNlOiBMb2dnZXJTZXJ2aWNlLFxyXG4gICAgICAgIHByaXZhdGUgem9uZTogTmdab25lLFxyXG4gICAgICAgIHByaXZhdGUgcmVhZG9ubHkgaHR0cENsaWVudDogSHR0cENsaWVudFxyXG4gICAgKSB7XHJcbiAgICAgICAgdGhpcy5vbk1vZHVsZVNldHVwLnBpcGUodGFrZSgxKSkuc3Vic2NyaWJlKCgpID0+IHtcclxuICAgICAgICAgICAgdGhpcy5tb2R1bGVTZXR1cCA9IHRydWU7XHJcbiAgICAgICAgICAgIHRoaXMuX2lzTW9kdWxlU2V0dXAubmV4dCh0cnVlKTtcclxuICAgICAgICB9KTtcclxuXHJcbiAgICAgICAgdGhpcy5faXNTZXR1cEFuZEF1dGhvcml6ZWQgPSB0aGlzLl9pc01vZHVsZVNldHVwLnBpcGUoXHJcbiAgICAgICAgICAgIGZpbHRlcigoaXNNb2R1bGVTZXR1cDogYm9vbGVhbikgPT4gaXNNb2R1bGVTZXR1cCksXHJcbiAgICAgICAgICAgIHN3aXRjaE1hcCgoKSA9PiB7XHJcbiAgICAgICAgICAgICAgICBpZiAoIXRoaXMuYXV0aENvbmZpZ3VyYXRpb24uc2lsZW50X3JlbmV3KSB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZyb20oW3RydWVdKS5waXBlKHRhcCgoKSA9PiB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoYElzQXV0aG9yaXplZFJhY2U6IFNpbGVudCBSZW5ldyBOb3QgQWN0aXZlLiBFbWl0dGluZy5gKSkpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIGNvbnN0IHJhY2UkID0gdGhpcy5faXNBdXRob3JpemVkLmFzT2JzZXJ2YWJsZSgpLnBpcGUoXHJcbiAgICAgICAgICAgICAgICAgICAgZmlsdGVyKChpc0F1dGhvcml6ZWQ6IGJvb2xlYW4pID0+IGlzQXV0aG9yaXplZCksXHJcbiAgICAgICAgICAgICAgICAgICAgdGFrZSgxKSxcclxuICAgICAgICAgICAgICAgICAgICB0YXAoKCkgPT4gdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdJc0F1dGhvcml6ZWRSYWNlOiBFeGlzdGluZyB0b2tlbiBpcyBzdGlsbCBhdXRob3JpemVkLicpKSxcclxuICAgICAgICAgICAgICAgICAgICByYWNlKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9vbkF1dGhvcml6YXRpb25SZXN1bHQucGlwZShcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRha2UoMSksXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0YXAoKCkgPT4gdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdJc0F1dGhvcml6ZWRSYWNlOiBTaWxlbnQgUmVuZXcgUmVmcmVzaCBTZXNzaW9uIENvbXBsZXRlJykpLFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbWFwKCgpID0+IHRydWUpXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICksXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVyKDUwMDApLnBpcGUoXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBiYWNrdXAsIGlmIG5vdGhpbmcgaGFwcGVucyBhZnRlciA1IHNlY29uZHMgc3RvcCB3YWl0aW5nIGFuZCBlbWl0XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0YXAoKCkgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucmVzZXRBdXRob3JpemF0aW9uRGF0YShmYWxzZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aE5vbmNlID0gJyc7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ0lzQXV0aG9yaXplZFJhY2U6IFRpbWVvdXQgcmVhY2hlZC4gRW1pdHRpbmcuJyk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KSxcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1hcCgoKSA9PiB0cnVlKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgKTtcclxuXHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ1NpbGVudCBSZW5ldyBpcyBhY3RpdmUsIGNoZWNrIGlmIHRva2VuIGluIHN0b3JhZ2UgaXMgYWN0aXZlJyk7XHJcbiAgICAgICAgICAgICAgICBpZiAodGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aE5vbmNlID09PSAnJyB8fCB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoTm9uY2UgPT09IHVuZGVmaW5lZCkge1xyXG4gICAgICAgICAgICAgICAgICAgIC8vIGxvZ2luIG5vdCBydW5uaW5nLCBvciBhIHNlY29uZCBzaWxlbnQgcmVuZXcsIHVzZXIgbXVzdCBsb2dpbiBmaXJzdCBiZWZvcmUgdGhpcyB3aWxsIHdvcmsuXHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdTaWxlbnQgUmVuZXcgb3IgbG9naW4gbm90IHJ1bm5pbmcsIHRyeSB0byByZWZyZXNoIHRoZSBzZXNzaW9uJyk7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5yZWZyZXNoU2Vzc2lvbigpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIHJldHVybiByYWNlJDtcclxuICAgICAgICAgICAgfSksXHJcbiAgICAgICAgICAgIHRhcCgoKSA9PiB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ0lzQXV0aG9yaXplZFJhY2U6IENvbXBsZXRlZCcpKSxcclxuICAgICAgICAgICAgc3dpdGNoTWFwVG8odGhpcy5faXNBdXRob3JpemVkLmFzT2JzZXJ2YWJsZSgpKSxcclxuICAgICAgICAgICAgdGFwKChpc0F1dGhvcml6ZWQ6IGJvb2xlYW4pID0+IHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZyhgZ2V0SXNBdXRob3JpemVkOiAke2lzQXV0aG9yaXplZH1gKSksXHJcbiAgICAgICAgICAgIHNoYXJlUmVwbGF5KDEpXHJcbiAgICAgICAgKTtcclxuXHJcbiAgICAgICAgdGhpcy5faXNTZXR1cEFuZEF1dGhvcml6ZWQucGlwZShmaWx0ZXIoKCkgPT4gdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zdGFydF9jaGVja3Nlc3Npb24pKS5zdWJzY3JpYmUoaXNTZXR1cEFuZEF1dGhvcml6ZWQgPT4ge1xyXG4gICAgICAgICAgICBpZiAoaXNTZXR1cEFuZEF1dGhvcml6ZWQpIHtcclxuICAgICAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q2hlY2tTZXNzaW9uLnN0YXJ0Q2hlY2tpbmdTZXNzaW9uKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uY2xpZW50X2lkKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q2hlY2tTZXNzaW9uLnN0b3BDaGVja2luZ1Nlc3Npb24oKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH0pO1xyXG4gICAgfVxyXG5cclxuICAgIHNldHVwTW9kdWxlKG9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb246IE9wZW5JREltcGxpY2l0Rmxvd0NvbmZpZ3VyYXRpb24sIGF1dGhXZWxsS25vd25FbmRwb2ludHM6IEF1dGhXZWxsS25vd25FbmRwb2ludHMpOiB2b2lkIHtcclxuICAgICAgICB0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMgPSBPYmplY3QuYXNzaWduKHt9LCBhdXRoV2VsbEtub3duRW5kcG9pbnRzKTtcclxuICAgICAgICB0aGlzLmF1dGhDb25maWd1cmF0aW9uLmluaXQob3BlbklESW1wbGljaXRGbG93Q29uZmlndXJhdGlvbik7XHJcbiAgICAgICAgdGhpcy5zdGF0ZVZhbGlkYXRpb25TZXJ2aWNlLnNldHVwTW9kdWxlKGF1dGhXZWxsS25vd25FbmRwb2ludHMpO1xyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q2hlY2tTZXNzaW9uLnNldHVwTW9kdWxlKGF1dGhXZWxsS25vd25FbmRwb2ludHMpO1xyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5VXNlclNlcnZpY2Uuc2V0dXBNb2R1bGUoYXV0aFdlbGxLbm93bkVuZHBvaW50cyk7XHJcblxyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q2hlY2tTZXNzaW9uLm9uQ2hlY2tTZXNzaW9uQ2hhbmdlZC5zdWJzY3JpYmUoKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ29uQ2hlY2tTZXNzaW9uQ2hhbmdlZCcpO1xyXG4gICAgICAgICAgICB0aGlzLmNoZWNrU2Vzc2lvbkNoYW5nZWQgPSB0cnVlO1xyXG4gICAgICAgICAgICB0aGlzLl9vbkNoZWNrU2Vzc2lvbkNoYW5nZWQubmV4dCh0aGlzLmNoZWNrU2Vzc2lvbkNoYW5nZWQpO1xyXG4gICAgICAgIH0pO1xyXG5cclxuICAgICAgICBjb25zdCB1c2VyRGF0YSA9IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLnVzZXJEYXRhO1xyXG4gICAgICAgIGlmICh1c2VyRGF0YSkge1xyXG4gICAgICAgICAgICB0aGlzLnNldFVzZXJEYXRhKHVzZXJEYXRhKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IGlzQXV0aG9yaXplZCA9IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmlzQXV0aG9yaXplZDtcclxuICAgICAgICBpZiAoaXNBdXRob3JpemVkKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnSXNBdXRob3JpemVkIHNldHVwIG1vZHVsZScpO1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcodGhpcy5vaWRjU2VjdXJpdHlDb21tb24uaWRUb2tlbik7XHJcbiAgICAgICAgICAgIGlmICh0aGlzLm9pZGNTZWN1cml0eVZhbGlkYXRpb24uaXNUb2tlbkV4cGlyZWQodGhpcy5vaWRjU2VjdXJpdHlDb21tb24uaWRUb2tlbiwgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zaWxlbnRfcmVuZXdfb2Zmc2V0X2luX3NlY29uZHMpKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ0lzQXV0aG9yaXplZCBzZXR1cCBtb2R1bGU7IGlkX3Rva2VuIGlzVG9rZW5FeHBpcmVkJyk7XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ0lzQXV0aG9yaXplZCBzZXR1cCBtb2R1bGU7IGlkX3Rva2VuIGlzIHZhbGlkJyk7XHJcbiAgICAgICAgICAgICAgICB0aGlzLnNldElzQXV0aG9yaXplZChpc0F1dGhvcml6ZWQpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHRoaXMucnVuVG9rZW5WYWxpZGF0aW9uKCk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ1NUUyBzZXJ2ZXI6ICcgKyB0aGlzLmF1dGhDb25maWd1cmF0aW9uLnN0c1NlcnZlcik7XHJcblxyXG4gICAgICAgIHRoaXMuX29uTW9kdWxlU2V0dXAubmV4dCgpO1xyXG5cclxuICAgICAgICBpZiAodGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zaWxlbnRfcmVuZXcpIHtcclxuICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlTaWxlbnRSZW5ldy5pbml0UmVuZXcoKTtcclxuXHJcbiAgICAgICAgICAgIC8vIFN1cHBvcnQgYXV0aG9yaXphdGlvbiB2aWEgRE9NIGV2ZW50cy5cclxuICAgICAgICAgICAgLy8gRGVyZWdpc3RlciBpZiBPaWRjU2VjdXJpdHlTZXJ2aWNlLnNldHVwTW9kdWxlIGlzIGNhbGxlZCBhZ2FpbiBieSBhbnkgaW5zdGFuY2UuXHJcbiAgICAgICAgICAgIC8vICAgICAgV2Ugb25seSBldmVyIHdhbnQgdGhlIGxhdGVzdCBzZXR1cCBzZXJ2aWNlIHRvIGJlIHJlYWN0aW5nIHRvIHRoaXMgZXZlbnQuXHJcbiAgICAgICAgICAgIHRoaXMuYm91bmRTaWxlbnRSZW5ld0V2ZW50ID0gdGhpcy5zaWxlbnRSZW5ld0V2ZW50SGFuZGxlci5iaW5kKHRoaXMpO1xyXG5cclxuICAgICAgICAgICAgY29uc3QgaW5zdGFuY2VJZCA9IE1hdGgucmFuZG9tKCk7XHJcblxyXG4gICAgICAgICAgICBjb25zdCBib3VuZFNpbGVudFJlbmV3SW5pdEV2ZW50ID0gKChlOiBDdXN0b21FdmVudCkgPT4ge1xyXG4gICAgICAgICAgICAgICAgaWYgKGUuZGV0YWlsICE9PSBpbnN0YW5jZUlkKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ29pZGMtc2lsZW50LXJlbmV3LW1lc3NhZ2UnLCB0aGlzLmJvdW5kU2lsZW50UmVuZXdFdmVudCk7XHJcbiAgICAgICAgICAgICAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ29pZGMtc2lsZW50LXJlbmV3LWluaXQnLCBib3VuZFNpbGVudFJlbmV3SW5pdEV2ZW50KTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfSkuYmluZCh0aGlzKTtcclxuXHJcbiAgICAgICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdvaWRjLXNpbGVudC1yZW5ldy1pbml0JywgYm91bmRTaWxlbnRSZW5ld0luaXRFdmVudCwgZmFsc2UpO1xyXG4gICAgICAgICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignb2lkYy1zaWxlbnQtcmVuZXctbWVzc2FnZScsIHRoaXMuYm91bmRTaWxlbnRSZW5ld0V2ZW50LCBmYWxzZSk7XHJcblxyXG4gICAgICAgICAgICB3aW5kb3cuZGlzcGF0Y2hFdmVudChcclxuICAgICAgICAgICAgICAgIG5ldyBDdXN0b21FdmVudCgnb2lkYy1zaWxlbnQtcmVuZXctaW5pdCcsIHtcclxuICAgICAgICAgICAgICAgICAgICBkZXRhaWw6IGluc3RhbmNlSWQsXHJcbiAgICAgICAgICAgICAgICB9KVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBnZXRVc2VyRGF0YSgpOiBPYnNlcnZhYmxlPGFueT4ge1xyXG4gICAgICAgIHJldHVybiB0aGlzLl91c2VyRGF0YS5hc09ic2VydmFibGUoKTtcclxuICAgIH1cclxuXHJcbiAgICBnZXRJc01vZHVsZVNldHVwKCk6IE9ic2VydmFibGU8Ym9vbGVhbj4ge1xyXG4gICAgICAgIHJldHVybiB0aGlzLl9pc01vZHVsZVNldHVwLmFzT2JzZXJ2YWJsZSgpO1xyXG4gICAgfVxyXG5cclxuICAgIGdldElzQXV0aG9yaXplZCgpOiBPYnNlcnZhYmxlPGJvb2xlYW4+IHtcclxuICAgICAgICByZXR1cm4gdGhpcy5faXNTZXR1cEFuZEF1dGhvcml6ZWQ7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0VG9rZW4oKTogc3RyaW5nIHtcclxuICAgICAgICBpZiAoIXRoaXMuX2lzQXV0aG9yaXplZC5nZXRWYWx1ZSgpKSB7XHJcbiAgICAgICAgICAgIHJldHVybiAnJztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IHRva2VuID0gdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uZ2V0QWNjZXNzVG9rZW4oKTtcclxuICAgICAgICByZXR1cm4gZGVjb2RlVVJJQ29tcG9uZW50KHRva2VuKTtcclxuICAgIH1cclxuXHJcbiAgICBnZXRJZFRva2VuKCk6IHN0cmluZyB7XHJcbiAgICAgICAgaWYgKCF0aGlzLl9pc0F1dGhvcml6ZWQuZ2V0VmFsdWUoKSkge1xyXG4gICAgICAgICAgICByZXR1cm4gJyc7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCB0b2tlbiA9IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmdldElkVG9rZW4oKTtcclxuICAgICAgICByZXR1cm4gZGVjb2RlVVJJQ29tcG9uZW50KHRva2VuKTtcclxuICAgIH1cclxuXHJcbiAgICBnZXRQYXlsb2FkRnJvbUlkVG9rZW4oZW5jb2RlID0gZmFsc2UpOiBhbnkge1xyXG4gICAgICAgIGNvbnN0IHRva2VuID0gdGhpcy5nZXRJZFRva2VuKCk7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMudG9rZW5IZWxwZXJTZXJ2aWNlLmdldFBheWxvYWRGcm9tVG9rZW4odG9rZW4sIGVuY29kZSk7XHJcbiAgICB9XHJcblxyXG4gICAgc2V0U3RhdGUoc3RhdGU6IHN0cmluZyk6IHZvaWQge1xyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhTdGF0ZUNvbnRyb2wgPSBzdGF0ZTtcclxuICAgIH1cclxuXHJcbiAgICBnZXRTdGF0ZSgpOiBzdHJpbmcge1xyXG4gICAgICAgIHJldHVybiB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoU3RhdGVDb250cm9sO1xyXG4gICAgfVxyXG5cclxuICAgIHNldEN1c3RvbVJlcXVlc3RQYXJhbWV0ZXJzKHBhcmFtczogeyBba2V5OiBzdHJpbmddOiBzdHJpbmcgfCBudW1iZXIgfCBib29sZWFuIH0pIHtcclxuICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5jdXN0b21SZXF1ZXN0UGFyYW1zID0gcGFyYW1zO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIENvZGUgRmxvdyB3aXRoIFBDS0Ugb3IgSW1wbGljaXQgRmxvd1xyXG4gICAgYXV0aG9yaXplKHVybEhhbmRsZXI/OiAodXJsOiBzdHJpbmcpID0+IGFueSkge1xyXG4gICAgICAgIGlmICh0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMpIHtcclxuICAgICAgICAgICAgdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzTG9hZGVkID0gdHJ1ZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmICghdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzTG9hZGVkKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dFcnJvcignV2VsbCBrbm93biBlbmRwb2ludHMgbXVzdCBiZSBsb2FkZWQgYmVmb3JlIHVzZXIgY2FuIGxvZ2luIScpO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoIXRoaXMub2lkY1NlY3VyaXR5VmFsaWRhdGlvbi5jb25maWdfdmFsaWRhdGVfcmVzcG9uc2VfdHlwZSh0aGlzLmF1dGhDb25maWd1cmF0aW9uLnJlc3BvbnNlX3R5cGUpKSB7XHJcbiAgICAgICAgICAgIC8vIGludmFsaWQgcmVzcG9uc2VfdHlwZVxyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICB0aGlzLnJlc2V0QXV0aG9yaXphdGlvbkRhdGEoZmFsc2UpO1xyXG5cclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ0JFR0lOIEF1dGhvcml6ZSBDb2RlIEZsb3csIG5vIGF1dGggZGF0YScpO1xyXG5cclxuICAgICAgICBsZXQgc3RhdGUgPSB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoU3RhdGVDb250cm9sO1xyXG4gICAgICAgIGlmICghc3RhdGUpIHtcclxuICAgICAgICAgICAgc3RhdGUgPSBEYXRlLm5vdygpICsgJycgKyBNYXRoLnJhbmRvbSgpICsgTWF0aC5yYW5kb20oKTtcclxuICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aFN0YXRlQ29udHJvbCA9IHN0YXRlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3Qgbm9uY2UgPSAnTicgKyBNYXRoLnJhbmRvbSgpICsgJycgKyBEYXRlLm5vdygpO1xyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhOb25jZSA9IG5vbmNlO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnQXV0aG9yaXplZENvbnRyb2xsZXIgY3JlYXRlZC4gbG9jYWwgc3RhdGU6ICcgKyB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoU3RhdGVDb250cm9sKTtcclxuXHJcbiAgICAgICAgbGV0IHVybCA9ICcnO1xyXG4gICAgICAgIC8vIENvZGUgRmxvd1xyXG4gICAgICAgIGlmICh0aGlzLmF1dGhDb25maWd1cmF0aW9uLnJlc3BvbnNlX3R5cGUgPT09ICdjb2RlJykge1xyXG5cclxuICAgICAgICAgICAgLy8gY29kZV9jaGFsbGVuZ2Ugd2l0aCBcIlMyNTZcIlxyXG4gICAgICAgICAgICBjb25zdCBjb2RlX3ZlcmlmaWVyID0gJ0MnICsgTWF0aC5yYW5kb20oKSArICcnICsgRGF0ZS5ub3coKSArICcnICsgRGF0ZS5ub3coKSArIE1hdGgucmFuZG9tKCk7XHJcbiAgICAgICAgICAgIGNvbnN0IGNvZGVfY2hhbGxlbmdlID0gdGhpcy5vaWRjU2VjdXJpdHlWYWxpZGF0aW9uLmdlbmVyYXRlX2NvZGVfdmVyaWZpZXIoY29kZV92ZXJpZmllcik7XHJcblxyXG4gICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5jb2RlX3ZlcmlmaWVyID0gY29kZV92ZXJpZmllcjtcclxuXHJcbiAgICAgICAgICAgIGlmICh0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMpIHtcclxuICAgICAgICAgICAgICAgIHVybCA9IHRoaXMuY3JlYXRlQXV0aG9yaXplVXJsKHRydWUsIGNvZGVfY2hhbGxlbmdlLFxyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ucmVkaXJlY3RfdXJsLFxyXG4gICAgICAgICAgICAgICAgICAgIG5vbmNlLFxyXG4gICAgICAgICAgICAgICAgICAgIHN0YXRlLFxyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cy5hdXRob3JpemF0aW9uX2VuZHBvaW50XHJcbiAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0Vycm9yKCdhdXRoV2VsbEtub3duRW5kcG9pbnRzIGlzIHVuZGVmaW5lZCcpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfSBlbHNlIHsgLy8gSW1wbGljaXQgRmxvd1xyXG5cclxuICAgICAgICAgICAgaWYgKHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cykge1xyXG4gICAgICAgICAgICAgICAgdXJsID0gdGhpcy5jcmVhdGVBdXRob3JpemVVcmwoZmFsc2UsICcnLFxyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ucmVkaXJlY3RfdXJsLFxyXG4gICAgICAgICAgICAgICAgICAgIG5vbmNlLFxyXG4gICAgICAgICAgICAgICAgICAgIHN0YXRlLFxyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cy5hdXRob3JpemF0aW9uX2VuZHBvaW50XHJcbiAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0Vycm9yKCdhdXRoV2VsbEtub3duRW5kcG9pbnRzIGlzIHVuZGVmaW5lZCcpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAodXJsSGFuZGxlcikge1xyXG4gICAgICAgICAgICB1cmxIYW5kbGVyKHVybCk7XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgdGhpcy5yZWRpcmVjdFRvKHVybCk7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIC8vIENvZGUgRmxvd1xyXG4gICAgYXV0aG9yaXplZENhbGxiYWNrV2l0aENvZGUodXJsVG9DaGVjazogc3RyaW5nKSB7XHJcbiAgICAgICAgY29uc3QgdXJsUGFydHMgPSB1cmxUb0NoZWNrLnNwbGl0KCc/Jyk7XHJcbiAgICAgICAgY29uc3QgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoe1xyXG4gICAgICAgICAgICBmcm9tU3RyaW5nOiB1cmxQYXJ0c1sxXVxyXG4gICAgICAgIH0pO1xyXG4gICAgICAgIGNvbnN0IGNvZGUgPSBwYXJhbXMuZ2V0KCdjb2RlJyk7XHJcbiAgICAgICAgY29uc3Qgc3RhdGUgPSBwYXJhbXMuZ2V0KCdzdGF0ZScpO1xyXG4gICAgICAgIGNvbnN0IHNlc3Npb25fc3RhdGUgPSBwYXJhbXMuZ2V0KCdzZXNzaW9uX3N0YXRlJyk7XHJcblxyXG4gICAgICAgIGlmIChjb2RlICYmIHN0YXRlKSB7XHJcbiAgICAgICAgICAgIHRoaXMucmVxdWVzdFRva2Vuc1dpdGhDb2RlKGNvZGUsIHN0YXRlLCBzZXNzaW9uX3N0YXRlKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgLy8gQ29kZSBGbG93XHJcbiAgICByZXF1ZXN0VG9rZW5zV2l0aENvZGUoY29kZTogc3RyaW5nLCBzdGF0ZTogc3RyaW5nLCBzZXNzaW9uX3N0YXRlOiBzdHJpbmcgfCBudWxsKSB7XHJcbiAgICAgICAgdGhpcy5faXNNb2R1bGVTZXR1cFxyXG4gICAgICAgICAgICAucGlwZShcclxuICAgICAgICAgICAgICAgIGZpbHRlcigoaXNNb2R1bGVTZXR1cDogYm9vbGVhbikgPT4gaXNNb2R1bGVTZXR1cCksXHJcbiAgICAgICAgICAgICAgICB0YWtlKDEpXHJcbiAgICAgICAgICAgIClcclxuICAgICAgICAgICAgLnN1YnNjcmliZSgoKSA9PiB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLnJlcXVlc3RUb2tlbnNXaXRoQ29kZVByb2NlZHVyZShjb2RlLCBzdGF0ZSwgc2Vzc2lvbl9zdGF0ZSk7XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIENvZGUgRmxvdyB3aXRoIFBDS0VcclxuICAgIHJlcXVlc3RUb2tlbnNXaXRoQ29kZVByb2NlZHVyZShjb2RlOiBzdHJpbmcsIHN0YXRlOiBzdHJpbmcsIHNlc3Npb25fc3RhdGU6IHN0cmluZyB8IG51bGwpIHtcclxuICAgICAgICBsZXQgdG9rZW5SZXF1ZXN0VXJsID0gJyc7XHJcbiAgICAgICAgaWYgKHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cyAmJiB0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMudG9rZW5fZW5kcG9pbnQpIHtcclxuICAgICAgICAgICAgdG9rZW5SZXF1ZXN0VXJsID0gYCR7dGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLnRva2VuX2VuZHBvaW50fWA7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoIXRoaXMub2lkY1NlY3VyaXR5VmFsaWRhdGlvbi52YWxpZGF0ZVN0YXRlRnJvbUhhc2hDYWxsYmFjayhzdGF0ZSwgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aFN0YXRlQ29udHJvbCkpIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2F1dGhvcml6ZWRDYWxsYmFjayBpbmNvcnJlY3Qgc3RhdGUnKTtcclxuICAgICAgICAgICAgLy8gVmFsaWRhdGlvblJlc3VsdC5TdGF0ZXNEb05vdE1hdGNoO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBsZXQgaGVhZGVyczogSHR0cEhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKTtcclxuICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoJ0NvbnRlbnQtVHlwZScsICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnKTtcclxuXHJcbiAgICAgICAgbGV0IGRhdGEgPSBgZ3JhbnRfdHlwZT1hdXRob3JpemF0aW9uX2NvZGUmY2xpZW50X2lkPSR7dGhpcy5hdXRoQ29uZmlndXJhdGlvbi5jbGllbnRfaWR9YFxyXG4gICAgICAgICAgICArIGAmY29kZV92ZXJpZmllcj0ke3RoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmNvZGVfdmVyaWZpZXJ9JmNvZGU9JHtjb2RlfSZyZWRpcmVjdF91cmk9JHt0aGlzLmF1dGhDb25maWd1cmF0aW9uLnJlZGlyZWN0X3VybH1gO1xyXG4gICAgICAgIGlmICh0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zaWxlbnRSZW5ld1J1bm5pbmcgPT09ICdydW5uaW5nJykge1xyXG4gICAgICAgICAgICBkYXRhID0gYGdyYW50X3R5cGU9YXV0aG9yaXphdGlvbl9jb2RlJmNsaWVudF9pZD0ke3RoaXMuYXV0aENvbmZpZ3VyYXRpb24uY2xpZW50X2lkfWBcclxuICAgICAgICAgICAgICAgICsgYCZjb2RlX3ZlcmlmaWVyPSR7dGhpcy5vaWRjU2VjdXJpdHlDb21tb24uY29kZV92ZXJpZmllcn0mY29kZT0ke2NvZGV9JnJlZGlyZWN0X3VyaT0ke3RoaXMuYXV0aENvbmZpZ3VyYXRpb24uc2lsZW50X3JlZGlyZWN0X3VybH1gO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgdGhpcy5odHRwQ2xpZW50XHJcbiAgICAgICAgICAgIC5wb3N0KHRva2VuUmVxdWVzdFVybCwgZGF0YSwgeyBoZWFkZXJzOiBoZWFkZXJzIH0pXHJcbiAgICAgICAgICAgIC5waXBlKFxyXG4gICAgICAgICAgICBtYXAocmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIGxldCBvYmo6IGFueSA9IG5ldyBPYmplY3Q7XHJcbiAgICAgICAgICAgICAgICAgICAgb2JqID0gcmVzcG9uc2U7XHJcbiAgICAgICAgICAgICAgICAgICAgb2JqLnN0YXRlID0gc3RhdGU7XHJcbiAgICAgICAgICAgICAgICAgICAgb2JqLnNlc3Npb25fc3RhdGUgPSBzZXNzaW9uX3N0YXRlO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICB0aGlzLmF1dGhvcml6ZWRDb2RlRmxvd0NhbGxiYWNrUHJvY2VkdXJlKG9iaik7XHJcbiAgICAgICAgICAgICAgICB9KSxcclxuICAgICAgICAgICAgY2F0Y2hFcnJvcihlcnJvciA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0Vycm9yKGVycm9yKTtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRXJyb3IoYE9pZGNTZXJ2aWNlIGNvZGUgcmVxdWVzdCAke3RoaXMuYXV0aENvbmZpZ3VyYXRpb24uc3RzU2VydmVyfWApO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBvZihmYWxzZSk7XHJcbiAgICAgICAgICAgICAgICB9KVxyXG4gICAgICAgICAgICApXHJcbiAgICAgICAgICAgIC5zdWJzY3JpYmUoKTtcclxuICAgIH1cclxuXHJcbiAgICAvLyBDb2RlIEZsb3dcclxuICAgIHByaXZhdGUgYXV0aG9yaXplZENvZGVGbG93Q2FsbGJhY2tQcm9jZWR1cmUocmVzdWx0OiBhbnkpIHtcclxuICAgICAgICBjb25zdCBzaWxlbnRSZW5ldyA9IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLnNpbGVudFJlbmV3UnVubmluZztcclxuICAgICAgICBjb25zdCBpc1JlbmV3UHJvY2VzcyA9IHNpbGVudFJlbmV3ID09PSAncnVubmluZyc7XHJcblxyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnQkVHSU4gYXV0aG9yaXplZCBDb2RlIEZsb3cgQ2FsbGJhY2ssIG5vIGF1dGggZGF0YScpO1xyXG4gICAgICAgIHRoaXMucmVzZXRBdXRob3JpemF0aW9uRGF0YShpc1JlbmV3UHJvY2Vzcyk7XHJcblxyXG4gICAgICAgIHRoaXMuYXV0aG9yaXplZENhbGxiYWNrUHJvY2VkdXJlKHJlc3VsdCwgaXNSZW5ld1Byb2Nlc3MpO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIEltcGxpY2l0IEZsb3dcclxuICAgIHByaXZhdGUgYXV0aG9yaXplZEltcGxpY2l0Rmxvd0NhbGxiYWNrUHJvY2VkdXJlKGhhc2g/OiBzdHJpbmcpIHtcclxuICAgICAgICBjb25zdCBzaWxlbnRSZW5ldyA9IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLnNpbGVudFJlbmV3UnVubmluZztcclxuICAgICAgICBjb25zdCBpc1JlbmV3UHJvY2VzcyA9IHNpbGVudFJlbmV3ID09PSAncnVubmluZyc7XHJcblxyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnQkVHSU4gYXV0aG9yaXplZENhbGxiYWNrLCBubyBhdXRoIGRhdGEnKTtcclxuICAgICAgICB0aGlzLnJlc2V0QXV0aG9yaXphdGlvbkRhdGEoaXNSZW5ld1Byb2Nlc3MpO1xyXG5cclxuICAgICAgICBoYXNoID0gaGFzaCB8fCB3aW5kb3cubG9jYXRpb24uaGFzaC5zdWJzdHIoMSk7XHJcblxyXG4gICAgICAgIGNvbnN0IHJlc3VsdDogYW55ID0gaGFzaC5zcGxpdCgnJicpLnJlZHVjZShmdW5jdGlvbiAocmVzdWx0RGF0YTogYW55LCBpdGVtOiBzdHJpbmcpIHtcclxuICAgICAgICAgICAgY29uc3QgcGFydHMgPSBpdGVtLnNwbGl0KCc9Jyk7XHJcbiAgICAgICAgICAgIHJlc3VsdERhdGFbPHN0cmluZz5wYXJ0cy5zaGlmdCgpXSA9IHBhcnRzLmpvaW4oJz0nKTtcclxuICAgICAgICAgICAgcmV0dXJuIHJlc3VsdERhdGE7XHJcbiAgICAgICAgfSwge30pO1xyXG5cclxuICAgICAgICB0aGlzLmF1dGhvcml6ZWRDYWxsYmFja1Byb2NlZHVyZShyZXN1bHQsIGlzUmVuZXdQcm9jZXNzKTtcclxuICAgIH1cclxuXHJcbiAgICAvLyBJbXBsaWNpdCBGbG93XHJcbiAgICBhdXRob3JpemVkSW1wbGljaXRGbG93Q2FsbGJhY2soaGFzaD86IHN0cmluZykge1xyXG4gICAgICAgIHRoaXMuX2lzTW9kdWxlU2V0dXBcclxuICAgICAgICAgICAgLnBpcGUoXHJcbiAgICAgICAgICAgICAgICBmaWx0ZXIoKGlzTW9kdWxlU2V0dXA6IGJvb2xlYW4pID0+IGlzTW9kdWxlU2V0dXApLFxyXG4gICAgICAgICAgICAgICAgdGFrZSgxKVxyXG4gICAgICAgICAgICApXHJcbiAgICAgICAgICAgIC5zdWJzY3JpYmUoKCkgPT4ge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5hdXRob3JpemVkSW1wbGljaXRGbG93Q2FsbGJhY2tQcm9jZWR1cmUoaGFzaCk7XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgcmVkaXJlY3RUbyh1cmw6IHN0cmluZykge1xyXG4gICAgICAgIHdpbmRvdy5sb2NhdGlvbi5ocmVmID0gdXJsO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIEltcGxpY2l0IEZsb3dcclxuICAgIHByaXZhdGUgYXV0aG9yaXplZENhbGxiYWNrUHJvY2VkdXJlKHJlc3VsdDogYW55LCBpc1JlbmV3UHJvY2VzczogYm9vbGVhbikge1xyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhSZXN1bHQgPSByZXN1bHQ7XHJcblxyXG4gICAgICAgIGlmICghdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5oaXN0b3J5X2NsZWFudXBfb2ZmICYmICFpc1JlbmV3UHJvY2Vzcykge1xyXG4gICAgICAgICAgICAvLyByZXNldCB0aGUgaGlzdG9yeSB0byByZW1vdmUgdGhlIHRva2Vuc1xyXG4gICAgICAgICAgICB3aW5kb3cuaGlzdG9yeS5yZXBsYWNlU3RhdGUoe30sIHdpbmRvdy5kb2N1bWVudC50aXRsZSwgd2luZG93LmxvY2F0aW9uLm9yaWdpbiArIHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZSk7XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdoaXN0b3J5IGNsZWFuIHVwIGluYWN0aXZlJyk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAocmVzdWx0LmVycm9yKSB7XHJcbiAgICAgICAgICAgIGlmIChpc1JlbmV3UHJvY2Vzcykge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKHJlc3VsdCk7XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZyhyZXN1bHQpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBpZiAoKHJlc3VsdC5lcnJvciBhcyBzdHJpbmcpID09PSAnbG9naW5fcmVxdWlyZWQnKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLl9vbkF1dGhvcml6YXRpb25SZXN1bHQubmV4dChuZXcgQXV0aG9yaXphdGlvblJlc3VsdChBdXRob3JpemF0aW9uU3RhdGUudW5hdXRob3JpemVkLCBWYWxpZGF0aW9uUmVzdWx0LkxvZ2luUmVxdWlyZWQpKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgIHRoaXMuX29uQXV0aG9yaXphdGlvblJlc3VsdC5uZXh0KG5ldyBBdXRob3JpemF0aW9uUmVzdWx0KEF1dGhvcml6YXRpb25TdGF0ZS51bmF1dGhvcml6ZWQsIFZhbGlkYXRpb25SZXN1bHQuU2VjdXJlVG9rZW5TZXJ2ZXJFcnJvcikpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICB0aGlzLnJlc2V0QXV0aG9yaXphdGlvbkRhdGEoZmFsc2UpO1xyXG4gICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoTm9uY2UgPSAnJztcclxuXHJcbiAgICAgICAgICAgIGlmICghdGhpcy5hdXRoQ29uZmlndXJhdGlvbi50cmlnZ2VyX2F1dGhvcml6YXRpb25fcmVzdWx0X2V2ZW50ICYmICFpc1JlbmV3UHJvY2Vzcykge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5yb3V0ZXIubmF2aWdhdGUoW3RoaXMuYXV0aENvbmZpZ3VyYXRpb24udW5hdXRob3JpemVkX3JvdXRlXSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcocmVzdWx0KTtcclxuXHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnYXV0aG9yaXplZENhbGxiYWNrIGNyZWF0ZWQsIGJlZ2luIHRva2VuIHZhbGlkYXRpb24nKTtcclxuXHJcbiAgICAgICAgICAgIHRoaXMuZ2V0U2lnbmluZ0tleXMoKS5zdWJzY3JpYmUoXHJcbiAgICAgICAgICAgICAgICBqd3RLZXlzID0+IHtcclxuICAgICAgICAgICAgICAgICAgICBjb25zdCB2YWxpZGF0aW9uUmVzdWx0ID0gdGhpcy5nZXRWYWxpZGF0ZWRTdGF0ZVJlc3VsdChyZXN1bHQsIGp3dEtleXMpO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICBpZiAodmFsaWRhdGlvblJlc3VsdC5hdXRoUmVzcG9uc2VJc1ZhbGlkKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc2V0QXV0aG9yaXphdGlvbkRhdGEodmFsaWRhdGlvblJlc3VsdC5hY2Nlc3NfdG9rZW4sIHZhbGlkYXRpb25SZXN1bHQuaWRfdG9rZW4pO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zaWxlbnRSZW5ld1J1bm5pbmcgPSAnJztcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLmF1dGhDb25maWd1cmF0aW9uLmF1dG9fdXNlcmluZm8pIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZ2V0VXNlcmluZm8oaXNSZW5ld1Byb2Nlc3MsIHJlc3VsdCwgdmFsaWRhdGlvblJlc3VsdC5pZF90b2tlbiwgdmFsaWRhdGlvblJlc3VsdC5kZWNvZGVkX2lkX3Rva2VuKS5zdWJzY3JpYmUoXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2UpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX29uQXV0aG9yaXphdGlvblJlc3VsdC5uZXh0KFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBBdXRob3JpemF0aW9uUmVzdWx0KEF1dGhvcml6YXRpb25TdGF0ZS5hdXRob3JpemVkLCB2YWxpZGF0aW9uUmVzdWx0LnN0YXRlKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5hdXRoQ29uZmlndXJhdGlvbi50cmlnZ2VyX2F1dGhvcml6YXRpb25fcmVzdWx0X2V2ZW50ICYmICFpc1JlbmV3UHJvY2Vzcykge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucm91dGVyLm5hdmlnYXRlKFt0aGlzLmF1dGhDb25maWd1cmF0aW9uLnBvc3RfbG9naW5fcm91dGVdKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX29uQXV0aG9yaXphdGlvblJlc3VsdC5uZXh0KFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBBdXRob3JpemF0aW9uUmVzdWx0KEF1dGhvcml6YXRpb25TdGF0ZS51bmF1dGhvcml6ZWQsIHZhbGlkYXRpb25SZXN1bHQuc3RhdGUpXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLmF1dGhDb25maWd1cmF0aW9uLnRyaWdnZXJfYXV0aG9yaXphdGlvbl9yZXN1bHRfZXZlbnQgJiYgIWlzUmVuZXdQcm9jZXNzKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yb3V0ZXIubmF2aWdhdGUoW3RoaXMuYXV0aENvbmZpZ3VyYXRpb24udW5hdXRob3JpemVkX3JvdXRlXSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9LFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVyciA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8qIFNvbWV0aGluZyB3ZW50IHdyb25nIHdoaWxlIGdldHRpbmcgc2lnbmluZyBrZXkgKi9cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ0ZhaWxlZCB0byByZXRyZWl2ZSB1c2VyIGluZm8gd2l0aCBlcnJvcjogJyArIEpTT04uc3RyaW5naWZ5KGVycikpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWlzUmVuZXdQcm9jZXNzKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gdXNlckRhdGEgaXMgc2V0IHRvIHRoZSBpZF90b2tlbiBkZWNvZGVkLCBhdXRvIGdldCB1c2VyIGRhdGEgc2V0IHRvIGZhbHNlXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlVc2VyU2VydmljZS5zZXRVc2VyRGF0YSh2YWxpZGF0aW9uUmVzdWx0LmRlY29kZWRfaWRfdG9rZW4pO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc2V0VXNlckRhdGEodGhpcy5vaWRjU2VjdXJpdHlVc2VyU2VydmljZS5nZXRVc2VyRGF0YSgpKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnJ1blRva2VuVmFsaWRhdGlvbigpO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX29uQXV0aG9yaXphdGlvblJlc3VsdC5uZXh0KG5ldyBBdXRob3JpemF0aW9uUmVzdWx0KEF1dGhvcml6YXRpb25TdGF0ZS5hdXRob3JpemVkLCB2YWxpZGF0aW9uUmVzdWx0LnN0YXRlKSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMuYXV0aENvbmZpZ3VyYXRpb24udHJpZ2dlcl9hdXRob3JpemF0aW9uX3Jlc3VsdF9ldmVudCAmJiAhaXNSZW5ld1Byb2Nlc3MpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnJvdXRlci5uYXZpZ2F0ZShbdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5wb3N0X2xvZ2luX3JvdXRlXSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBzb21ldGhpbmcgd2VudCB3cm9uZ1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnYXV0aG9yaXplZENhbGxiYWNrLCB0b2tlbihzKSB2YWxpZGF0aW9uIGZhaWxlZCwgcmVzZXR0aW5nJyk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKHdpbmRvdy5sb2NhdGlvbi5oYXNoKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yZXNldEF1dGhvcml6YXRpb25EYXRhKGZhbHNlKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uc2lsZW50UmVuZXdSdW5uaW5nID0gJyc7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9vbkF1dGhvcml6YXRpb25SZXN1bHQubmV4dChuZXcgQXV0aG9yaXphdGlvblJlc3VsdChBdXRob3JpemF0aW9uU3RhdGUudW5hdXRob3JpemVkLCB2YWxpZGF0aW9uUmVzdWx0LnN0YXRlKSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5hdXRoQ29uZmlndXJhdGlvbi50cmlnZ2VyX2F1dGhvcml6YXRpb25fcmVzdWx0X2V2ZW50ICYmICFpc1JlbmV3UHJvY2Vzcykge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yb3V0ZXIubmF2aWdhdGUoW3RoaXMuYXV0aENvbmZpZ3VyYXRpb24udW5hdXRob3JpemVkX3JvdXRlXSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9LFxyXG4gICAgICAgICAgICAgICAgZXJyID0+IHtcclxuICAgICAgICAgICAgICAgICAgICAvKiBTb21ldGhpbmcgd2VudCB3cm9uZyB3aGlsZSBnZXR0aW5nIHNpZ25pbmcga2V5ICovXHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ0ZhaWxlZCB0byByZXRyZWl2ZSBzaWdpbmcga2V5IHdpdGggZXJyb3I6ICcgKyBKU09OLnN0cmluZ2lmeShlcnIpKTtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zaWxlbnRSZW5ld1J1bm5pbmcgPSAnJztcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0VXNlcmluZm8oaXNSZW5ld1Byb2Nlc3MgPSBmYWxzZSwgcmVzdWx0PzogYW55LCBpZF90b2tlbj86IGFueSwgZGVjb2RlZF9pZF90b2tlbj86IGFueSk6IE9ic2VydmFibGU8Ym9vbGVhbj4ge1xyXG4gICAgICAgIHJlc3VsdCA9IHJlc3VsdCA/IHJlc3VsdCA6IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhSZXN1bHQ7XHJcbiAgICAgICAgaWRfdG9rZW4gPSBpZF90b2tlbiA/IGlkX3Rva2VuIDogdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uaWRUb2tlbjtcclxuICAgICAgICBkZWNvZGVkX2lkX3Rva2VuID0gZGVjb2RlZF9pZF90b2tlbiA/IGRlY29kZWRfaWRfdG9rZW4gOiB0aGlzLnRva2VuSGVscGVyU2VydmljZS5nZXRQYXlsb2FkRnJvbVRva2VuKGlkX3Rva2VuLCBmYWxzZSk7XHJcblxyXG4gICAgICAgIHJldHVybiBuZXcgT2JzZXJ2YWJsZTxib29sZWFuPihvYnNlcnZlciA9PiB7XHJcbiAgICAgICAgICAgIC8vIGZsb3cgaWRfdG9rZW4gdG9rZW5cclxuICAgICAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ucmVzcG9uc2VfdHlwZSA9PT0gJ2lkX3Rva2VuIHRva2VuJyB8fCB0aGlzLmF1dGhDb25maWd1cmF0aW9uLnJlc3BvbnNlX3R5cGUgPT09ICdjb2RlJykge1xyXG4gICAgICAgICAgICAgICAgaWYgKGlzUmVuZXdQcm9jZXNzICYmIHRoaXMuX3VzZXJEYXRhLnZhbHVlKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uc2Vzc2lvblN0YXRlID0gcmVzdWx0LnNlc3Npb25fc3RhdGU7XHJcbiAgICAgICAgICAgICAgICAgICAgb2JzZXJ2ZXIubmV4dCh0cnVlKTtcclxuICAgICAgICAgICAgICAgICAgICBvYnNlcnZlci5jb21wbGV0ZSgpO1xyXG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eVVzZXJTZXJ2aWNlLmluaXRVc2VyRGF0YSgpLnN1YnNjcmliZSgoKSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnYXV0aG9yaXplZENhbGxiYWNrIChpZF90b2tlbiB0b2tlbiB8fCBjb2RlKSBmbG93Jyk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zdCB1c2VyRGF0YSA9IHRoaXMub2lkY1NlY3VyaXR5VXNlclNlcnZpY2UuZ2V0VXNlckRhdGEoKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLm9pZGNTZWN1cml0eVZhbGlkYXRpb24udmFsaWRhdGVfdXNlcmRhdGFfc3ViX2lkX3Rva2VuKGRlY29kZWRfaWRfdG9rZW4uc3ViLCB1c2VyRGF0YS5zdWIpKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnNldFVzZXJEYXRhKHVzZXJEYXRhKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1Zyh0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hY2Nlc3NUb2tlbik7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcodGhpcy5vaWRjU2VjdXJpdHlVc2VyU2VydmljZS5nZXRVc2VyRGF0YSgpKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zZXNzaW9uU3RhdGUgPSByZXN1bHQuc2Vzc2lvbl9zdGF0ZTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnJ1blRva2VuVmFsaWRhdGlvbigpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgb2JzZXJ2ZXIubmV4dCh0cnVlKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIHNvbWV0aGluZyB3ZW50IHdyb25nLCB1c2VyZGF0YSBzdWIgZG9lcyBub3QgbWF0Y2ggdGhhdCBmcm9tIGlkX3Rva2VuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnYXV0aG9yaXplZENhbGxiYWNrLCBVc2VyIGRhdGEgc3ViIGRvZXMgbm90IG1hdGNoIHN1YiBpbiBpZF90b2tlbicpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdhdXRob3JpemVkQ2FsbGJhY2ssIHRva2VuKHMpIHZhbGlkYXRpb24gZmFpbGVkLCByZXNldHRpbmcnKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucmVzZXRBdXRob3JpemF0aW9uRGF0YShmYWxzZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvYnNlcnZlci5uZXh0KGZhbHNlKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICBvYnNlcnZlci5jb21wbGV0ZSgpO1xyXG4gICAgICAgICAgICAgICAgICAgIH0pO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgLy8gZmxvdyBpZF90b2tlblxyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdhdXRob3JpemVkQ2FsbGJhY2sgaWRfdG9rZW4gZmxvdycpO1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmFjY2Vzc1Rva2VuKTtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyB1c2VyRGF0YSBpcyBzZXQgdG8gdGhlIGlkX3Rva2VuIGRlY29kZWQuIE5vIGFjY2Vzc190b2tlbi5cclxuICAgICAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5VXNlclNlcnZpY2Uuc2V0VXNlckRhdGEoZGVjb2RlZF9pZF90b2tlbik7XHJcbiAgICAgICAgICAgICAgICB0aGlzLnNldFVzZXJEYXRhKHRoaXMub2lkY1NlY3VyaXR5VXNlclNlcnZpY2UuZ2V0VXNlckRhdGEoKSk7XHJcblxyXG4gICAgICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uc2Vzc2lvblN0YXRlID0gcmVzdWx0LnNlc3Npb25fc3RhdGU7XHJcblxyXG4gICAgICAgICAgICAgICAgdGhpcy5ydW5Ub2tlblZhbGlkYXRpb24oKTtcclxuXHJcbiAgICAgICAgICAgICAgICBvYnNlcnZlci5uZXh0KHRydWUpO1xyXG4gICAgICAgICAgICAgICAgb2JzZXJ2ZXIuY29tcGxldGUoKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH0pO1xyXG4gICAgfVxyXG5cclxuICAgIGxvZ29mZih1cmxIYW5kbGVyPzogKHVybDogc3RyaW5nKSA9PiBhbnkpIHtcclxuICAgICAgICAvLyAvY29ubmVjdC9lbmRzZXNzaW9uP2lkX3Rva2VuX2hpbnQ9Li4uJnBvc3RfbG9nb3V0X3JlZGlyZWN0X3VyaT1odHRwczovL215YXBwLmNvbVxyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnQkVHSU4gQXV0aG9yaXplLCBubyBhdXRoIGRhdGEnKTtcclxuXHJcbiAgICAgICAgaWYgKHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cykge1xyXG4gICAgICAgICAgICBpZiAodGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLmVuZF9zZXNzaW9uX2VuZHBvaW50KSB7XHJcbiAgICAgICAgICAgICAgICBjb25zdCBlbmRfc2Vzc2lvbl9lbmRwb2ludCA9IHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cy5lbmRfc2Vzc2lvbl9lbmRwb2ludDtcclxuICAgICAgICAgICAgICAgIGNvbnN0IGlkX3Rva2VuX2hpbnQgPSB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5pZFRva2VuO1xyXG4gICAgICAgICAgICAgICAgY29uc3QgdXJsID0gdGhpcy5jcmVhdGVFbmRTZXNzaW9uVXJsKGVuZF9zZXNzaW9uX2VuZHBvaW50LCBpZF90b2tlbl9oaW50KTtcclxuXHJcbiAgICAgICAgICAgICAgICB0aGlzLnJlc2V0QXV0aG9yaXphdGlvbkRhdGEoZmFsc2UpO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmICh0aGlzLmF1dGhDb25maWd1cmF0aW9uLnN0YXJ0X2NoZWNrc2Vzc2lvbiAmJiB0aGlzLmNoZWNrU2Vzc2lvbkNoYW5nZWQpIHtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ29ubHkgbG9jYWwgbG9naW4gY2xlYW5lZCB1cCwgc2VydmVyIHNlc3Npb24gaGFzIGNoYW5nZWQnKTtcclxuICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAodXJsSGFuZGxlcikge1xyXG4gICAgICAgICAgICAgICAgICAgIHVybEhhbmRsZXIodXJsKTtcclxuICAgICAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5yZWRpcmVjdFRvKHVybCk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLnJlc2V0QXV0aG9yaXphdGlvbkRhdGEoZmFsc2UpO1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdvbmx5IGxvY2FsIGxvZ2luIGNsZWFuZWQgdXAsIG5vIGVuZF9zZXNzaW9uX2VuZHBvaW50Jyk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnYXV0aFdlbGxLbm93bkVuZHBvaW50cyBpcyB1bmRlZmluZWQnKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmVmcmVzaFNlc3Npb24oKTogT2JzZXJ2YWJsZTxhbnk+IHtcclxuICAgICAgICBpZiAoIXRoaXMuYXV0aENvbmZpZ3VyYXRpb24uc2lsZW50X3JlbmV3KSB7XHJcbiAgICAgICAgICAgIHJldHVybiBmcm9tKFtmYWxzZV0pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdCRUdJTiByZWZyZXNoIHNlc3Npb24gQXV0aG9yaXplJyk7XHJcblxyXG4gICAgICAgIGxldCBzdGF0ZSA9IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhTdGF0ZUNvbnRyb2w7XHJcbiAgICAgICAgaWYgKHN0YXRlID09PSAnJyB8fCBzdGF0ZSA9PT0gbnVsbCkge1xyXG4gICAgICAgICAgICBzdGF0ZSA9IERhdGUubm93KCkgKyAnJyArIE1hdGgucmFuZG9tKCkgKyBNYXRoLnJhbmRvbSgpO1xyXG4gICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoU3RhdGVDb250cm9sID0gc3RhdGU7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBub25jZSA9ICdOJyArIE1hdGgucmFuZG9tKCkgKyAnJyArIERhdGUubm93KCk7XHJcbiAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aE5vbmNlID0gbm9uY2U7XHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdSZWZyZXNoU2Vzc2lvbiBjcmVhdGVkLiBhZGRpbmcgbXlhdXRvc3RhdGU6ICcgKyB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoU3RhdGVDb250cm9sKTtcclxuXHJcbiAgICAgICAgbGV0IHVybCA9ICcnO1xyXG5cclxuICAgICAgICAvLyBDb2RlIEZsb3dcclxuICAgICAgICBpZiAodGhpcy5hdXRoQ29uZmlndXJhdGlvbi5yZXNwb25zZV90eXBlID09PSAnY29kZScpIHtcclxuXHJcbiAgICAgICAgICAgIC8vIGNvZGVfY2hhbGxlbmdlIHdpdGggXCJTMjU2XCJcclxuICAgICAgICAgICAgY29uc3QgY29kZV92ZXJpZmllciA9ICdDJyArIE1hdGgucmFuZG9tKCkgKyAnJyArIERhdGUubm93KCkgKyAnJyArIERhdGUubm93KCkgKyBNYXRoLnJhbmRvbSgpO1xyXG4gICAgICAgICAgICBjb25zdCBjb2RlX2NoYWxsZW5nZSA9IHRoaXMub2lkY1NlY3VyaXR5VmFsaWRhdGlvbi5nZW5lcmF0ZV9jb2RlX3ZlcmlmaWVyKGNvZGVfdmVyaWZpZXIpO1xyXG5cclxuICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uY29kZV92ZXJpZmllciA9IGNvZGVfdmVyaWZpZXI7XHJcblxyXG4gICAgICAgICAgICBpZiAodGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzKSB7XHJcbiAgICAgICAgICAgICAgICB1cmwgPSB0aGlzLmNyZWF0ZUF1dGhvcml6ZVVybCh0cnVlLCBjb2RlX2NoYWxsZW5nZSxcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLmF1dGhDb25maWd1cmF0aW9uLnNpbGVudF9yZWRpcmVjdF91cmwsXHJcbiAgICAgICAgICAgICAgICAgICAgbm9uY2UsXHJcbiAgICAgICAgICAgICAgICAgICAgc3RhdGUsXHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLmF1dGhvcml6YXRpb25fZW5kcG9pbnQsXHJcbiAgICAgICAgICAgICAgICAgICAgJ25vbmUnXHJcbiAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2F1dGhXZWxsS25vd25FbmRwb2ludHMgaXMgdW5kZWZpbmVkJyk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICBpZiAodGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzKSB7XHJcbiAgICAgICAgICAgICAgICB1cmwgPSB0aGlzLmNyZWF0ZUF1dGhvcml6ZVVybChmYWxzZSwgJycsXHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zaWxlbnRfcmVkaXJlY3RfdXJsLFxyXG4gICAgICAgICAgICAgICAgICAgIG5vbmNlLFxyXG4gICAgICAgICAgICAgICAgICAgIHN0YXRlLFxyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cy5hdXRob3JpemF0aW9uX2VuZHBvaW50LFxyXG4gICAgICAgICAgICAgICAgICAgICdub25lJ1xyXG4gICAgICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdhdXRoV2VsbEtub3duRW5kcG9pbnRzIGlzIHVuZGVmaW5lZCcpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zaWxlbnRSZW5ld1J1bm5pbmcgPSAncnVubmluZyc7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMub2lkY1NlY3VyaXR5U2lsZW50UmVuZXcuc3RhcnRSZW5ldyh1cmwpO1xyXG4gICAgfVxyXG5cclxuICAgIGhhbmRsZUVycm9yKGVycm9yOiBhbnkpIHtcclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRXJyb3IoZXJyb3IpO1xyXG4gICAgICAgIGlmIChlcnJvci5zdGF0dXMgPT09IDQwMyB8fCBlcnJvci5zdGF0dXMgPT09ICc0MDMnKSB7XHJcbiAgICAgICAgICAgIGlmICh0aGlzLmF1dGhDb25maWd1cmF0aW9uLnRyaWdnZXJfYXV0aG9yaXphdGlvbl9yZXN1bHRfZXZlbnQpIHtcclxuICAgICAgICAgICAgICAgIHRoaXMuX29uQXV0aG9yaXphdGlvblJlc3VsdC5uZXh0KG5ldyBBdXRob3JpemF0aW9uUmVzdWx0KEF1dGhvcml6YXRpb25TdGF0ZS51bmF1dGhvcml6ZWQsIFZhbGlkYXRpb25SZXN1bHQuTm90U2V0KSk7XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLnJvdXRlci5uYXZpZ2F0ZShbdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5mb3JiaWRkZW5fcm91dGVdKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH0gZWxzZSBpZiAoZXJyb3Iuc3RhdHVzID09PSA0MDEgfHwgZXJyb3Iuc3RhdHVzID09PSAnNDAxJykge1xyXG4gICAgICAgICAgICBjb25zdCBzaWxlbnRSZW5ldyA9IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLnNpbGVudFJlbmV3UnVubmluZztcclxuXHJcbiAgICAgICAgICAgIHRoaXMucmVzZXRBdXRob3JpemF0aW9uRGF0YSghIXNpbGVudFJlbmV3KTtcclxuXHJcbiAgICAgICAgICAgIGlmICh0aGlzLmF1dGhDb25maWd1cmF0aW9uLnRyaWdnZXJfYXV0aG9yaXphdGlvbl9yZXN1bHRfZXZlbnQpIHtcclxuICAgICAgICAgICAgICAgIHRoaXMuX29uQXV0aG9yaXphdGlvblJlc3VsdC5uZXh0KG5ldyBBdXRob3JpemF0aW9uUmVzdWx0KEF1dGhvcml6YXRpb25TdGF0ZS51bmF1dGhvcml6ZWQsIFZhbGlkYXRpb25SZXN1bHQuTm90U2V0KSk7XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLnJvdXRlci5uYXZpZ2F0ZShbdGhpcy5hdXRoQ29uZmlndXJhdGlvbi51bmF1dGhvcml6ZWRfcm91dGVdKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBzdGFydENoZWNraW5nU2lsZW50UmVuZXcoKTogdm9pZCB7XHJcbiAgICAgICAgdGhpcy5ydW5Ub2tlblZhbGlkYXRpb24oKTtcclxuICAgIH1cclxuXHJcbiAgICBzdG9wQ2hlY2tpbmdTaWxlbnRSZW5ldygpOiB2b2lkIHtcclxuICAgICAgICBpZiAodGhpcy5fc2NoZWR1bGVkSGVhcnRCZWF0KSB7XHJcbiAgICAgICAgICAgIGNsZWFyVGltZW91dCh0aGlzLl9zY2hlZHVsZWRIZWFydEJlYXQpO1xyXG4gICAgICAgICAgICB0aGlzLl9zY2hlZHVsZWRIZWFydEJlYXQgPSBudWxsO1xyXG4gICAgICAgICAgICB0aGlzLnJ1blRva2VuVmFsaWRhdGlvblJ1bm5pbmcgPSBmYWxzZTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmVzZXRBdXRob3JpemF0aW9uRGF0YShpc1JlbmV3UHJvY2VzczogYm9vbGVhbik6IHZvaWQge1xyXG4gICAgICAgIGlmICghaXNSZW5ld1Byb2Nlc3MpIHtcclxuICAgICAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uYXV0b191c2VyaW5mbykge1xyXG4gICAgICAgICAgICAgICAgLy8gQ2xlYXIgdXNlciBkYXRhLiBGaXhlcyAjOTcuXHJcbiAgICAgICAgICAgICAgICB0aGlzLnNldFVzZXJEYXRhKCcnKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24ucmVzZXRTdG9yYWdlRGF0YShpc1JlbmV3UHJvY2Vzcyk7XHJcbiAgICAgICAgICAgIHRoaXMuY2hlY2tTZXNzaW9uQ2hhbmdlZCA9IGZhbHNlO1xyXG4gICAgICAgICAgICB0aGlzLnNldElzQXV0aG9yaXplZChmYWxzZSk7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGdldEVuZFNlc3Npb25VcmwoKTogc3RyaW5nIHwgdW5kZWZpbmVkIHtcclxuICAgICAgICBpZiAodGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzKSB7XHJcbiAgICAgICAgICAgIGlmICh0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMuZW5kX3Nlc3Npb25fZW5kcG9pbnQpIHtcclxuICAgICAgICAgICAgICAgIGNvbnN0IGVuZF9zZXNzaW9uX2VuZHBvaW50ID0gdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLmVuZF9zZXNzaW9uX2VuZHBvaW50O1xyXG4gICAgICAgICAgICAgICAgY29uc3QgaWRfdG9rZW5faGludCA9IHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmlkVG9rZW47XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5jcmVhdGVFbmRTZXNzaW9uVXJsKGVuZF9zZXNzaW9uX2VuZHBvaW50LCBpZF90b2tlbl9oaW50KTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIGdldFZhbGlkYXRlZFN0YXRlUmVzdWx0KHJlc3VsdDogYW55LCBqd3RLZXlzOiBKd3RLZXlzKTogVmFsaWRhdGVTdGF0ZVJlc3VsdCB7XHJcbiAgICAgICAgaWYgKHJlc3VsdC5lcnJvcikge1xyXG4gICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRlU3RhdGVSZXN1bHQoJycsICcnLCBmYWxzZSwge30pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuc3RhdGVWYWxpZGF0aW9uU2VydmljZS52YWxpZGF0ZVN0YXRlKHJlc3VsdCwgand0S2V5cyk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzZXRVc2VyRGF0YSh1c2VyRGF0YTogYW55KTogdm9pZCB7XHJcbiAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24udXNlckRhdGEgPSB1c2VyRGF0YTtcclxuICAgICAgICB0aGlzLl91c2VyRGF0YS5uZXh0KHVzZXJEYXRhKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHNldElzQXV0aG9yaXplZChpc0F1dGhvcml6ZWQ6IGJvb2xlYW4pOiB2b2lkIHtcclxuICAgICAgICB0aGlzLl9pc0F1dGhvcml6ZWQubmV4dChpc0F1dGhvcml6ZWQpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgc2V0QXV0aG9yaXphdGlvbkRhdGEoYWNjZXNzX3Rva2VuOiBhbnksIGlkX3Rva2VuOiBhbnkpIHtcclxuICAgICAgICBpZiAodGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYWNjZXNzVG9rZW4gIT09ICcnKSB7XHJcbiAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmFjY2Vzc1Rva2VuID0gJyc7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoYWNjZXNzX3Rva2VuKTtcclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoaWRfdG9rZW4pO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1Zygnc3RvcmluZyB0byBzdG9yYWdlLCBnZXR0aW5nIHRoZSByb2xlcycpO1xyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmFjY2Vzc1Rva2VuID0gYWNjZXNzX3Rva2VuO1xyXG4gICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmlkVG9rZW4gPSBpZF90b2tlbjtcclxuICAgICAgICB0aGlzLnNldElzQXV0aG9yaXplZCh0cnVlKTtcclxuICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5pc0F1dGhvcml6ZWQgPSB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgY3JlYXRlQXV0aG9yaXplVXJsKGlzQ29kZUZsb3c6IGJvb2xlYW4sIGNvZGVfY2hhbGxlbmdlOiBzdHJpbmcsIHJlZGlyZWN0X3VybDogc3RyaW5nLCBub25jZTogc3RyaW5nLCBzdGF0ZTogc3RyaW5nLCBhdXRob3JpemF0aW9uX2VuZHBvaW50OiBzdHJpbmcsIHByb21wdD86IHN0cmluZyk6IHN0cmluZyB7XHJcbiAgICAgICAgY29uc3QgdXJsUGFydHMgPSBhdXRob3JpemF0aW9uX2VuZHBvaW50LnNwbGl0KCc/Jyk7XHJcbiAgICAgICAgY29uc3QgYXV0aG9yaXphdGlvblVybCA9IHVybFBhcnRzWzBdO1xyXG4gICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcyh7XHJcbiAgICAgICAgICAgIGZyb21TdHJpbmc6IHVybFBhcnRzWzFdLFxyXG4gICAgICAgICAgICBlbmNvZGVyOiBuZXcgVXJpRW5jb2RlcigpLFxyXG4gICAgICAgIH0pO1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uY2xpZW50X2lkKTtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuYXBwZW5kKCdyZWRpcmVjdF91cmknLCByZWRpcmVjdF91cmwpO1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5hcHBlbmQoJ3Jlc3BvbnNlX3R5cGUnLCB0aGlzLmF1dGhDb25maWd1cmF0aW9uLnJlc3BvbnNlX3R5cGUpO1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5hcHBlbmQoJ3Njb3BlJywgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zY29wZSk7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLmFwcGVuZCgnbm9uY2UnLCBub25jZSk7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLmFwcGVuZCgnc3RhdGUnLCBzdGF0ZSk7XHJcblxyXG4gICAgICAgIGlmIChpc0NvZGVGbG93KSB7XHJcblxyXG4gICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuYXBwZW5kKCdjb2RlX2NoYWxsZW5nZScsIGNvZGVfY2hhbGxlbmdlKTtcclxuICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLmFwcGVuZCgnY29kZV9jaGFsbGVuZ2VfbWV0aG9kJywgJ1MyNTYnKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmIChwcm9tcHQpIHtcclxuICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLmFwcGVuZCgncHJvbXB0JywgcHJvbXB0KTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmICh0aGlzLmF1dGhDb25maWd1cmF0aW9uLmhkX3BhcmFtKSB7XHJcbiAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5hcHBlbmQoJ2hkJywgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5oZF9wYXJhbSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBjdXN0b21QYXJhbXMgPSBPYmplY3QuYXNzaWduKHt9LCB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5jdXN0b21SZXF1ZXN0UGFyYW1zKTtcclxuXHJcbiAgICAgICAgT2JqZWN0LmtleXMoY3VzdG9tUGFyYW1zKS5mb3JFYWNoKGtleSA9PiB7XHJcbiAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5hcHBlbmQoa2V5LCBjdXN0b21QYXJhbXNba2V5XS50b1N0cmluZygpKTtcclxuICAgICAgICB9KTtcclxuXHJcbiAgICAgICAgcmV0dXJuIGAke2F1dGhvcml6YXRpb25Vcmx9PyR7cGFyYW1zfWA7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBjcmVhdGVFbmRTZXNzaW9uVXJsKGVuZF9zZXNzaW9uX2VuZHBvaW50OiBzdHJpbmcsIGlkX3Rva2VuX2hpbnQ6IHN0cmluZykge1xyXG4gICAgICAgIGNvbnN0IHVybFBhcnRzID0gZW5kX3Nlc3Npb25fZW5kcG9pbnQuc3BsaXQoJz8nKTtcclxuXHJcbiAgICAgICAgY29uc3QgYXV0aG9yaXphdGlvbkVuZHNlc3Npb25VcmwgPSB1cmxQYXJ0c1swXTtcclxuXHJcbiAgICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKHtcclxuICAgICAgICAgICAgZnJvbVN0cmluZzogdXJsUGFydHNbMV0sXHJcbiAgICAgICAgICAgIGVuY29kZXI6IG5ldyBVcmlFbmNvZGVyKCksXHJcbiAgICAgICAgfSk7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnaWRfdG9rZW5faGludCcsIGlkX3Rva2VuX2hpbnQpO1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5hcHBlbmQoJ3Bvc3RfbG9nb3V0X3JlZGlyZWN0X3VyaScsIHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ucG9zdF9sb2dvdXRfcmVkaXJlY3RfdXJpKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIGAke2F1dGhvcml6YXRpb25FbmRzZXNzaW9uVXJsfT8ke3BhcmFtc31gO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgZ2V0U2lnbmluZ0tleXMoKTogT2JzZXJ2YWJsZTxKd3RLZXlzPiB7XHJcbiAgICAgICAgaWYgKHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cykge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ2p3a3NfdXJpOiAnICsgdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLmp3a3NfdXJpKTtcclxuXHJcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm9pZGNEYXRhU2VydmljZS5nZXQ8Snd0S2V5cz4odGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLmp3a3NfdXJpKS5waXBlKGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvckdldFNpZ25pbmdLZXlzKSk7XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2dldFNpZ25pbmdLZXlzOiBhdXRoV2VsbEtub3duRW5kcG9pbnRzIGlzIHVuZGVmaW5lZCcpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMub2lkY0RhdGFTZXJ2aWNlLmdldDxKd3RLZXlzPigndW5kZWZpbmVkJykucGlwZShjYXRjaEVycm9yKHRoaXMuaGFuZGxlRXJyb3JHZXRTaWduaW5nS2V5cykpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgaGFuZGxlRXJyb3JHZXRTaWduaW5nS2V5cyhlcnJvcjogUmVzcG9uc2UgfCBhbnkpIHtcclxuICAgICAgICBsZXQgZXJyTXNnOiBzdHJpbmc7XHJcbiAgICAgICAgaWYgKGVycm9yIGluc3RhbmNlb2YgUmVzcG9uc2UpIHtcclxuICAgICAgICAgICAgY29uc3QgYm9keSA9IGVycm9yLmpzb24oKSB8fCB7fTtcclxuICAgICAgICAgICAgY29uc3QgZXJyID0gSlNPTi5zdHJpbmdpZnkoYm9keSk7XHJcbiAgICAgICAgICAgIGVyck1zZyA9IGAke2Vycm9yLnN0YXR1c30gLSAke2Vycm9yLnN0YXR1c1RleHQgfHwgJyd9ICR7ZXJyfWA7XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgZXJyTXNnID0gZXJyb3IubWVzc2FnZSA/IGVycm9yLm1lc3NhZ2UgOiBlcnJvci50b1N0cmluZygpO1xyXG4gICAgICAgIH1cclxuICAgICAgICBjb25zb2xlLmVycm9yKGVyck1zZyk7XHJcbiAgICAgICAgcmV0dXJuIG9ic2VydmFibGVUaHJvd0Vycm9yKGVyck1zZyk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBydW5Ub2tlblZhbGlkYXRpb24oKSB7XHJcbiAgICAgICAgaWYgKHRoaXMucnVuVG9rZW5WYWxpZGF0aW9uUnVubmluZyB8fCAhdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zaWxlbnRfcmVuZXcpIHtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuICAgICAgICB0aGlzLnJ1blRva2VuVmFsaWRhdGlvblJ1bm5pbmcgPSB0cnVlO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygncnVuVG9rZW5WYWxpZGF0aW9uIHNpbGVudC1yZW5ldyBydW5uaW5nJyk7XHJcblxyXG4gICAgICAgIC8qKlxyXG4gICAgICAgICAgICBGaXJzdCB0aW1lOiBkZWxheSAxMCBzZWNvbmRzIHRvIGNhbGwgc2lsZW50UmVuZXdIZWFydEJlYXRDaGVja1xyXG4gICAgICAgICAgICBBZnRlcndhcmRzOiBSdW4gdGhpcyBjaGVjayBpbiBhIDUgc2Vjb25kIGludGVydmFsIG9ubHkgQUZURVIgdGhlIHByZXZpb3VzIG9wZXJhdGlvbiBlbmRzLlxyXG4gICAgICAgICAqL1xyXG4gICAgICAgIGNvbnN0IHNpbGVudFJlbmV3SGVhcnRCZWF0Q2hlY2sgPSAoKSA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZyhcclxuICAgICAgICAgICAgICAgICdzaWxlbnRSZW5ld0hlYXJ0QmVhdENoZWNrXFxyXFxuJyArXHJcbiAgICAgICAgICAgICAgICAgICAgYFxcdHNpbGVudFJlbmV3UnVubmluZzogJHt0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zaWxlbnRSZW5ld1J1bm5pbmcgPT09ICdydW5uaW5nJ31cXHJcXG5gICtcclxuICAgICAgICAgICAgICAgICAgICBgXFx0aWRUb2tlbjogJHshIXRoaXMuZ2V0SWRUb2tlbigpfVxcclxcbmAgK1xyXG4gICAgICAgICAgICAgICAgICAgIGBcXHRfdXNlckRhdGEudmFsdWU6ICR7ISF0aGlzLl91c2VyRGF0YS52YWx1ZX1gXHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIGlmICh0aGlzLl91c2VyRGF0YS52YWx1ZSAmJiB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zaWxlbnRSZW5ld1J1bm5pbmcgIT09ICdydW5uaW5nJyAmJiB0aGlzLmdldElkVG9rZW4oKSkge1xyXG4gICAgICAgICAgICAgICAgaWYgKFxyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5VmFsaWRhdGlvbi5pc1Rva2VuRXhwaXJlZCh0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5pZFRva2VuLCB0aGlzLmF1dGhDb25maWd1cmF0aW9uLnNpbGVudF9yZW5ld19vZmZzZXRfaW5fc2Vjb25kcylcclxuICAgICAgICAgICAgICAgICkge1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnSXNBdXRob3JpemVkOiBpZF90b2tlbiBpc1Rva2VuRXhwaXJlZCwgc3RhcnQgc2lsZW50IHJlbmV3IGlmIGFjdGl2ZScpO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zaWxlbnRfcmVuZXcpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yZWZyZXNoU2Vzc2lvbigpLnN1YnNjcmliZShcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICgpID0+IHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9zY2hlZHVsZWRIZWFydEJlYXQgPSBzZXRUaW1lb3V0KHNpbGVudFJlbmV3SGVhcnRCZWF0Q2hlY2ssIDMwMDApO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfSxcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIChlcnI6IGFueSkgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dFcnJvcignRXJyb3I6ICcgKyBlcnIpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3NjaGVkdWxlZEhlYXJ0QmVhdCA9IHNldFRpbWVvdXQoc2lsZW50UmVuZXdIZWFydEJlYXRDaGVjaywgMzAwMCk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC8qIEluIHRoaXMgc2l0dWF0aW9uLCB3ZSBzY2hlZHVsZSBhIGhlYXRiZWF0IGNoZWNrIG9ubHkgd2hlbiBzaWxlbnRSZW5ldyBpcyBmaW5pc2hlZC5cclxuICAgICAgICAgICAgICAgICAgICAgICAgV2UgZG9uJ3Qgd2FudCB0byBzY2hlZHVsZSBhbm90aGVyIGNoZWNrIHNvIHdlIGhhdmUgdG8gcmV0dXJuIGhlcmUgKi9cclxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucmVzZXRBdXRob3JpemF0aW9uRGF0YShmYWxzZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAvKiBEZWxheSAzIHNlY29uZHMgYW5kIGRvIHRoZSBuZXh0IGNoZWNrICovXHJcbiAgICAgICAgICAgIHRoaXMuX3NjaGVkdWxlZEhlYXJ0QmVhdCA9IHNldFRpbWVvdXQoc2lsZW50UmVuZXdIZWFydEJlYXRDaGVjaywgMzAwMCk7XHJcbiAgICAgICAgfTtcclxuXHJcbiAgICAgICAgdGhpcy56b25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcclxuICAgICAgICAgICAgLyogSW5pdGlhbCBoZWFydGJlYXQgY2hlY2sgKi9cclxuICAgICAgICAgICAgdGhpcy5fc2NoZWR1bGVkSGVhcnRCZWF0ID0gc2V0VGltZW91dChzaWxlbnRSZW5ld0hlYXJ0QmVhdENoZWNrLCAxMDAwMCk7XHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBzaWxlbnRSZW5ld0V2ZW50SGFuZGxlcihlOiBDdXN0b21FdmVudCkge1xyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1Zygnc2lsZW50UmVuZXdFdmVudEhhbmRsZXInKTtcclxuXHJcbiAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ucmVzcG9uc2VfdHlwZSA9PT0gJ2NvZGUnKSB7XHJcblxyXG4gICAgICAgICAgICBjb25zdCB1cmxQYXJ0cyA9IGUuZGV0YWlsLnRvU3RyaW5nKCkuc3BsaXQoJz8nKTtcclxuICAgICAgICAgICAgY29uc3QgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoe1xyXG4gICAgICAgICAgICAgICAgZnJvbVN0cmluZzogdXJsUGFydHNbMV1cclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgICAgIGNvbnN0IGNvZGUgPSBwYXJhbXMuZ2V0KCdjb2RlJyk7XHJcbiAgICAgICAgICAgIGNvbnN0IHN0YXRlID0gcGFyYW1zLmdldCgnc3RhdGUnKTtcclxuICAgICAgICAgICAgY29uc3Qgc2Vzc2lvbl9zdGF0ZSA9IHBhcmFtcy5nZXQoJ3Nlc3Npb25fc3RhdGUnKTtcclxuICAgICAgICAgICAgY29uc3QgZXJyb3IgPSBwYXJhbXMuZ2V0KCdlcnJvcicpO1xyXG4gICAgICAgICAgICBpZiAoY29kZSAmJiBzdGF0ZSkge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5yZXF1ZXN0VG9rZW5zV2l0aENvZGVQcm9jZWR1cmUoY29kZSwgc3RhdGUsIHNlc3Npb25fc3RhdGUpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIGlmIChlcnJvcikge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5fb25BdXRob3JpemF0aW9uUmVzdWx0Lm5leHQobmV3IEF1dGhvcml6YXRpb25SZXN1bHQoQXV0aG9yaXphdGlvblN0YXRlLnVuYXV0aG9yaXplZCwgVmFsaWRhdGlvblJlc3VsdC5Mb2dpblJlcXVpcmVkKSk7XHJcbiAgICAgICAgICAgICAgICB0aGlzLnJlc2V0QXV0aG9yaXphdGlvbkRhdGEoZmFsc2UpO1xyXG4gICAgICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aE5vbmNlID0gJyc7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoZS5kZXRhaWwudG9TdHJpbmcoKSk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgLy8gSW1wbGljaXRGbG93XHJcbiAgICAgICAgICAgIHRoaXMuYXV0aG9yaXplZEltcGxpY2l0Rmxvd0NhbGxiYWNrKGUuZGV0YWlsKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcbn1cclxuIl19