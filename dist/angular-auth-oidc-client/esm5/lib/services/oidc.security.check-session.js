/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable, NgZone } from '@angular/core';
import { from, Observable, Subject } from 'rxjs';
import { take } from 'rxjs/operators';
import { AuthConfiguration } from '../modules/auth.configuration';
import { IFrameService } from './existing-iframe.service';
import { LoggerService } from './oidc.logger.service';
import { OidcSecurityCommon } from './oidc.security.common';
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
        this._onCheckSessionChanged = new Subject();
    }
    Object.defineProperty(OidcSecurityCheckSession.prototype, "onCheckSessionChanged", {
        get: /**
         * @return {?}
         */
        function () {
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
        function (observer) {
            _this.sessionIframe.onload = (/**
             * @return {?}
             */
            function () {
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
        var _pollServerSessionRecur = (/**
         * @return {?}
         */
        function () {
            _this.init()
                .pipe(take(1))
                .subscribe((/**
             * @return {?}
             */
            function () {
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
        this.zone.runOutsideAngular((/**
         * @return {?}
         */
        function () {
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
        { type: Injectable }
    ];
    /** @nocollapse */
    OidcSecurityCheckSession.ctorParameters = function () { return [
        { type: AuthConfiguration },
        { type: OidcSecurityCommon },
        { type: LoggerService },
        { type: IFrameService },
        { type: NgZone }
    ]; };
    return OidcSecurityCheckSession;
}());
export { OidcSecurityCheckSession };
if (false) {
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.sessionIframe;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.iframeMessageEvent;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.authWellKnownEndpoints;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.scheduledHeartBeat;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.lastIFrameRefresh;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.outstandingMessages;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.heartBeatInterval;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.iframeRefreshInterval;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype._onCheckSessionChanged;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.authConfiguration;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.oidcSecurityCommon;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.loggerService;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.iFrameService;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityCheckSession.prototype.zone;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS5jaGVjay1zZXNzaW9uLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1hdXRoLW9pZGMtY2xpZW50LyIsInNvdXJjZXMiOlsibGliL3NlcnZpY2VzL29pZGMuc2VjdXJpdHkuY2hlY2stc2Vzc2lvbi50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDbkQsT0FBTyxFQUFFLElBQUksRUFBRSxVQUFVLEVBQVksT0FBTyxFQUFFLE1BQU0sTUFBTSxDQUFDO0FBQzNELE9BQU8sRUFBRSxJQUFJLEVBQUUsTUFBTSxnQkFBZ0IsQ0FBQztBQUV0QyxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSwrQkFBK0IsQ0FBQztBQUNsRSxPQUFPLEVBQUUsYUFBYSxFQUFFLE1BQU0sMkJBQTJCLENBQUM7QUFDMUQsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLHVCQUF1QixDQUFDO0FBQ3RELE9BQU8sRUFBRSxrQkFBa0IsRUFBRSxNQUFNLHdCQUF3QixDQUFDOztJQUV0RCxtQ0FBbUMsR0FBRyx5QkFBeUI7O0FBSXJFO0lBZ0JJLGtDQUNZLGlCQUFvQyxFQUNwQyxrQkFBc0MsRUFDdEMsYUFBNEIsRUFDNUIsYUFBNEIsRUFDNUIsSUFBWTtRQUpaLHNCQUFpQixHQUFqQixpQkFBaUIsQ0FBbUI7UUFDcEMsdUJBQWtCLEdBQWxCLGtCQUFrQixDQUFvQjtRQUN0QyxrQkFBYSxHQUFiLGFBQWEsQ0FBZTtRQUM1QixrQkFBYSxHQUFiLGFBQWEsQ0FBZTtRQUM1QixTQUFJLEdBQUosSUFBSSxDQUFRO1FBZmhCLHNCQUFpQixHQUFHLENBQUMsQ0FBQztRQUN0Qix3QkFBbUIsR0FBRyxDQUFDLENBQUM7UUFDeEIsc0JBQWlCLEdBQUcsSUFBSSxDQUFDO1FBQ3pCLDBCQUFxQixHQUFHLEtBQUssQ0FBQztRQUM5QiwyQkFBc0IsR0FBRyxJQUFJLE9BQU8sRUFB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Ozs7O0lBQ2pDLGlEQUEyQjs7Ozs7SUFDM0Isc0RBQWdDOzs7OztJQUNoQywwREFBbUU7Ozs7O0lBQ25FLHNEQUFnQzs7Ozs7SUFDaEMscURBQThCOzs7OztJQUM5Qix1REFBZ0M7Ozs7O0lBQ2hDLHFEQUFpQzs7Ozs7SUFDakMseURBQXNDOzs7OztJQUN0QywwREFBb0Q7Ozs7O0lBT2hELHFEQUE0Qzs7Ozs7SUFDNUMsc0RBQThDOzs7OztJQUM5QyxpREFBb0M7Ozs7O0lBQ3BDLGlEQUFvQzs7Ozs7SUFDcEMsd0NBQW9CIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmdab25lIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcbmltcG9ydCB7IGZyb20sIE9ic2VydmFibGUsIE9ic2VydmVyLCBTdWJqZWN0IH0gZnJvbSAncnhqcyc7XHJcbmltcG9ydCB7IHRha2UgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XHJcbmltcG9ydCB7IEF1dGhXZWxsS25vd25FbmRwb2ludHMgfSBmcm9tICcuLi9tb2RlbHMvYXV0aC53ZWxsLWtub3duLWVuZHBvaW50cyc7XHJcbmltcG9ydCB7IEF1dGhDb25maWd1cmF0aW9uIH0gZnJvbSAnLi4vbW9kdWxlcy9hdXRoLmNvbmZpZ3VyYXRpb24nO1xyXG5pbXBvcnQgeyBJRnJhbWVTZXJ2aWNlIH0gZnJvbSAnLi9leGlzdGluZy1pZnJhbWUuc2VydmljZSc7XHJcbmltcG9ydCB7IExvZ2dlclNlcnZpY2UgfSBmcm9tICcuL29pZGMubG9nZ2VyLnNlcnZpY2UnO1xyXG5pbXBvcnQgeyBPaWRjU2VjdXJpdHlDb21tb24gfSBmcm9tICcuL29pZGMuc2VjdXJpdHkuY29tbW9uJztcclxuXHJcbmNvbnN0IElGUkFNRV9GT1JfQ0hFQ0tfU0VTU0lPTl9JREVOVElGSUVSID0gJ215aUZyYW1lRm9yQ2hlY2tTZXNzaW9uJztcclxuXHJcbi8vIGh0dHA6Ly9vcGVuaWQubmV0L3NwZWNzL29wZW5pZC1jb25uZWN0LXNlc3Npb24tMV8wLUlENC5odG1sXHJcblxyXG5ASW5qZWN0YWJsZSgpXHJcbmV4cG9ydCBjbGFzcyBPaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24ge1xyXG4gICAgcHJpdmF0ZSBzZXNzaW9uSWZyYW1lOiBhbnk7XHJcbiAgICBwcml2YXRlIGlmcmFtZU1lc3NhZ2VFdmVudDogYW55O1xyXG4gICAgcHJpdmF0ZSBhdXRoV2VsbEtub3duRW5kcG9pbnRzOiBBdXRoV2VsbEtub3duRW5kcG9pbnRzIHwgdW5kZWZpbmVkO1xyXG4gICAgcHJpdmF0ZSBzY2hlZHVsZWRIZWFydEJlYXQ6IGFueTtcclxuICAgIHByaXZhdGUgbGFzdElGcmFtZVJlZnJlc2ggPSAwO1xyXG4gICAgcHJpdmF0ZSBvdXRzdGFuZGluZ01lc3NhZ2VzID0gMDtcclxuICAgIHByaXZhdGUgaGVhcnRCZWF0SW50ZXJ2YWwgPSAzMDAwO1xyXG4gICAgcHJpdmF0ZSBpZnJhbWVSZWZyZXNoSW50ZXJ2YWwgPSA2MDAwMDtcclxuICAgIHByaXZhdGUgX29uQ2hlY2tTZXNzaW9uQ2hhbmdlZCA9IG5ldyBTdWJqZWN0PGFueT4oKTtcclxuXHJcbiAgICBwdWJsaWMgZ2V0IG9uQ2hlY2tTZXNzaW9uQ2hhbmdlZCgpOiBPYnNlcnZhYmxlPGFueT4ge1xyXG4gICAgICAgIHJldHVybiB0aGlzLl9vbkNoZWNrU2Vzc2lvbkNoYW5nZWQuYXNPYnNlcnZhYmxlKCk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3RydWN0b3IoXHJcbiAgICAgICAgcHJpdmF0ZSBhdXRoQ29uZmlndXJhdGlvbjogQXV0aENvbmZpZ3VyYXRpb24sXHJcbiAgICAgICAgcHJpdmF0ZSBvaWRjU2VjdXJpdHlDb21tb246IE9pZGNTZWN1cml0eUNvbW1vbixcclxuICAgICAgICBwcml2YXRlIGxvZ2dlclNlcnZpY2U6IExvZ2dlclNlcnZpY2UsXHJcbiAgICAgICAgcHJpdmF0ZSBpRnJhbWVTZXJ2aWNlOiBJRnJhbWVTZXJ2aWNlLFxyXG4gICAgICAgIHByaXZhdGUgem9uZTogTmdab25lXHJcbiAgICApIHt9XHJcblxyXG4gICAgc2V0dXBNb2R1bGUoYXV0aFdlbGxLbm93bkVuZHBvaW50czogQXV0aFdlbGxLbm93bkVuZHBvaW50cykge1xyXG4gICAgICAgIHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cyA9IE9iamVjdC5hc3NpZ24oe30sIGF1dGhXZWxsS25vd25FbmRwb2ludHMpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgZG9lc1Nlc3Npb25FeGlzdCgpOiBib29sZWFuIHtcclxuICAgICAgICBjb25zdCBleGlzdGluZ0lGcmFtZSA9IHRoaXMuaUZyYW1lU2VydmljZS5nZXRFeGlzdGluZ0lGcmFtZShJRlJBTUVfRk9SX0NIRUNLX1NFU1NJT05fSURFTlRJRklFUik7XHJcblxyXG4gICAgICAgIGlmICghZXhpc3RpbmdJRnJhbWUpIHtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgdGhpcy5zZXNzaW9uSWZyYW1lID0gZXhpc3RpbmdJRnJhbWU7XHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBpbml0KCkge1xyXG4gICAgICAgIGlmICh0aGlzLmxhc3RJRnJhbWVSZWZyZXNoICsgdGhpcy5pZnJhbWVSZWZyZXNoSW50ZXJ2YWwgPiBEYXRlLm5vdygpKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBmcm9tKFt0aGlzXSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoIXRoaXMuZG9lc1Nlc3Npb25FeGlzdCgpKSB7XHJcbiAgICAgICAgICAgIHRoaXMuc2Vzc2lvbklmcmFtZSA9IHRoaXMuaUZyYW1lU2VydmljZS5hZGRJRnJhbWVUb1dpbmRvd0JvZHkoSUZSQU1FX0ZPUl9DSEVDS19TRVNTSU9OX0lERU5USUZJRVIpO1xyXG4gICAgICAgICAgICB0aGlzLmlmcmFtZU1lc3NhZ2VFdmVudCA9IHRoaXMubWVzc2FnZUhhbmRsZXIuYmluZCh0aGlzKTtcclxuICAgICAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCB0aGlzLmlmcmFtZU1lc3NhZ2VFdmVudCwgZmFsc2UpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cykge1xyXG4gICAgICAgICAgICB0aGlzLnNlc3Npb25JZnJhbWUuY29udGVudFdpbmRvdy5sb2NhdGlvbi5yZXBsYWNlKHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cy5jaGVja19zZXNzaW9uX2lmcmFtZSk7XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2luaXQgY2hlY2sgc2Vzc2lvbjogYXV0aFdlbGxLbm93bkVuZHBvaW50cyBpcyB1bmRlZmluZWQnKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiBPYnNlcnZhYmxlLmNyZWF0ZSgob2JzZXJ2ZXI6IE9ic2VydmVyPE9pZGNTZWN1cml0eUNoZWNrU2Vzc2lvbj4pID0+IHtcclxuICAgICAgICAgICAgdGhpcy5zZXNzaW9uSWZyYW1lLm9ubG9hZCA9ICgpID0+IHtcclxuICAgICAgICAgICAgICAgIHRoaXMubGFzdElGcmFtZVJlZnJlc2ggPSBEYXRlLm5vdygpO1xyXG4gICAgICAgICAgICAgICAgb2JzZXJ2ZXIubmV4dCh0aGlzKTtcclxuICAgICAgICAgICAgICAgIG9ic2VydmVyLmNvbXBsZXRlKCk7XHJcbiAgICAgICAgICAgIH07XHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgc3RhcnRDaGVja2luZ1Nlc3Npb24oY2xpZW50SWQ6IHN0cmluZyk6IHZvaWQge1xyXG4gICAgICAgIGlmICh0aGlzLnNjaGVkdWxlZEhlYXJ0QmVhdCkge1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICB0aGlzLnBvbGxTZXJ2ZXJTZXNzaW9uKGNsaWVudElkKTtcclxuICAgIH1cclxuXHJcbiAgICBzdG9wQ2hlY2tpbmdTZXNzaW9uKCk6IHZvaWQge1xyXG4gICAgICAgIGlmICghdGhpcy5zY2hlZHVsZWRIZWFydEJlYXQpIHtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgdGhpcy5jbGVhclNjaGVkdWxlZEhlYXJ0QmVhdCgpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgcG9sbFNlcnZlclNlc3Npb24oY2xpZW50SWQ6IHN0cmluZykge1xyXG4gICAgICAgIGNvbnN0IF9wb2xsU2VydmVyU2Vzc2lvblJlY3VyID0gKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmluaXQoKVxyXG4gICAgICAgICAgICAgICAgLnBpcGUodGFrZSgxKSlcclxuICAgICAgICAgICAgICAgIC5zdWJzY3JpYmUoKCkgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLnNlc3Npb25JZnJhbWUgJiYgY2xpZW50SWQpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKHRoaXMuc2Vzc2lvbklmcmFtZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHNlc3Npb25fc3RhdGUgPSB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zZXNzaW9uU3RhdGU7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChzZXNzaW9uX3N0YXRlKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLm91dHN0YW5kaW5nTWVzc2FnZXMrKztcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc2Vzc2lvbklmcmFtZS5jb250ZW50V2luZG93LnBvc3RNZXNzYWdlKGNsaWVudElkICsgJyAnICsgc2Vzc2lvbl9zdGF0ZSwgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zdHNTZXJ2ZXIpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdPaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24gcG9sbFNlcnZlclNlc3Npb24gc2Vzc2lvbl9zdGF0ZSBpcyBibGFuaycpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fb25DaGVja1Nlc3Npb25DaGFuZ2VkLm5leHQoKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdPaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24gcG9sbFNlcnZlclNlc3Npb24gc2Vzc2lvbklmcmFtZSBkb2VzIG5vdCBleGlzdCcpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoY2xpZW50SWQpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcodGhpcy5zZXNzaW9uSWZyYW1lKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gdGhpcy5pbml0KCk7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICAvLyBhZnRlciBzZW5kaW5nIHRocmVlIG1lc3NhZ2VzIHdpdGggbm8gcmVzcG9uc2UsIGZhaWwuXHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMub3V0c3RhbmRpbmdNZXNzYWdlcyA+IDMpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0Vycm9yKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYE9pZGNTZWN1cml0eUNoZWNrU2Vzc2lvbiBub3QgcmVjZWl2aW5nIGNoZWNrIHNlc3Npb24gcmVzcG9uc2UgbWVzc2FnZXMuIE91dHN0YW5kaW5nIG1lc3NhZ2VzOiAke1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMub3V0c3RhbmRpbmdNZXNzYWdlc1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfS4gU2VydmVyIHVucmVhY2hhYmxlP2BcclxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fb25DaGVja1Nlc3Npb25DaGFuZ2VkLm5leHQoKTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuc2NoZWR1bGVkSGVhcnRCZWF0ID0gc2V0VGltZW91dChfcG9sbFNlcnZlclNlc3Npb25SZWN1ciwgdGhpcy5oZWFydEJlYXRJbnRlcnZhbCk7XHJcbiAgICAgICAgICAgICAgICB9KTtcclxuICAgICAgICB9O1xyXG5cclxuICAgICAgICB0aGlzLm91dHN0YW5kaW5nTWVzc2FnZXMgPSAwO1xyXG5cclxuICAgICAgICB0aGlzLnpvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLnNjaGVkdWxlZEhlYXJ0QmVhdCA9IHNldFRpbWVvdXQoX3BvbGxTZXJ2ZXJTZXNzaW9uUmVjdXIsIHRoaXMuaGVhcnRCZWF0SW50ZXJ2YWwpO1xyXG4gICAgICAgIH0pO1xyXG4gICAgfVxyXG4gICAgcHJpdmF0ZSBjbGVhclNjaGVkdWxlZEhlYXJ0QmVhdCgpIHtcclxuICAgICAgICBjbGVhclRpbWVvdXQodGhpcy5zY2hlZHVsZWRIZWFydEJlYXQpO1xyXG4gICAgICAgIHRoaXMuc2NoZWR1bGVkSGVhcnRCZWF0ID0gbnVsbDtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIG1lc3NhZ2VIYW5kbGVyKGU6IGFueSkge1xyXG4gICAgICAgIHRoaXMub3V0c3RhbmRpbmdNZXNzYWdlcyA9IDA7XHJcbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbklmcmFtZSAmJiBlLm9yaWdpbiA9PT0gdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zdHNTZXJ2ZXIgJiYgZS5zb3VyY2UgPT09IHRoaXMuc2Vzc2lvbklmcmFtZS5jb250ZW50V2luZG93KSB7XHJcbiAgICAgICAgICAgIGlmIChlLmRhdGEgPT09ICdlcnJvcicpIHtcclxuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdlcnJvciBmcm9tIGNoZWNrc2Vzc2lvbiBtZXNzYWdlSGFuZGxlcicpO1xyXG4gICAgICAgICAgICB9IGVsc2UgaWYgKGUuZGF0YSA9PT0gJ2NoYW5nZWQnKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLl9vbkNoZWNrU2Vzc2lvbkNoYW5nZWQubmV4dCgpO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKGUuZGF0YSArICcgZnJvbSBjaGVja3Nlc3Npb24gbWVzc2FnZUhhbmRsZXInKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgIH1cclxufVxyXG4iXX0=