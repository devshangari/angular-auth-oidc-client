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
const IFRAME_FOR_CHECK_SESSION_IDENTIFIER = 'myiFrameForCheckSession';
// http://openid.net/specs/openid-connect-session-1_0-ID4.html
export class OidcSecurityCheckSession {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS5jaGVjay1zZXNzaW9uLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1hdXRoLW9pZGMtY2xpZW50LyIsInNvdXJjZXMiOlsibGliL3NlcnZpY2VzL29pZGMuc2VjdXJpdHkuY2hlY2stc2Vzc2lvbi50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDbkQsT0FBTyxFQUFFLElBQUksRUFBRSxVQUFVLEVBQVksT0FBTyxFQUFFLE1BQU0sTUFBTSxDQUFDO0FBQzNELE9BQU8sRUFBRSxJQUFJLEVBQUUsTUFBTSxnQkFBZ0IsQ0FBQztBQUV0QyxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSwrQkFBK0IsQ0FBQztBQUNsRSxPQUFPLEVBQUUsYUFBYSxFQUFFLE1BQU0sMkJBQTJCLENBQUM7QUFDMUQsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLHVCQUF1QixDQUFDO0FBQ3RELE9BQU8sRUFBRSxrQkFBa0IsRUFBRSxNQUFNLHdCQUF3QixDQUFDOztNQUV0RCxtQ0FBbUMsR0FBRyx5QkFBeUI7O0FBS3JFLE1BQU0sT0FBTyx3QkFBd0I7Ozs7Ozs7O0lBZWpDLFlBQ1ksaUJBQW9DLEVBQ3BDLGtCQUFzQyxFQUN0QyxhQUE0QixFQUM1QixhQUE0QixFQUM1QixJQUFZO1FBSlosc0JBQWlCLEdBQWpCLGlCQUFpQixDQUFtQjtRQUNwQyx1QkFBa0IsR0FBbEIsa0JBQWtCLENBQW9CO1FBQ3RDLGtCQUFhLEdBQWIsYUFBYSxDQUFlO1FBQzVCLGtCQUFhLEdBQWIsYUFBYSxDQUFlO1FBQzVCLFNBQUksR0FBSixJQUFJLENBQVE7UUFmaEIsc0JBQWlCLEdBQUcsQ0FBQyxDQUFDO1FBQ3RCLHdCQUFtQixHQUFHLENBQUMsQ0FBQztRQUN4QixzQkFBaUIsR0FBRyxJQUFJLENBQUM7UUFDekIsMEJBQXFCLEdBQUcsS0FBSyxDQUFDO1FBQzlCLDJC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QUM5Qix1REFBZ0M7Ozs7O0lBQ2hDLHFEQUFpQzs7Ozs7SUFDakMseURBQXNDOzs7OztJQUN0QywwREFBb0Q7Ozs7O0lBT2hELHFEQUE0Qzs7Ozs7SUFDNUMsc0RBQThDOzs7OztJQUM5QyxpREFBb0M7Ozs7O0lBQ3BDLGlEQUFvQzs7Ozs7SUFDcEMsd0NBQW9CIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmdab25lIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcbmltcG9ydCB7IGZyb20sIE9ic2VydmFibGUsIE9ic2VydmVyLCBTdWJqZWN0IH0gZnJvbSAncnhqcyc7XHJcbmltcG9ydCB7IHRha2UgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XHJcbmltcG9ydCB7IEF1dGhXZWxsS25vd25FbmRwb2ludHMgfSBmcm9tICcuLi9tb2RlbHMvYXV0aC53ZWxsLWtub3duLWVuZHBvaW50cyc7XHJcbmltcG9ydCB7IEF1dGhDb25maWd1cmF0aW9uIH0gZnJvbSAnLi4vbW9kdWxlcy9hdXRoLmNvbmZpZ3VyYXRpb24nO1xyXG5pbXBvcnQgeyBJRnJhbWVTZXJ2aWNlIH0gZnJvbSAnLi9leGlzdGluZy1pZnJhbWUuc2VydmljZSc7XHJcbmltcG9ydCB7IExvZ2dlclNlcnZpY2UgfSBmcm9tICcuL29pZGMubG9nZ2VyLnNlcnZpY2UnO1xyXG5pbXBvcnQgeyBPaWRjU2VjdXJpdHlDb21tb24gfSBmcm9tICcuL29pZGMuc2VjdXJpdHkuY29tbW9uJztcclxuXHJcbmNvbnN0IElGUkFNRV9GT1JfQ0hFQ0tfU0VTU0lPTl9JREVOVElGSUVSID0gJ215aUZyYW1lRm9yQ2hlY2tTZXNzaW9uJztcclxuXHJcbi8vIGh0dHA6Ly9vcGVuaWQubmV0L3NwZWNzL29wZW5pZC1jb25uZWN0LXNlc3Npb24tMV8wLUlENC5odG1sXHJcblxyXG5ASW5qZWN0YWJsZSgpXHJcbmV4cG9ydCBjbGFzcyBPaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24ge1xyXG4gICAgcHJpdmF0ZSBzZXNzaW9uSWZyYW1lOiBhbnk7XHJcbiAgICBwcml2YXRlIGlmcmFtZU1lc3NhZ2VFdmVudDogYW55O1xyXG4gICAgcHJpdmF0ZSBhdXRoV2VsbEtub3duRW5kcG9pbnRzOiBBdXRoV2VsbEtub3duRW5kcG9pbnRzIHwgdW5kZWZpbmVkO1xyXG4gICAgcHJpdmF0ZSBzY2hlZHVsZWRIZWFydEJlYXQ6IGFueTtcclxuICAgIHByaXZhdGUgbGFzdElGcmFtZVJlZnJlc2ggPSAwO1xyXG4gICAgcHJpdmF0ZSBvdXRzdGFuZGluZ01lc3NhZ2VzID0gMDtcclxuICAgIHByaXZhdGUgaGVhcnRCZWF0SW50ZXJ2YWwgPSAzMDAwO1xyXG4gICAgcHJpdmF0ZSBpZnJhbWVSZWZyZXNoSW50ZXJ2YWwgPSA2MDAwMDtcclxuICAgIHByaXZhdGUgX29uQ2hlY2tTZXNzaW9uQ2hhbmdlZCA9IG5ldyBTdWJqZWN0PGFueT4oKTtcclxuXHJcbiAgICBwdWJsaWMgZ2V0IG9uQ2hlY2tTZXNzaW9uQ2hhbmdlZCgpOiBPYnNlcnZhYmxlPGFueT4ge1xyXG4gICAgICAgIHJldHVybiB0aGlzLl9vbkNoZWNrU2Vzc2lvbkNoYW5nZWQuYXNPYnNlcnZhYmxlKCk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3RydWN0b3IoXHJcbiAgICAgICAgcHJpdmF0ZSBhdXRoQ29uZmlndXJhdGlvbjogQXV0aENvbmZpZ3VyYXRpb24sXHJcbiAgICAgICAgcHJpdmF0ZSBvaWRjU2VjdXJpdHlDb21tb246IE9pZGNTZWN1cml0eUNvbW1vbixcclxuICAgICAgICBwcml2YXRlIGxvZ2dlclNlcnZpY2U6IExvZ2dlclNlcnZpY2UsXHJcbiAgICAgICAgcHJpdmF0ZSBpRnJhbWVTZXJ2aWNlOiBJRnJhbWVTZXJ2aWNlLFxyXG4gICAgICAgIHByaXZhdGUgem9uZTogTmdab25lXHJcbiAgICApIHt9XHJcblxyXG4gICAgc2V0dXBNb2R1bGUoYXV0aFdlbGxLbm93bkVuZHBvaW50czogQXV0aFdlbGxLbm93bkVuZHBvaW50cykge1xyXG4gICAgICAgIHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cyA9IE9iamVjdC5hc3NpZ24oe30sIGF1dGhXZWxsS25vd25FbmRwb2ludHMpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgZG9lc1Nlc3Npb25FeGlzdCgpOiBib29sZWFuIHtcclxuICAgICAgICBjb25zdCBleGlzdGluZ0lGcmFtZSA9IHRoaXMuaUZyYW1lU2VydmljZS5nZXRFeGlzdGluZ0lGcmFtZShJRlJBTUVfRk9SX0NIRUNLX1NFU1NJT05fSURFTlRJRklFUik7XHJcblxyXG4gICAgICAgIGlmICghZXhpc3RpbmdJRnJhbWUpIHtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgdGhpcy5zZXNzaW9uSWZyYW1lID0gZXhpc3RpbmdJRnJhbWU7XHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBpbml0KCkge1xyXG4gICAgICAgIGlmICh0aGlzLmxhc3RJRnJhbWVSZWZyZXNoICsgdGhpcy5pZnJhbWVSZWZyZXNoSW50ZXJ2YWwgPiBEYXRlLm5vdygpKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBmcm9tKFt0aGlzXSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoIXRoaXMuZG9lc1Nlc3Npb25FeGlzdCgpKSB7XHJcbiAgICAgICAgICAgIHRoaXMuc2Vzc2lvbklmcmFtZSA9IHRoaXMuaUZyYW1lU2VydmljZS5hZGRJRnJhbWVUb1dpbmRvd0JvZHkoSUZSQU1FX0ZPUl9DSEVDS19TRVNTSU9OX0lERU5USUZJRVIpO1xyXG4gICAgICAgICAgICB0aGlzLmlmcmFtZU1lc3NhZ2VFdmVudCA9IHRoaXMubWVzc2FnZUhhbmRsZXIuYmluZCh0aGlzKTtcclxuICAgICAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCB0aGlzLmlmcmFtZU1lc3NhZ2VFdmVudCwgZmFsc2UpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cykge1xyXG4gICAgICAgICAgICB0aGlzLnNlc3Npb25JZnJhbWUuY29udGVudFdpbmRvdy5sb2NhdGlvbi5yZXBsYWNlKHRoaXMuYXV0aFdlbGxLbm93bkVuZHBvaW50cy5jaGVja19zZXNzaW9uX2lmcmFtZSk7XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2luaXQgY2hlY2sgc2Vzc2lvbjogYXV0aFdlbGxLbm93bkVuZHBvaW50cyBpcyB1bmRlZmluZWQnKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiBPYnNlcnZhYmxlLmNyZWF0ZSgob2JzZXJ2ZXI6IE9ic2VydmVyPE9pZGNTZWN1cml0eUNoZWNrU2Vzc2lvbj4pID0+IHtcclxuICAgICAgICAgICAgdGhpcy5zZXNzaW9uSWZyYW1lLm9ubG9hZCA9ICgpID0+IHtcclxuICAgICAgICAgICAgICAgIHRoaXMubGFzdElGcmFtZVJlZnJlc2ggPSBEYXRlLm5vdygpO1xyXG4gICAgICAgICAgICAgICAgb2JzZXJ2ZXIubmV4dCh0aGlzKTtcclxuICAgICAgICAgICAgICAgIG9ic2VydmVyLmNvbXBsZXRlKCk7XHJcbiAgICAgICAgICAgIH07XHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgc3RhcnRDaGVja2luZ1Nlc3Npb24oY2xpZW50SWQ6IHN0cmluZyk6IHZvaWQge1xyXG4gICAgICAgIGlmICh0aGlzLnNjaGVkdWxlZEhlYXJ0QmVhdCkge1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICB0aGlzLnBvbGxTZXJ2ZXJTZXNzaW9uKGNsaWVudElkKTtcclxuICAgIH1cclxuXHJcbiAgICBzdG9wQ2hlY2tpbmdTZXNzaW9uKCk6IHZvaWQge1xyXG4gICAgICAgIGlmICghdGhpcy5zY2hlZHVsZWRIZWFydEJlYXQpIHtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgdGhpcy5jbGVhclNjaGVkdWxlZEhlYXJ0QmVhdCgpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgcG9sbFNlcnZlclNlc3Npb24oY2xpZW50SWQ6IHN0cmluZykge1xyXG4gICAgICAgIGNvbnN0IF9wb2xsU2VydmVyU2Vzc2lvblJlY3VyID0gKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmluaXQoKVxyXG4gICAgICAgICAgICAgICAgLnBpcGUodGFrZSgxKSlcclxuICAgICAgICAgICAgICAgIC5zdWJzY3JpYmUoKCkgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLnNlc3Npb25JZnJhbWUgJiYgY2xpZW50SWQpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKHRoaXMuc2Vzc2lvbklmcmFtZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHNlc3Npb25fc3RhdGUgPSB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5zZXNzaW9uU3RhdGU7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChzZXNzaW9uX3N0YXRlKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLm91dHN0YW5kaW5nTWVzc2FnZXMrKztcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc2Vzc2lvbklmcmFtZS5jb250ZW50V2luZG93LnBvc3RNZXNzYWdlKGNsaWVudElkICsgJyAnICsgc2Vzc2lvbl9zdGF0ZSwgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zdHNTZXJ2ZXIpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdPaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24gcG9sbFNlcnZlclNlc3Npb24gc2Vzc2lvbl9zdGF0ZSBpcyBibGFuaycpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fb25DaGVja1Nlc3Npb25DaGFuZ2VkLm5leHQoKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdPaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24gcG9sbFNlcnZlclNlc3Npb24gc2Vzc2lvbklmcmFtZSBkb2VzIG5vdCBleGlzdCcpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoY2xpZW50SWQpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcodGhpcy5zZXNzaW9uSWZyYW1lKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gdGhpcy5pbml0KCk7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICAvLyBhZnRlciBzZW5kaW5nIHRocmVlIG1lc3NhZ2VzIHdpdGggbm8gcmVzcG9uc2UsIGZhaWwuXHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMub3V0c3RhbmRpbmdNZXNzYWdlcyA+IDMpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0Vycm9yKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYE9pZGNTZWN1cml0eUNoZWNrU2Vzc2lvbiBub3QgcmVjZWl2aW5nIGNoZWNrIHNlc3Npb24gcmVzcG9uc2UgbWVzc2FnZXMuIE91dHN0YW5kaW5nIG1lc3NhZ2VzOiAke1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMub3V0c3RhbmRpbmdNZXNzYWdlc1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfS4gU2VydmVyIHVucmVhY2hhYmxlP2BcclxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fb25DaGVja1Nlc3Npb25DaGFuZ2VkLm5leHQoKTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuc2NoZWR1bGVkSGVhcnRCZWF0ID0gc2V0VGltZW91dChfcG9sbFNlcnZlclNlc3Npb25SZWN1ciwgdGhpcy5oZWFydEJlYXRJbnRlcnZhbCk7XHJcbiAgICAgICAgICAgICAgICB9KTtcclxuICAgICAgICB9O1xyXG5cclxuICAgICAgICB0aGlzLm91dHN0YW5kaW5nTWVzc2FnZXMgPSAwO1xyXG5cclxuICAgICAgICB0aGlzLnpvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLnNjaGVkdWxlZEhlYXJ0QmVhdCA9IHNldFRpbWVvdXQoX3BvbGxTZXJ2ZXJTZXNzaW9uUmVjdXIsIHRoaXMuaGVhcnRCZWF0SW50ZXJ2YWwpO1xyXG4gICAgICAgIH0pO1xyXG4gICAgfVxyXG4gICAgcHJpdmF0ZSBjbGVhclNjaGVkdWxlZEhlYXJ0QmVhdCgpIHtcclxuICAgICAgICBjbGVhclRpbWVvdXQodGhpcy5zY2hlZHVsZWRIZWFydEJlYXQpO1xyXG4gICAgICAgIHRoaXMuc2NoZWR1bGVkSGVhcnRCZWF0ID0gbnVsbDtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIG1lc3NhZ2VIYW5kbGVyKGU6IGFueSkge1xyXG4gICAgICAgIHRoaXMub3V0c3RhbmRpbmdNZXNzYWdlcyA9IDA7XHJcbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbklmcmFtZSAmJiBlLm9yaWdpbiA9PT0gdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5zdHNTZXJ2ZXIgJiYgZS5zb3VyY2UgPT09IHRoaXMuc2Vzc2lvbklmcmFtZS5jb250ZW50V2luZG93KSB7XHJcbiAgICAgICAgICAgIGlmIChlLmRhdGEgPT09ICdlcnJvcicpIHtcclxuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdlcnJvciBmcm9tIGNoZWNrc2Vzc2lvbiBtZXNzYWdlSGFuZGxlcicpO1xyXG4gICAgICAgICAgICB9IGVsc2UgaWYgKGUuZGF0YSA9PT0gJ2NoYW5nZWQnKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLl9vbkNoZWNrU2Vzc2lvbkNoYW5nZWQubmV4dCgpO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKGUuZGF0YSArICcgZnJvbSBjaGVja3Nlc3Npb24gbWVzc2FnZUhhbmRsZXInKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgIH1cclxufVxyXG4iXX0=