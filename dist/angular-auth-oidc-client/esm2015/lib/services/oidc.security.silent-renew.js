/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { IFrameService } from './existing-iframe.service';
import { LoggerService } from './oidc.logger.service';
/** @type {?} */
const IFRAME_FOR_SILENT_RENEW_IDENTIFIER = 'myiFrameForSilentRenew';
export class OidcSecuritySilentRenew {
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
if (false) {
    /**
     * @type {?}
     * @private
     */
    OidcSecuritySilentRenew.prototype.sessionIframe;
    /**
     * @type {?}
     * @private
     */
    OidcSecuritySilentRenew.prototype.isRenewInitialized;
    /**
     * @type {?}
     * @private
     */
    OidcSecuritySilentRenew.prototype.loggerService;
    /**
     * @type {?}
     * @private
     */
    OidcSecuritySilentRenew.prototype.iFrameService;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS5zaWxlbnQtcmVuZXcuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLWF1dGgtb2lkYy1jbGllbnQvIiwic291cmNlcyI6WyJsaWIvc2VydmljZXMvb2lkYy5zZWN1cml0eS5zaWxlbnQtcmVuZXcudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7OztBQUFBLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLFVBQVUsRUFBWSxNQUFNLE1BQU0sQ0FBQztBQUM1QyxPQUFPLEVBQUUsYUFBYSxFQUFFLE1BQU0sMkJBQTJCLENBQUM7QUFDMUQsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLHVCQUF1QixDQUFDOztNQUVoRCxrQ0FBa0MsR0FBRyx3QkFBd0I7QUFHbkUsTUFBTSxPQUFPLHVCQUF1Qjs7Ozs7SUFJaEMsWUFBb0IsYUFBNEIsRUFBVSxhQUE0QjtRQUFsRSxrQkFBYSxHQUFiLGFBQWEsQ0FBZTtRQUFVLGtCQUFhLEdBQWIsYUFBYSxDQUFlO1FBRjlFLHVCQUFrQixHQUFHLEtBQUssQ0FBQztJQUVzRCxDQUFDOzs7O0lBRTFGLFNBQVM7O2NBQ0MsY0FBYyxHQUFHLElBQUksQ0FBQyxhQUFhLENBQUMsaUJBQWlCLENBQUMsa0NBQWtDLENBQUM7UUFFL0YsSUFBSSxDQUFDLGNBQWMsRUFBRTtZQUNqQixJQUFJLENBQUMsYUFBYSxDQUFDLHFCQUFxQixDQUFDLGtDQUFrQyxDQUFDLENBQUM7U0FDaEY7UUFFRCxJQUFJLENBQUMsa0JBQWtCLEdBQUcsSUFBSSxDQUFDO0lBQ25DLENBQUM7Ozs7O0lBRUQsVUFBVSxDQUFDLEdBQVc7UUFDbEIsSUFBSSxDQUFDLElBQUksQ0FBQyxrQkFBa0IsRUFBRTtZQUMxQixJQUFJLENBQUMsU0FBUyxFQUFFLENBQUM7U0FDcEI7UUFFRCxJQUFJLENBQUMsYUFBYSxHQUFHLElBQUksQ0FBQyxhQUFhLENBQUMsaUJBQWlCLENBQUMsa0NBQWtDLENBQUMsQ0FBQztRQUU5RixJQUFJLENBQUMsYUFBYSxDQUFDLFFBQVEsQ0FBQyxxQkFBcUIsR0FBRyxHQUFHLENBQUMsQ0FBQztRQUN6RCxJQUFJLENBQUMsYUFBYSxDQUFDLGFBQWEsQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBRXZELE9BQU8sVUFBVSxDQUFDLE1BQU07Ozs7UUFBQyxDQUFDLFFBQXVCLEVBQUUsRUFBRTtZQUNqRCxJQUFJLENBQUMsYUFBYSxDQUFDLE1BQU07OztZQUFHLEdBQUcsRUFBRTtnQkFDN0IsUUFBUSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQztnQkFDcEIsUUFBUSxDQUFDLFFBQVEsRUFBRSxDQUFDO1lBQ3hCLENBQUMsQ0FBQSxDQUFDO1FBQ04sQ0FBQyxFQUFDLENBQUM7SUFDUCxDQUFDOzs7WUFqQ0osVUFBVTs7OztZQUpGLGFBQWE7WUFEYixhQUFhOzs7Ozs7O0lBT2xCLGdEQUEyQjs7Ozs7SUFDM0IscURBQW1DOzs7OztJQUV2QixnREFBb0M7Ozs7O0lBQUUsZ0RBQW9DIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xyXG5pbXBvcnQgeyBPYnNlcnZhYmxlLCBPYnNlcnZlciB9IGZyb20gJ3J4anMnO1xyXG5pbXBvcnQgeyBJRnJhbWVTZXJ2aWNlIH0gZnJvbSAnLi9leGlzdGluZy1pZnJhbWUuc2VydmljZSc7XHJcbmltcG9ydCB7IExvZ2dlclNlcnZpY2UgfSBmcm9tICcuL29pZGMubG9nZ2VyLnNlcnZpY2UnO1xyXG5cclxuY29uc3QgSUZSQU1FX0ZPUl9TSUxFTlRfUkVORVdfSURFTlRJRklFUiA9ICdteWlGcmFtZUZvclNpbGVudFJlbmV3JztcclxuXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGNsYXNzIE9pZGNTZWN1cml0eVNpbGVudFJlbmV3IHtcclxuICAgIHByaXZhdGUgc2Vzc2lvbklmcmFtZTogYW55O1xyXG4gICAgcHJpdmF0ZSBpc1JlbmV3SW5pdGlhbGl6ZWQgPSBmYWxzZTtcclxuXHJcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGxvZ2dlclNlcnZpY2U6IExvZ2dlclNlcnZpY2UsIHByaXZhdGUgaUZyYW1lU2VydmljZTogSUZyYW1lU2VydmljZSkge31cclxuXHJcbiAgICBpbml0UmVuZXcoKSB7XHJcbiAgICAgICAgY29uc3QgZXhpc3RpbmdJRnJhbWUgPSB0aGlzLmlGcmFtZVNlcnZpY2UuZ2V0RXhpc3RpbmdJRnJhbWUoSUZSQU1FX0ZPUl9TSUxFTlRfUkVORVdfSURFTlRJRklFUik7XHJcblxyXG4gICAgICAgIGlmICghZXhpc3RpbmdJRnJhbWUpIHtcclxuICAgICAgICAgICAgdGhpcy5pRnJhbWVTZXJ2aWNlLmFkZElGcmFtZVRvV2luZG93Qm9keShJRlJBTUVfRk9SX1NJTEVOVF9SRU5FV19JREVOVElGSUVSKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHRoaXMuaXNSZW5ld0luaXRpYWxpemVkID0gdHJ1ZTtcclxuICAgIH1cclxuXHJcbiAgICBzdGFydFJlbmV3KHVybDogc3RyaW5nKTogT2JzZXJ2YWJsZTxhbnk+IHtcclxuICAgICAgICBpZiAoIXRoaXMuaXNSZW5ld0luaXRpYWxpemVkKSB7XHJcbiAgICAgICAgICAgIHRoaXMuaW5pdFJlbmV3KCk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICB0aGlzLnNlc3Npb25JZnJhbWUgPSB0aGlzLmlGcmFtZVNlcnZpY2UuZ2V0RXhpc3RpbmdJRnJhbWUoSUZSQU1FX0ZPUl9TSUxFTlRfUkVORVdfSURFTlRJRklFUik7XHJcblxyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1Zygnc3RhcnRSZW5ldyBmb3IgVVJMOicgKyB1cmwpO1xyXG4gICAgICAgIHRoaXMuc2Vzc2lvbklmcmFtZS5jb250ZW50V2luZG93LmxvY2F0aW9uLnJlcGxhY2UodXJsKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIE9ic2VydmFibGUuY3JlYXRlKChvYnNlcnZlcjogT2JzZXJ2ZXI8YW55PikgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLnNlc3Npb25JZnJhbWUub25sb2FkID0gKCkgPT4ge1xyXG4gICAgICAgICAgICAgICAgb2JzZXJ2ZXIubmV4dCh0aGlzKTtcclxuICAgICAgICAgICAgICAgIG9ic2VydmVyLmNvbXBsZXRlKCk7XHJcbiAgICAgICAgICAgIH07XHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcbn1cclxuIl19