/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
import { LoggerService } from './oidc.logger.service';
export class IFrameService {
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
if (false) {
    /**
     * @type {?}
     * @private
     */
    IFrameService.prototype.loggerService;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXhpc3RpbmctaWZyYW1lLnNlcnZpY2UuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLWF1dGgtb2lkYy1jbGllbnQvIiwic291cmNlcyI6WyJsaWIvc2VydmljZXMvZXhpc3RpbmctaWZyYW1lLnNlcnZpY2UudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7OztBQUFBLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLHVCQUF1QixDQUFDO0FBR3RELE1BQU0sT0FBTyxhQUFhOzs7O0lBQ3RCLFlBQW9CLGFBQTRCO1FBQTVCLGtCQUFhLEdBQWIsYUFBYSxDQUFlO0lBQUcsQ0FBQzs7Ozs7SUFFcEQsaUJBQWlCLENBQUMsVUFBa0I7O2NBQzFCLGNBQWMsR0FBRyxJQUFJLENBQUMseUJBQXlCLENBQUMsVUFBVSxDQUFDO1FBRWpFLElBQUksY0FBYyxFQUFFO1lBQ2hCLE9BQU8sY0FBYyxDQUFDO1NBQ3pCO1FBRUQsT0FBTyxJQUFJLENBQUMsbUJBQW1CLENBQUMsVUFBVSxDQUFDLENBQUM7SUFDaEQsQ0FBQzs7Ozs7SUFFRCxxQkFBcUIsQ0FBQyxVQUFrQjs7Y0FDOUIsYUFBYSxHQUFHLE1BQU0sQ0FBQyxRQUFRLENBQUMsYUFBYSxDQUFDLFFBQVEsQ0FBQztRQUM3RCxhQUFhLENBQUMsRUFBRSxHQUFHLFVBQVUsQ0FBQztRQUM5QixJQUFJLENBQUMsYUFBYSxDQUFDLFFBQVEsQ0FBQyxhQUFhLENBQUMsQ0FBQztRQUMzQyxhQUFhLENBQUMsS0FBSyxDQUFDLE9BQU8sR0FBRyxNQUFNLENBQUM7UUFDckMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsV0FBVyxDQUFDLGFBQWEsQ0FBQyxDQUFDO1FBQ2hELE9BQU8sYUFBYSxDQUFDO0lBQ3pCLENBQUM7Ozs7OztJQUVPLHlCQUF5QixDQUFDLFVBQWtCO1FBQ2hELElBQUk7WUFDQSxPQUFPLE1BQU0sQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLGNBQWMsQ0FBQyxVQUFVLENBQUMsQ0FBQztTQUM1RDtRQUFDLE9BQU8sQ0FBQyxFQUFFO1lBQ1IsT0FBTyxJQUFJLENBQUM7U0FDZjtJQUNMLENBQUM7Ozs7OztJQUVPLG1CQUFtQixDQUFDLFVBQWtCO1FBQzFDLE9BQU8sTUFBTSxDQUFDLFFBQVEsQ0FBQyxjQUFjLENBQUMsVUFBVSxDQUFDLENBQUM7SUFDdEQsQ0FBQzs7O1lBakNKLFVBQVU7Ozs7WUFGRixhQUFhOzs7Ozs7O0lBSU4sc0NBQW9DIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xyXG5pbXBvcnQgeyBMb2dnZXJTZXJ2aWNlIH0gZnJvbSAnLi9vaWRjLmxvZ2dlci5zZXJ2aWNlJztcclxuXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGNsYXNzIElGcmFtZVNlcnZpY2Uge1xyXG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBsb2dnZXJTZXJ2aWNlOiBMb2dnZXJTZXJ2aWNlKSB7fVxyXG5cclxuICAgIGdldEV4aXN0aW5nSUZyYW1lKGlkZW50aWZpZXI6IHN0cmluZykge1xyXG4gICAgICAgIGNvbnN0IGlGcmFtZU9uUGFyZW50ID0gdGhpcy5nZXRJRnJhbWVGcm9tUGFyZW50V2luZG93KGlkZW50aWZpZXIpO1xyXG5cclxuICAgICAgICBpZiAoaUZyYW1lT25QYXJlbnQpIHtcclxuICAgICAgICAgICAgcmV0dXJuIGlGcmFtZU9uUGFyZW50O1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2V0SUZyYW1lRnJvbVdpbmRvdyhpZGVudGlmaWVyKTtcclxuICAgIH1cclxuXHJcbiAgICBhZGRJRnJhbWVUb1dpbmRvd0JvZHkoaWRlbnRpZmllcjogc3RyaW5nKSB7XHJcbiAgICAgICAgY29uc3Qgc2Vzc2lvbklmcmFtZSA9IHdpbmRvdy5kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcclxuICAgICAgICBzZXNzaW9uSWZyYW1lLmlkID0gaWRlbnRpZmllcjtcclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoc2Vzc2lvbklmcmFtZSk7XHJcbiAgICAgICAgc2Vzc2lvbklmcmFtZS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnO1xyXG4gICAgICAgIHdpbmRvdy5kb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHNlc3Npb25JZnJhbWUpO1xyXG4gICAgICAgIHJldHVybiBzZXNzaW9uSWZyYW1lO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgZ2V0SUZyYW1lRnJvbVBhcmVudFdpbmRvdyhpZGVudGlmaWVyOiBzdHJpbmcpIHtcclxuICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICByZXR1cm4gd2luZG93LnBhcmVudC5kb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZGVudGlmaWVyKTtcclxuICAgICAgICB9IGNhdGNoIChlKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIGdldElGcmFtZUZyb21XaW5kb3coaWRlbnRpZmllcjogc3RyaW5nKSB7XHJcbiAgICAgICAgcmV0dXJuIHdpbmRvdy5kb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZGVudGlmaWVyKTtcclxuICAgIH1cclxufVxyXG4iXX0=