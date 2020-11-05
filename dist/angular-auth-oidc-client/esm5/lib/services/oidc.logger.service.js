/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
import { AuthConfiguration } from '../modules/auth.configuration';
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
        { type: Injectable }
    ];
    /** @nocollapse */
    LoggerService.ctorParameters = function () { return [
        { type: AuthConfiguration }
    ]; };
    return LoggerService;
}());
export { LoggerService };
if (false) {
    /**
     * @type {?}
     * @private
     */
    LoggerService.prototype.authConfiguration;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5sb2dnZXIuc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItYXV0aC1vaWRjLWNsaWVudC8iLCJzb3VyY2VzIjpbImxpYi9zZXJ2aWNlcy9vaWRjLmxvZ2dlci5zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBQzNDLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLCtCQUErQixDQUFDO0FBRWxFO0lBRUksdUJBQW9CLGlCQUFvQztRQUFwQyxzQkFBaUIsR0FBakIsaUJBQWlCLENBQW1CO0lBQUcsQ0FBQzs7Ozs7SUFFNUQsZ0NBQVE7Ozs7SUFBUixVQUFTLE9BQVk7UUFDakIsT0FBTyxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQztJQUMzQixDQUFDOzs7OztJQUVELGtDQUFVOzs7O0lBQVYsVUFBVyxPQUFZO1FBQ25CLElBQUksSUFBSSxDQUFDLGlCQUFpQixDQUFDLHdCQUF3QixFQUFFO1lBQ2pELE9BQU8sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7U0FDekI7SUFDTCxDQUFDOzs7OztJQUVELGdDQUFROzs7O0lBQVIsVUFBUyxPQUFZO1FBQ2pCLElBQUksSUFBSSxDQUFDLGlCQUFpQixDQUFDLHNCQUFzQixFQUFFO1lBQy9DLE9BQU8sQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLENBQUM7U0FDeEI7SUFDTCxDQUFDOztnQkFsQkosVUFBVTs7OztnQkFGRixpQkFBaUI7O0lBcUIxQixvQkFBQztDQUFBLEFBbkJELElBbUJDO1NBbEJZLGFBQWE7Ozs7OztJQUNWLDBDQUE0QyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcclxuaW1wb3J0IHsgQXV0aENvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi9tb2R1bGVzL2F1dGguY29uZmlndXJhdGlvbic7XHJcblxyXG5ASW5qZWN0YWJsZSgpXHJcbmV4cG9ydCBjbGFzcyBMb2dnZXJTZXJ2aWNlIHtcclxuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgYXV0aENvbmZpZ3VyYXRpb246IEF1dGhDb25maWd1cmF0aW9uKSB7fVxyXG5cclxuICAgIGxvZ0Vycm9yKG1lc3NhZ2U6IGFueSkge1xyXG4gICAgICAgIGNvbnNvbGUuZXJyb3IobWVzc2FnZSk7XHJcbiAgICB9XHJcblxyXG4gICAgbG9nV2FybmluZyhtZXNzYWdlOiBhbnkpIHtcclxuICAgICAgICBpZiAodGhpcy5hdXRoQ29uZmlndXJhdGlvbi5pc0xvZ0xldmVsV2FybmluZ0VuYWJsZWQpIHtcclxuICAgICAgICAgICAgY29uc29sZS53YXJuKG1lc3NhZ2UpO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBsb2dEZWJ1ZyhtZXNzYWdlOiBhbnkpIHtcclxuICAgICAgICBpZiAodGhpcy5hdXRoQ29uZmlndXJhdGlvbi5pc0xvZ0xldmVsRGVidWdFbmFibGVkKSB7XHJcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKG1lc3NhZ2UpO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxufVxyXG4iXX0=