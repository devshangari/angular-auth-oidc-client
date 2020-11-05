/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
import { map } from 'rxjs/operators';
import { OidcDataService } from '../data-services/oidc-data.service';
import { LoggerService } from './oidc.logger.service';
import { OidcSecurityCommon } from './oidc.security.common';
export class OidcSecurityUserService {
    /**
     * @param {?} oidcDataService
     * @param {?} oidcSecurityCommon
     * @param {?} loggerService
     */
    constructor(oidcDataService, oidcSecurityCommon, loggerService) {
        this.oidcDataService = oidcDataService;
        this.oidcSecurityCommon = oidcSecurityCommon;
        this.loggerService = loggerService;
        this.userData = '';
    }
    /**
     * @param {?} authWellKnownEndpoints
     * @return {?}
     */
    setupModule(authWellKnownEndpoints) {
        this.authWellKnownEndpoints = Object.assign({}, authWellKnownEndpoints);
    }
    /**
     * @return {?}
     */
    initUserData() {
        return this.getIdentityUserData().pipe(map((/**
         * @param {?} data
         * @return {?}
         */
        (data) => (this.userData = data))));
    }
    /**
     * @return {?}
     */
    getUserData() {
        if (!this.userData) {
            throw Error('UserData is not set!');
        }
        return this.userData;
    }
    /**
     * @param {?} value
     * @return {?}
     */
    setUserData(value) {
        this.userData = value;
    }
    /**
     * @private
     * @return {?}
     */
    getIdentityUserData() {
        /** @type {?} */
        const token = this.oidcSecurityCommon.getAccessToken();
        if (!this.authWellKnownEndpoints) {
            this.loggerService.logWarning('init check session: authWellKnownEndpoints is undefined');
            throw Error('authWellKnownEndpoints is undefined');
        }
        /** @type {?} */
        const canGetUserData = this.authWellKnownEndpoints && this.authWellKnownEndpoints.userinfo_endpoint;
        if (!canGetUserData) {
            this.loggerService.logError('init check session: authWellKnownEndpoints.userinfo_endpoint is undefined; set auto_userinfo = false in config');
            throw Error('authWellKnownEndpoints.userinfo_endpoint is undefined');
        }
        return this.oidcDataService.getIdentityUserData(this.authWellKnownEndpoints.userinfo_endpoint, token);
    }
}
OidcSecurityUserService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcSecurityUserService.ctorParameters = () => [
    { type: OidcDataService },
    { type: OidcSecurityCommon },
    { type: LoggerService }
];
if (false) {
    /**
     * @type {?}
     * @private
     */
    OidcSecurityUserService.prototype.userData;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityUserService.prototype.authWellKnownEndpoints;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityUserService.prototype.oidcDataService;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityUserService.prototype.oidcSecurityCommon;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityUserService.prototype.loggerService;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS51c2VyLXNlcnZpY2UuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLWF1dGgtb2lkYy1jbGllbnQvIiwic291cmNlcyI6WyJsaWIvc2VydmljZXMvb2lkYy5zZWN1cml0eS51c2VyLXNlcnZpY2UudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7OztBQUFBLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFFM0MsT0FBTyxFQUFFLEdBQUcsRUFBRSxNQUFNLGdCQUFnQixDQUFDO0FBQ3JDLE9BQU8sRUFBRSxlQUFlLEVBQUUsTUFBTSxvQ0FBb0MsQ0FBQztBQUVyRSxPQUFPLEVBQUUsYUFBYSxFQUFFLE1BQU0sdUJBQXVCLENBQUM7QUFDdEQsT0FBTyxFQUFFLGtCQUFrQixFQUFFLE1BQU0sd0JBQXdCLENBQUM7QUFHNUQsTUFBTSxPQUFPLHVCQUF1Qjs7Ozs7O0lBSWhDLFlBQW9CLGVBQWdDLEVBQVUsa0JBQXNDLEVBQVUsYUFBNEI7UUFBdEgsb0JBQWUsR0FBZixlQUFlLENBQWlCO1FBQVUsdUJBQWtCLEdBQWxCLGtCQUFrQixDQUFvQjtRQUFVLGtCQUFhLEdBQWIsYUFBYSxDQUFlO1FBSGxJLGFBQVEsR0FBUSxFQUFFLENBQUM7SUFHa0gsQ0FBQzs7Ozs7SUFFOUksV0FBVyxDQUFDLHNCQUE4QztRQUN0RCxJQUFJLENBQUMsc0JBQXNCLEdBQUcsTUFBTSxDQUFDLE1BQU0sQ0FBQyxFQUFFLEVBQUUsc0JBQXNCLENBQUMsQ0FBQztJQUM1RSxDQUFDOzs7O0lBRUQsWUFBWTtRQUNSLE9BQU8sSUFBSSxDQUFDLG1CQUFtQixFQUFFLENBQUMsSUFBSSxDQUFDLEdBQUc7Ozs7UUFBQyxDQUFDLElBQVMsRUFBRSxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsUUFBUSxHQUFHLElBQUksQ0FBQyxFQUFDLENBQUMsQ0FBQztJQUN2RixDQUFDOzs7O0lBRUQsV0FBVztRQUNQLElBQUksQ0FBQyxJQUFJLENBQUMsUUFBUSxFQUFFO1lBQ2hCLE1BQU0sS0FBSyxDQUFDLHNCQUFzQixDQUFDLENBQUM7U0FDdkM7UUFFRCxPQUFPLElBQUksQ0FBQyxRQUFRLENBQUM7SUFDekIsQ0FBQzs7Ozs7SUFFRCxXQUFXLENBQUMsS0FBVTtRQUNsQixJQUFJLENBQUMsUUFBUSxHQUFHLEtBQUssQ0FBQztJQUMxQixDQUFDOzs7OztJQUVPLG1CQUFtQjs7Y0FDakIsS0FBSyxHQUFHLElBQUksQ0FBQyxrQkFBa0IsQ0FBQyxjQUFjLEVBQUU7UUFFdEQsSUFBSSxDQUFDLElBQUksQ0FBQyxzQkFBc0IsRUFBRTtZQUM5QixJQUFJLENBQUMsYUFBYSxDQUFDLFVBQVUsQ0FBQyx5REFBeUQsQ0FBQyxDQUFDO1lBRXpGLE1BQU0sS0FBSyxDQUFDLHFDQUFxQyxDQUFDLENBQUM7U0FDdEQ7O2NBRUssY0FBYyxHQUFHLElBQUksQ0FBQyxzQkFBc0IsSUFBSSxJQUFJLENBQUMsc0JBQXNCLENBQUMsaUJBQWlCO1FBRW5HLElBQUksQ0FBQyxjQUFjLEVBQUU7WUFDakIsSUFBSSxDQUFDLGFBQWEsQ0FBQyxRQUFRLENBQ3ZCLGdIQUFnSCxDQUNuSCxDQUFDO1lBQ0YsTUFBTSxLQUFLLENBQUMsdURBQXVELENBQUMsQ0FBQztTQUN4RTtRQUVELE9BQU8sSUFBSSxDQUFDLGVBQWUsQ0FBQyxtQkFBbUIsQ0FBQyxJQUFJLENBQUMsc0JBQXNCLENBQUMsaUJBQWlCLEVBQUUsS0FBSyxDQUFDLENBQUM7SUFDMUcsQ0FBQzs7O1lBOUNKLFVBQVU7Ozs7WUFMRixlQUFlO1lBR2Ysa0JBQWtCO1lBRGxCLGFBQWE7Ozs7Ozs7SUFLbEIsMkNBQTJCOzs7OztJQUMzQix5REFBbUU7Ozs7O0lBRXZELGtEQUF3Qzs7Ozs7SUFBRSxxREFBOEM7Ozs7O0lBQUUsZ0RBQW9DIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xyXG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XHJcbmltcG9ydCB7IG1hcCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcclxuaW1wb3J0IHsgT2lkY0RhdGFTZXJ2aWNlIH0gZnJvbSAnLi4vZGF0YS1zZXJ2aWNlcy9vaWRjLWRhdGEuc2VydmljZSc7XHJcbmltcG9ydCB7IEF1dGhXZWxsS25vd25FbmRwb2ludHMgfSBmcm9tICcuLi9tb2RlbHMvYXV0aC53ZWxsLWtub3duLWVuZHBvaW50cyc7XHJcbmltcG9ydCB7IExvZ2dlclNlcnZpY2UgfSBmcm9tICcuL29pZGMubG9nZ2VyLnNlcnZpY2UnO1xyXG5pbXBvcnQgeyBPaWRjU2VjdXJpdHlDb21tb24gfSBmcm9tICcuL29pZGMuc2VjdXJpdHkuY29tbW9uJztcclxuXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGNsYXNzIE9pZGNTZWN1cml0eVVzZXJTZXJ2aWNlIHtcclxuICAgIHByaXZhdGUgdXNlckRhdGE6IGFueSA9ICcnO1xyXG4gICAgcHJpdmF0ZSBhdXRoV2VsbEtub3duRW5kcG9pbnRzOiBBdXRoV2VsbEtub3duRW5kcG9pbnRzIHwgdW5kZWZpbmVkO1xyXG5cclxuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgb2lkY0RhdGFTZXJ2aWNlOiBPaWRjRGF0YVNlcnZpY2UsIHByaXZhdGUgb2lkY1NlY3VyaXR5Q29tbW9uOiBPaWRjU2VjdXJpdHlDb21tb24sIHByaXZhdGUgbG9nZ2VyU2VydmljZTogTG9nZ2VyU2VydmljZSkge31cclxuXHJcbiAgICBzZXR1cE1vZHVsZShhdXRoV2VsbEtub3duRW5kcG9pbnRzOiBBdXRoV2VsbEtub3duRW5kcG9pbnRzKSB7XHJcbiAgICAgICAgdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzID0gT2JqZWN0LmFzc2lnbih7fSwgYXV0aFdlbGxLbm93bkVuZHBvaW50cyk7XHJcbiAgICB9XHJcblxyXG4gICAgaW5pdFVzZXJEYXRhKCkge1xyXG4gICAgICAgIHJldHVybiB0aGlzLmdldElkZW50aXR5VXNlckRhdGEoKS5waXBlKG1hcCgoZGF0YTogYW55KSA9PiAodGhpcy51c2VyRGF0YSA9IGRhdGEpKSk7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0VXNlckRhdGEoKTogYW55IHtcclxuICAgICAgICBpZiAoIXRoaXMudXNlckRhdGEpIHtcclxuICAgICAgICAgICAgdGhyb3cgRXJyb3IoJ1VzZXJEYXRhIGlzIG5vdCBzZXQhJyk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy51c2VyRGF0YTtcclxuICAgIH1cclxuXHJcbiAgICBzZXRVc2VyRGF0YSh2YWx1ZTogYW55KTogdm9pZCB7XHJcbiAgICAgICAgdGhpcy51c2VyRGF0YSA9IHZhbHVlO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgZ2V0SWRlbnRpdHlVc2VyRGF0YSgpOiBPYnNlcnZhYmxlPGFueT4ge1xyXG4gICAgICAgIGNvbnN0IHRva2VuID0gdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uZ2V0QWNjZXNzVG9rZW4oKTtcclxuXHJcbiAgICAgICAgaWYgKCF0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMpIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2luaXQgY2hlY2sgc2Vzc2lvbjogYXV0aFdlbGxLbm93bkVuZHBvaW50cyBpcyB1bmRlZmluZWQnKTtcclxuXHJcbiAgICAgICAgICAgIHRocm93IEVycm9yKCdhdXRoV2VsbEtub3duRW5kcG9pbnRzIGlzIHVuZGVmaW5lZCcpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3QgY2FuR2V0VXNlckRhdGEgPSB0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMgJiYgdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLnVzZXJpbmZvX2VuZHBvaW50O1xyXG5cclxuICAgICAgICBpZiAoIWNhbkdldFVzZXJEYXRhKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dFcnJvcihcclxuICAgICAgICAgICAgICAgICdpbml0IGNoZWNrIHNlc3Npb246IGF1dGhXZWxsS25vd25FbmRwb2ludHMudXNlcmluZm9fZW5kcG9pbnQgaXMgdW5kZWZpbmVkOyBzZXQgYXV0b191c2VyaW5mbyA9IGZhbHNlIGluIGNvbmZpZydcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgdGhyb3cgRXJyb3IoJ2F1dGhXZWxsS25vd25FbmRwb2ludHMudXNlcmluZm9fZW5kcG9pbnQgaXMgdW5kZWZpbmVkJyk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5vaWRjRGF0YVNlcnZpY2UuZ2V0SWRlbnRpdHlVc2VyRGF0YSh0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMudXNlcmluZm9fZW5kcG9pbnQsIHRva2VuKTtcclxuICAgIH1cclxufVxyXG4iXX0=