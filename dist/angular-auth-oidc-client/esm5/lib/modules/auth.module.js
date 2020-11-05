/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { NgModule } from '@angular/core';
import { OidcDataService } from '../data-services/oidc-data.service';
import { AuthWellKnownEndpoints } from '../models/auth.well-known-endpoints';
import { IFrameService } from '../services/existing-iframe.service';
import { EqualityHelperService } from '../services/oidc-equality-helper.service';
import { StateValidationService } from '../services/oidc-security-state-validation.service';
import { TokenHelperService } from '../services/oidc-token-helper.service';
import { LoggerService } from '../services/oidc.logger.service';
import { OidcSecurityCheckSession } from '../services/oidc.security.check-session';
import { OidcSecurityCommon } from '../services/oidc.security.common';
import { OidcConfigService } from '../services/oidc.security.config.service';
import { OidcSecurityService } from '../services/oidc.security.service';
import { OidcSecuritySilentRenew } from '../services/oidc.security.silent-renew';
import { BrowserStorage, OidcSecurityStorage } from '../services/oidc.security.storage';
import { OidcSecurityUserService } from '../services/oidc.security.user-service';
import { OidcSecurityValidation } from '../services/oidc.security.validation';
import { AuthConfiguration } from './auth.configuration';
var AuthModule = /** @class */ (function () {
    function AuthModule() {
    }
    /**
     * @param {?=} token
     * @return {?}
     */
    AuthModule.forRoot = /**
     * @param {?=} token
     * @return {?}
     */
    function (token) {
        if (token === void 0) { token = {}; }
        return {
            ngModule: AuthModule,
            providers: [
                OidcConfigService,
                OidcSecurityService,
                OidcSecurityValidation,
                OidcSecurityCheckSession,
                OidcSecuritySilentRenew,
                OidcSecurityUserService,
                OidcSecurityCommon,
                AuthConfiguration,
                TokenHelperService,
                LoggerService,
                IFrameService,
                EqualityHelperService,
                AuthWellKnownEndpoints,
                OidcDataService,
                StateValidationService,
                {
                    provide: OidcSecurityStorage,
                    useClass: token.storage || BrowserStorage,
                },
            ],
        };
    };
    AuthModule.decorators = [
        { type: NgModule }
    ];
    return AuthModule;
}());
export { AuthModule };
/**
 * @record
 * @template T
 */
export function Type() { }
/**
 * @record
 */
export function Token() { }
if (false) {
    /** @type {?|undefined} */
    Token.prototype.storage;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5tb2R1bGUuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLWF1dGgtb2lkYy1jbGllbnQvIiwic291cmNlcyI6WyJsaWIvbW9kdWxlcy9hdXRoLm1vZHVsZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUF1QixRQUFRLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDOUQsT0FBTyxFQUFFLGVBQWUsRUFBRSxNQUFNLG9DQUFvQyxDQUFDO0FBQ3JFLE9BQU8sRUFBRSxzQkFBc0IsRUFBRSxNQUFNLHFDQUFxQyxDQUFDO0FBQzdFLE9BQU8sRUFBRSxhQUFhLEVBQUUsTUFBTSxxQ0FBcUMsQ0FBQztBQUNwRSxPQUFPLEVBQUUscUJBQXFCLEVBQUUsTUFBTSwwQ0FBMEMsQ0FBQztBQUNqRixPQUFPLEVBQUUsc0JBQXNCLEVBQUUsTUFBTSxvREFBb0QsQ0FBQztBQUM1RixPQUFPLEVBQUUsa0JBQWtCLEVBQUUsTUFBTSx1Q0FBdUMsQ0FBQztBQUMzRSxPQUFPLEVBQUUsYUFBYSxFQUFFLE1BQU0saUNBQWlDLENBQUM7QUFDaEUsT0FBTyxFQUFFLHdCQUF3QixFQUFFLE1BQU0seUNBQXlDLENBQUM7QUFDbkYsT0FBTyxFQUFFLGtCQUFrQixFQUFFLE1BQU0sa0NBQWtDLENBQUM7QUFDdEUsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sMENBQTBDLENBQUM7QUFDN0UsT0FBTyxFQUFFLG1CQUFtQixFQUFFLE1BQU0sbUNBQW1DLENBQUM7QUFDeEUsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sd0NBQXdDLENBQUM7QUFDakYsT0FBTyxFQUFFLGNBQWMsRUFBRSxtQkFBbUIsRUFBRSxNQUFNLG1DQUFtQyxDQUFDO0FBQ3hGLE9BQU8sRUFBRSx1QkFBdUIsRUFBRSxNQUFNLHdDQUF3QyxDQUFDO0FBQ2pGLE9BQU8sRUFBRSxzQkFBc0IsRUFBRSxNQUFNLHNDQUFzQyxDQUFDO0FBQzlFLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBRXpEO0lBQUE7SUE0QkEsQ0FBQzs7Ozs7SUExQlUsa0JBQU87Ozs7SUFBZCxVQUFlLEtBQWlCO1FBQWpCLHNCQUFBLEVBQUEsVUFBaUI7UUFDNUIsT0FBTztZQUNILFFBQVEsRUFBRSxVQUFVO1lBQ3BCLFNBQVMsRUFBRTtnQkFDUCxpQkFBaUI7Z0JBQ2pCLG1CQUFtQjtnQkFDbkIsc0JBQXNCO2dCQUN0Qix3QkFBd0I7Z0JBQ3hCLHVCQUF1QjtnQkFDdkIsdUJBQXVCO2dCQUN2QixrQkFBa0I7Z0JBQ2xCLGlCQUFpQjtnQkFDakIsa0JBQWtCO2dCQUNsQixhQUFhO2dCQUNiLGFBQWE7Z0JBQ2IscUJBQXFCO2dCQUNyQixzQkFBc0I7Z0JBQ3RCLGVBQWU7Z0JBQ2Ysc0JBQXNCO2dCQUN0QjtvQkFDSSxPQUFPLEVBQUUsbUJBQW1CO29CQUM1QixRQUFRLEVBQUUsS0FBSyxDQUFDLE9BQU8sSUFBSSxjQUFjO2lCQUM1QzthQUNKO1NBQ0osQ0FBQztJQUNOLENBQUM7O2dCQTNCSixRQUFROztJQTRCVCxpQkFBQztDQUFBLEFBNUJELElBNEJDO1NBM0JZLFVBQVU7Ozs7O0FBNkJ2QiwwQkFFQzs7OztBQUVELDJCQUVDOzs7SUFERyx3QkFBb0IiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBNb2R1bGVXaXRoUHJvdmlkZXJzLCBOZ01vZHVsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xyXG5pbXBvcnQgeyBPaWRjRGF0YVNlcnZpY2UgfSBmcm9tICcuLi9kYXRhLXNlcnZpY2VzL29pZGMtZGF0YS5zZXJ2aWNlJztcclxuaW1wb3J0IHsgQXV0aFdlbGxLbm93bkVuZHBvaW50cyB9IGZyb20gJy4uL21vZGVscy9hdXRoLndlbGwta25vd24tZW5kcG9pbnRzJztcclxuaW1wb3J0IHsgSUZyYW1lU2VydmljZSB9IGZyb20gJy4uL3NlcnZpY2VzL2V4aXN0aW5nLWlmcmFtZS5zZXJ2aWNlJztcclxuaW1wb3J0IHsgRXF1YWxpdHlIZWxwZXJTZXJ2aWNlIH0gZnJvbSAnLi4vc2VydmljZXMvb2lkYy1lcXVhbGl0eS1oZWxwZXIuc2VydmljZSc7XHJcbmltcG9ydCB7IFN0YXRlVmFsaWRhdGlvblNlcnZpY2UgfSBmcm9tICcuLi9zZXJ2aWNlcy9vaWRjLXNlY3VyaXR5LXN0YXRlLXZhbGlkYXRpb24uc2VydmljZSc7XHJcbmltcG9ydCB7IFRva2VuSGVscGVyU2VydmljZSB9IGZyb20gJy4uL3NlcnZpY2VzL29pZGMtdG9rZW4taGVscGVyLnNlcnZpY2UnO1xyXG5pbXBvcnQgeyBMb2dnZXJTZXJ2aWNlIH0gZnJvbSAnLi4vc2VydmljZXMvb2lkYy5sb2dnZXIuc2VydmljZSc7XHJcbmltcG9ydCB7IE9pZGNTZWN1cml0eUNoZWNrU2Vzc2lvbiB9IGZyb20gJy4uL3NlcnZpY2VzL29pZGMuc2VjdXJpdHkuY2hlY2stc2Vzc2lvbic7XHJcbmltcG9ydCB7IE9pZGNTZWN1cml0eUNvbW1vbiB9IGZyb20gJy4uL3NlcnZpY2VzL29pZGMuc2VjdXJpdHkuY29tbW9uJztcclxuaW1wb3J0IHsgT2lkY0NvbmZpZ1NlcnZpY2UgfSBmcm9tICcuLi9zZXJ2aWNlcy9vaWRjLnNlY3VyaXR5LmNvbmZpZy5zZXJ2aWNlJztcclxuaW1wb3J0IHsgT2lkY1NlY3VyaXR5U2VydmljZSB9IGZyb20gJy4uL3NlcnZpY2VzL29pZGMuc2VjdXJpdHkuc2VydmljZSc7XHJcbmltcG9ydCB7IE9pZGNTZWN1cml0eVNpbGVudFJlbmV3IH0gZnJvbSAnLi4vc2VydmljZXMvb2lkYy5zZWN1cml0eS5zaWxlbnQtcmVuZXcnO1xyXG5pbXBvcnQgeyBCcm93c2VyU3RvcmFnZSwgT2lkY1NlY3VyaXR5U3RvcmFnZSB9IGZyb20gJy4uL3NlcnZpY2VzL29pZGMuc2VjdXJpdHkuc3RvcmFnZSc7XHJcbmltcG9ydCB7IE9pZGNTZWN1cml0eVVzZXJTZXJ2aWNlIH0gZnJvbSAnLi4vc2VydmljZXMvb2lkYy5zZWN1cml0eS51c2VyLXNlcnZpY2UnO1xyXG5pbXBvcnQgeyBPaWRjU2VjdXJpdHlWYWxpZGF0aW9uIH0gZnJvbSAnLi4vc2VydmljZXMvb2lkYy5zZWN1cml0eS52YWxpZGF0aW9uJztcclxuaW1wb3J0IHsgQXV0aENvbmZpZ3VyYXRpb24gfSBmcm9tICcuL2F1dGguY29uZmlndXJhdGlvbic7XHJcblxyXG5ATmdNb2R1bGUoKVxyXG5leHBvcnQgY2xhc3MgQXV0aE1vZHVsZSB7XHJcbiAgICBzdGF0aWMgZm9yUm9vdCh0b2tlbjogVG9rZW4gPSB7fSk6IE1vZHVsZVdpdGhQcm92aWRlcnMge1xyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIG5nTW9kdWxlOiBBdXRoTW9kdWxlLFxyXG4gICAgICAgICAgICBwcm92aWRlcnM6IFtcclxuICAgICAgICAgICAgICAgIE9pZGNDb25maWdTZXJ2aWNlLFxyXG4gICAgICAgICAgICAgICAgT2lkY1NlY3VyaXR5U2VydmljZSxcclxuICAgICAgICAgICAgICAgIE9pZGNTZWN1cml0eVZhbGlkYXRpb24sXHJcbiAgICAgICAgICAgICAgICBPaWRjU2VjdXJpdHlDaGVja1Nlc3Npb24sXHJcbiAgICAgICAgICAgICAgICBPaWRjU2VjdXJpdHlTaWxlbnRSZW5ldyxcclxuICAgICAgICAgICAgICAgIE9pZGNTZWN1cml0eVVzZXJTZXJ2aWNlLFxyXG4gICAgICAgICAgICAgICAgT2lkY1NlY3VyaXR5Q29tbW9uLFxyXG4gICAgICAgICAgICAgICAgQXV0aENvbmZpZ3VyYXRpb24sXHJcbiAgICAgICAgICAgICAgICBUb2tlbkhlbHBlclNlcnZpY2UsXHJcbiAgICAgICAgICAgICAgICBMb2dnZXJTZXJ2aWNlLFxyXG4gICAgICAgICAgICAgICAgSUZyYW1lU2VydmljZSxcclxuICAgICAgICAgICAgICAgIEVxdWFsaXR5SGVscGVyU2VydmljZSxcclxuICAgICAgICAgICAgICAgIEF1dGhXZWxsS25vd25FbmRwb2ludHMsXHJcbiAgICAgICAgICAgICAgICBPaWRjRGF0YVNlcnZpY2UsXHJcbiAgICAgICAgICAgICAgICBTdGF0ZVZhbGlkYXRpb25TZXJ2aWNlLFxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHByb3ZpZGU6IE9pZGNTZWN1cml0eVN0b3JhZ2UsXHJcbiAgICAgICAgICAgICAgICAgICAgdXNlQ2xhc3M6IHRva2VuLnN0b3JhZ2UgfHwgQnJvd3NlclN0b3JhZ2UsXHJcbiAgICAgICAgICAgICAgICB9LFxyXG4gICAgICAgICAgICBdLFxyXG4gICAgICAgIH07XHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgVHlwZTxUPiBleHRlbmRzIEZ1bmN0aW9uIHtcclxuICAgIG5ldyAoLi4uYXJnczogYW55W10pOiBUO1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFRva2VuIHtcclxuICAgIHN0b3JhZ2U/OiBUeXBlPGFueT47XHJcbn1cclxuIl19