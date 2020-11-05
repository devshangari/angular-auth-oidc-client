/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { of, Subject } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
var OidcConfigService = /** @class */ (function () {
    function OidcConfigService(httpClient) {
        this.httpClient = httpClient;
        this._onConfigurationLoaded = new Subject();
    }
    Object.defineProperty(OidcConfigService.prototype, "onConfigurationLoaded", {
        get: /**
         * @return {?}
         */
        function () {
            return this._onConfigurationLoaded.asObservable();
        },
        enumerable: true,
        configurable: true
    });
    /**
     * @param {?} configUrl
     * @return {?}
     */
    OidcConfigService.prototype.load = /**
     * @param {?} configUrl
     * @return {?}
     */
    function (configUrl) {
        var _this = this;
        this.httpClient
            .get(configUrl)
            .pipe(map((/**
         * @param {?} response
         * @return {?}
         */
        function (response) {
            _this.clientConfiguration = response;
            _this.load_using_stsServer(_this.clientConfiguration.stsServer);
        })), catchError((/**
         * @param {?} error
         * @return {?}
         */
        function (error) {
            console.error("OidcConfigService 'load' threw an error on calling " + configUrl, error);
            _this._onConfigurationLoaded.next(false);
            return of(false);
        })))
            .subscribe();
    };
    /**
     * @param {?} stsServer
     * @return {?}
     */
    OidcConfigService.prototype.load_using_stsServer = /**
     * @param {?} stsServer
     * @return {?}
     */
    function (stsServer) {
        var _this = this;
        /** @type {?} */
        var url = stsServer + "/.well-known/openid-configuration";
        this.httpClient
            .get(url)
            .pipe(map((/**
         * @param {?} response
         * @return {?}
         */
        function (response) {
            _this.wellKnownEndpoints = response;
            _this._onConfigurationLoaded.next(true);
        })), catchError((/**
         * @param {?} error
         * @return {?}
         */
        function (error) {
            console.error("OidcConfigService 'load_using_stsServer' threw an error on calling " + stsServer, error);
            _this._onConfigurationLoaded.next(false);
            return of(false);
        })))
            .subscribe();
    };
    /**
     * @param {?} url
     * @return {?}
     */
    OidcConfigService.prototype.load_using_custom_stsServer = /**
     * @param {?} url
     * @return {?}
     */
    function (url) {
        var _this = this;
        this.httpClient
            .get(url)
            .pipe(map((/**
         * @param {?} response
         * @return {?}
         */
        function (response) {
            _this.wellKnownEndpoints = response;
            _this._onConfigurationLoaded.next(true);
        })), catchError((/**
         * @param {?} error
         * @return {?}
         */
        function (error) {
            console.error("OidcConfigService 'load_using_custom_stsServer' threw an error on calling " + url, error);
            _this._onConfigurationLoaded.next(false);
            return of(false);
        })))
            .subscribe();
    };
    OidcConfigService.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    OidcConfigService.ctorParameters = function () { return [
        { type: HttpClient }
    ]; };
    return OidcConfigService;
}());
export { OidcConfigService };
if (false) {
    /**
     * @type {?}
     * @private
     */
    OidcConfigService.prototype._onConfigurationLoaded;
    /** @type {?} */
    OidcConfigService.prototype.clientConfiguration;
    /** @type {?} */
    OidcConfigService.prototype.wellKnownEndpoints;
    /**
     * @type {?}
     * @private
     */
    OidcConfigService.prototype.httpClient;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS5jb25maWcuc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItYXV0aC1vaWRjLWNsaWVudC8iLCJzb3VyY2VzIjpbImxpYi9zZXJ2aWNlcy9vaWRjLnNlY3VyaXR5LmNvbmZpZy5zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sc0JBQXNCLENBQUM7QUFDbEQsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQWMsRUFBRSxFQUFFLE9BQU8sRUFBRSxNQUFNLE1BQU0sQ0FBQztBQUMvQyxPQUFPLEVBQUUsVUFBVSxFQUFFLEdBQUcsRUFBRSxNQUFNLGdCQUFnQixDQUFDO0FBRWpEO0lBVUksMkJBQTZCLFVBQXNCO1FBQXRCLGVBQVUsR0FBVixVQUFVLENBQVk7UUFSM0MsMkJBQXNCLEdBQUcsSUFBSSxPQUFPLEVBQVcsQ0FBQztJQVFGLENBQUM7SUFKdkQsc0JBQVcsb0RBQXFCOzs7O1FBQWhDO1lBQ0ksT0FBTyxJQUFJLENBQUMsc0JBQXNCLENBQUMsWUFBWSxFQUFFLENBQUM7UUFDdEQsQ0FBQzs7O09BQUE7Ozs7O0lBSUQsZ0NBQUk7Ozs7SUFBSixVQUFLLFNBQWlCO1FBQXRCLGlCQWVDO1FBZEcsSUFBSSxDQUFDLFVBQVU7YUFDVixHQUFHLENBQUMsU0FBUyxDQUFDO2FBQ2QsSUFBSSxDQUNELEdBQUc7Ozs7UUFBQyxVQUFBLFFBQVE7WUFDUixLQUFJLENBQUMsbUJBQW1CLEdBQUcsUUFBUSxDQUFDO1lBQ3BDLEtBQUksQ0FBQyxvQkFBb0IsQ0FBQyxLQUFJLENBQUMsbUJBQW1CLENBQUMsU0FBUyxDQUFDLENBQUM7UUFDbEUsQ0FBQyxFQUFDLEVBQ0YsVUFBVTs7OztRQUFDLFVBQUEsS0FBSztZQUNaLE9BQU8sQ0FBQyxLQUFLLENBQUMsd0RBQXNELFNBQVcsRUFBRSxLQUFLLENBQUMsQ0FBQztZQUN4RixLQUFJLENBQUMsc0JBQXNCLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDO1lBQ3hDLE9BQU8sRUFBRSxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ3JCLENBQUMsRUFBQyxDQUNMO2FBQ0EsU0FBUyxFQUFFLENBQUM7SUFDckIsQ0FBQzs7Ozs7SUFFRCxnREFBb0I7Ozs7SUFBcEIsVUFBcUIsU0FBaUI7UUFBdEMsaUJBaUJDOztZQWhCUyxHQUFHLEdBQU0sU0FBUyxzQ0FBbUM7UUFFM0QsSUFBSSxDQUFDLFVBQVU7YUFDVixHQUFHLENBQUMsR0FBRyxDQUFDO2FBQ1IsSUFBSSxDQUNELEdBQUc7Ozs7UUFBQyxVQUFBLFFBQVE7WUFDUixLQUFJLENBQUMsa0JBQWtCLEdBQUcsUUFBUSxDQUFDO1lBQ25DLEtBQUksQ0FBQyxzQkFBc0IsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUM7UUFDM0MsQ0FBQyxFQUFDLEVBQ0YsVUFBVTs7OztRQUFDLFVBQUEsS0FBSztZQUNaLE9BQU8sQ0FBQyxLQUFLLENBQUMsd0VBQXNFLFNBQVcsRUFBRSxLQUFLLENBQUMsQ0FBQztZQUN4RyxLQUFJLENBQUMsc0JBQXNCLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDO1lBQ3hDLE9BQU8sRUFBRSxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ3JCLENBQUMsRUFBQyxDQUNMO2FBQ0EsU0FBUyxFQUFFLENBQUM7SUFDckIsQ0FBQzs7Ozs7SUFFRCx1REFBMkI7Ozs7SUFBM0IsVUFBNEIsR0FBVztRQUF2QyxpQkFlQztRQWRHLElBQUksQ0FBQyxVQUFVO2FBQ1YsR0FBRyxDQUFDLEdBQUcsQ0FBQzthQUNSLElBQUksQ0FDRCxHQUFHOzs7O1FBQUMsVUFBQSxRQUFRO1lBQ1IsS0FBSSxDQUFDLGtCQUFrQixHQUFHLFFBQVEsQ0FBQztZQUNuQyxLQUFJLENBQUMsc0JBQXNCLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDO1FBQzNDLENBQUMsRUFBQyxFQUNGLFVBQVU7Ozs7UUFBQyxVQUFBLEtBQUs7WUFDWixPQUFPLENBQUMsS0FBSyxDQUFDLCtFQUE2RSxHQUFLLEVBQUUsS0FBSyxDQUFDLENBQUM7WUFDekcsS0FBSSxDQUFDLHNCQUFzQixDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUN4QyxPQUFPLEVBQUUsQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUNyQixDQUFDLEVBQUMsQ0FDTDthQUNBLFNBQVMsRUFBRSxDQUFDO0lBQ3JCLENBQUM7O2dCQS9ESixVQUFVOzs7O2dCQUxGLFVBQVU7O0lBcUVuQix3QkFBQztDQUFBLEFBaEVELElBZ0VDO1NBL0RZLGlCQUFpQjs7Ozs7O0lBQzFCLG1EQUF3RDs7SUFDeEQsZ0RBQXlCOztJQUN6QiwrQ0FBd0I7Ozs7O0lBTVosdUNBQXVDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSHR0cENsaWVudCB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcclxuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xyXG5pbXBvcnQgeyBPYnNlcnZhYmxlLCBvZiwgU3ViamVjdCB9IGZyb20gJ3J4anMnO1xyXG5pbXBvcnQgeyBjYXRjaEVycm9yLCBtYXAgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XHJcblxyXG5ASW5qZWN0YWJsZSgpXHJcbmV4cG9ydCBjbGFzcyBPaWRjQ29uZmlnU2VydmljZSB7XHJcbiAgICBwcml2YXRlIF9vbkNvbmZpZ3VyYXRpb25Mb2FkZWQgPSBuZXcgU3ViamVjdDxib29sZWFuPigpO1xyXG4gICAgY2xpZW50Q29uZmlndXJhdGlvbjogYW55O1xyXG4gICAgd2VsbEtub3duRW5kcG9pbnRzOiBhbnk7XHJcblxyXG4gICAgcHVibGljIGdldCBvbkNvbmZpZ3VyYXRpb25Mb2FkZWQoKTogT2JzZXJ2YWJsZTxib29sZWFuPiB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMuX29uQ29uZmlndXJhdGlvbkxvYWRlZC5hc09ic2VydmFibGUoKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGh0dHBDbGllbnQ6IEh0dHBDbGllbnQpIHt9XHJcblxyXG4gICAgbG9hZChjb25maWdVcmw6IHN0cmluZykge1xyXG4gICAgICAgIHRoaXMuaHR0cENsaWVudFxyXG4gICAgICAgICAgICAuZ2V0KGNvbmZpZ1VybClcclxuICAgICAgICAgICAgLnBpcGUoXHJcbiAgICAgICAgICAgICAgICBtYXAocmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuY2xpZW50Q29uZmlndXJhdGlvbiA9IHJlc3BvbnNlO1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9hZF91c2luZ19zdHNTZXJ2ZXIodGhpcy5jbGllbnRDb25maWd1cmF0aW9uLnN0c1NlcnZlcik7XHJcbiAgICAgICAgICAgICAgICB9KSxcclxuICAgICAgICAgICAgICAgIGNhdGNoRXJyb3IoZXJyb3IgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoYE9pZGNDb25maWdTZXJ2aWNlICdsb2FkJyB0aHJldyBhbiBlcnJvciBvbiBjYWxsaW5nICR7Y29uZmlnVXJsfWAsIGVycm9yKTtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLl9vbkNvbmZpZ3VyYXRpb25Mb2FkZWQubmV4dChmYWxzZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG9mKGZhbHNlKTtcclxuICAgICAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgIClcclxuICAgICAgICAgICAgLnN1YnNjcmliZSgpO1xyXG4gICAgfVxyXG5cclxuICAgIGxvYWRfdXNpbmdfc3RzU2VydmVyKHN0c1NlcnZlcjogc3RyaW5nKSB7XHJcbiAgICAgICAgY29uc3QgdXJsID0gYCR7c3RzU2VydmVyfS8ud2VsbC1rbm93bi9vcGVuaWQtY29uZmlndXJhdGlvbmA7XHJcblxyXG4gICAgICAgIHRoaXMuaHR0cENsaWVudFxyXG4gICAgICAgICAgICAuZ2V0KHVybClcclxuICAgICAgICAgICAgLnBpcGUoXHJcbiAgICAgICAgICAgICAgICBtYXAocmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMud2VsbEtub3duRW5kcG9pbnRzID0gcmVzcG9uc2U7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5fb25Db25maWd1cmF0aW9uTG9hZGVkLm5leHQodHJ1ZSk7XHJcbiAgICAgICAgICAgICAgICB9KSxcclxuICAgICAgICAgICAgICAgIGNhdGNoRXJyb3IoZXJyb3IgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoYE9pZGNDb25maWdTZXJ2aWNlICdsb2FkX3VzaW5nX3N0c1NlcnZlcicgdGhyZXcgYW4gZXJyb3Igb24gY2FsbGluZyAke3N0c1NlcnZlcn1gLCBlcnJvcik7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5fb25Db25maWd1cmF0aW9uTG9hZGVkLm5leHQoZmFsc2UpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBvZihmYWxzZSk7XHJcbiAgICAgICAgICAgICAgICB9KVxyXG4gICAgICAgICAgICApXHJcbiAgICAgICAgICAgIC5zdWJzY3JpYmUoKTtcclxuICAgIH1cclxuXHJcbiAgICBsb2FkX3VzaW5nX2N1c3RvbV9zdHNTZXJ2ZXIodXJsOiBzdHJpbmcpIHtcclxuICAgICAgICB0aGlzLmh0dHBDbGllbnRcclxuICAgICAgICAgICAgLmdldCh1cmwpXHJcbiAgICAgICAgICAgIC5waXBlKFxyXG4gICAgICAgICAgICAgICAgbWFwKHJlc3BvbnNlID0+IHtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLndlbGxLbm93bkVuZHBvaW50cyA9IHJlc3BvbnNlO1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuX29uQ29uZmlndXJhdGlvbkxvYWRlZC5uZXh0KHRydWUpO1xyXG4gICAgICAgICAgICAgICAgfSksXHJcbiAgICAgICAgICAgICAgICBjYXRjaEVycm9yKGVycm9yID0+IHtcclxuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKGBPaWRjQ29uZmlnU2VydmljZSAnbG9hZF91c2luZ19jdXN0b21fc3RzU2VydmVyJyB0aHJldyBhbiBlcnJvciBvbiBjYWxsaW5nICR7dXJsfWAsIGVycm9yKTtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLl9vbkNvbmZpZ3VyYXRpb25Mb2FkZWQubmV4dChmYWxzZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG9mKGZhbHNlKTtcclxuICAgICAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgIClcclxuICAgICAgICAgICAgLnN1YnNjcmliZSgpO1xyXG4gICAgfVxyXG59XHJcbiJdfQ==