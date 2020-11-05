/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { of, Subject } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
export class OidcConfigService {
    /**
     * @param {?} httpClient
     */
    constructor(httpClient) {
        this.httpClient = httpClient;
        this._onConfigurationLoaded = new Subject();
    }
    /**
     * @return {?}
     */
    get onConfigurationLoaded() {
        return this._onConfigurationLoaded.asObservable();
    }
    /**
     * @param {?} configUrl
     * @return {?}
     */
    load(configUrl) {
        this.httpClient
            .get(configUrl)
            .pipe(map((/**
         * @param {?} response
         * @return {?}
         */
        response => {
            this.clientConfiguration = response;
            this.load_using_stsServer(this.clientConfiguration.stsServer);
        })), catchError((/**
         * @param {?} error
         * @return {?}
         */
        error => {
            console.error(`OidcConfigService 'load' threw an error on calling ${configUrl}`, error);
            this._onConfigurationLoaded.next(false);
            return of(false);
        })))
            .subscribe();
    }
    /**
     * @param {?} stsServer
     * @return {?}
     */
    load_using_stsServer(stsServer) {
        /** @type {?} */
        const url = `${stsServer}/.well-known/openid-configuration`;
        this.httpClient
            .get(url)
            .pipe(map((/**
         * @param {?} response
         * @return {?}
         */
        response => {
            this.wellKnownEndpoints = response;
            this._onConfigurationLoaded.next(true);
        })), catchError((/**
         * @param {?} error
         * @return {?}
         */
        error => {
            console.error(`OidcConfigService 'load_using_stsServer' threw an error on calling ${stsServer}`, error);
            this._onConfigurationLoaded.next(false);
            return of(false);
        })))
            .subscribe();
    }
    /**
     * @param {?} url
     * @return {?}
     */
    load_using_custom_stsServer(url) {
        this.httpClient
            .get(url)
            .pipe(map((/**
         * @param {?} response
         * @return {?}
         */
        response => {
            this.wellKnownEndpoints = response;
            this._onConfigurationLoaded.next(true);
        })), catchError((/**
         * @param {?} error
         * @return {?}
         */
        error => {
            console.error(`OidcConfigService 'load_using_custom_stsServer' threw an error on calling ${url}`, error);
            this._onConfigurationLoaded.next(false);
            return of(false);
        })))
            .subscribe();
    }
}
OidcConfigService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcConfigService.ctorParameters = () => [
    { type: HttpClient }
];
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS5jb25maWcuc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItYXV0aC1vaWRjLWNsaWVudC8iLCJzb3VyY2VzIjpbImxpYi9zZXJ2aWNlcy9vaWRjLnNlY3VyaXR5LmNvbmZpZy5zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sc0JBQXNCLENBQUM7QUFDbEQsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQWMsRUFBRSxFQUFFLE9BQU8sRUFBRSxNQUFNLE1BQU0sQ0FBQztBQUMvQyxPQUFPLEVBQUUsVUFBVSxFQUFFLEdBQUcsRUFBRSxNQUFNLGdCQUFnQixDQUFDO0FBR2pELE1BQU0sT0FBTyxpQkFBaUI7Ozs7SUFTMUIsWUFBNkIsVUFBc0I7UUFBdEIsZUFBVSxHQUFWLFVBQVUsQ0FBWTtRQVIzQywyQkFBc0IsR0FBRyxJQUFJLE9BQU8sRUFBVyxDQUFDO0lBUUYsQ0FBQzs7OztJQUp2RCxJQUFXLHFCQUFxQjtRQUM1QixPQUFPLElBQUksQ0FBQyxzQkFBc0IsQ0FBQyxZQUFZLEVBQUUsQ0FBQztJQUN0RCxDQUFDOzs7OztJQUlELElBQUksQ0FBQyxTQUFpQjtRQUNsQixJQUFJLENBQUMsVUFBVTthQUNWLEdBQUcsQ0FBQyxTQUFTLENBQUM7YUFDZCxJQUFJLENBQ0QsR0FBRzs7OztRQUFDLFFBQVEsQ0FBQyxFQUFFO1lBQ1gsSUFBSSxDQUFDLG1CQUFtQixHQUFHLFFBQVEsQ0FBQztZQUNwQyxJQUFJLENBQUMsb0JBQW9CLENBQUMsSUFBSSxDQUFDLG1CQUFtQixDQUFDLFNBQVMsQ0FBQyxDQUFDO1FBQ2xFLENBQUMsRUFBQyxFQUNGLFVBQVU7Ozs7UUFBQyxLQUFLLENBQUMsRUFBRTtZQUNmLE9BQU8sQ0FBQyxLQUFLLENBQUMsc0RBQXNELFNBQVMsRUFBRSxFQUFFLEtBQUssQ0FBQyxDQUFDO1lBQ3hGLElBQUksQ0FBQyxzQkFBc0IsQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUM7WUFDeEMsT0FBTyxFQUFFLENBQUMsS0FBSyxDQUFDLENBQUM7UUFDckIsQ0FBQyxFQUFDLENBQ0w7YUFDQSxTQUFTLEVBQUUsQ0FBQztJQUNyQixDQUFDOzs7OztJQUVELG9CQUFvQixDQUFDLFNBQWlCOztjQUM1QixHQUFHLEdBQUcsR0FBRyxTQUFTLG1DQUFtQztRQUUzRCxJQUFJLENBQUMsVUFBVTthQUNWLEdBQUcsQ0FBQyxHQUFHLENBQUM7YUFDUixJQUFJLENBQ0QsR0FBRzs7OztRQUFDLFFBQVEsQ0FBQyxFQUFFO1lBQ1gsSUFBSSxDQUFDLGtCQUFrQixHQUFHLFFBQVEsQ0FBQztZQUNuQyxJQUFJLENBQUMsc0JBQXNCLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDO1FBQzNDLENBQUMsRUFBQyxFQUNGLFVBQVU7Ozs7UUFBQyxLQUFLLENBQUMsRUFBRTtZQUNmLE9BQU8sQ0FBQyxLQUFLLENBQUMsc0VBQXNFLFNBQVMsRUFBRSxFQUFFLEtBQUssQ0FBQyxDQUFDO1lBQ3hHLElBQUksQ0FBQyxzQkFBc0IsQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUM7WUFDeEMsT0FBTyxFQUFFLENBQUMsS0FBSyxDQUFDLENBQUM7UUFDckIsQ0FBQyxFQUFDLENBQ0w7YUFDQSxTQUFTLEVBQUUsQ0FBQztJQUNyQixDQUFDOzs7OztJQUVELDJCQUEyQixDQUFDLEdBQVc7UUFDbkMsSUFBSSxDQUFDLFVBQVU7YUFDVixHQUFHLENBQUMsR0FBRyxDQUFDO2FBQ1IsSUFBSSxDQUNELEdBQUc7Ozs7UUFBQyxRQUFRLENBQUMsRUFBRTtZQUNYLElBQUksQ0FBQyxrQkFBa0IsR0FBRyxRQUFRLENBQUM7WUFDbkMsSUFBSSxDQUFDLHNCQUFzQixDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQztRQUMzQyxDQUFDLEVBQUMsRUFDRixVQUFVOzs7O1FBQUMsS0FBSyxDQUFDLEVBQUU7WUFDZixPQUFPLENBQUMsS0FBSyxDQUFDLDZFQUE2RSxHQUFHLEVBQUUsRUFBRSxLQUFLLENBQUMsQ0FBQztZQUN6RyxJQUFJLENBQUMsc0JBQXNCLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDO1lBQ3hDLE9BQU8sRUFBRSxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ3JCLENBQUMsRUFBQyxDQUNMO2FBQ0EsU0FBUyxFQUFFLENBQUM7SUFDckIsQ0FBQzs7O1lBL0RKLFVBQVU7Ozs7WUFMRixVQUFVOzs7Ozs7O0lBT2YsbURBQXdEOztJQUN4RCxnREFBeUI7O0lBQ3pCLCtDQUF3Qjs7Ozs7SUFNWix1Q0FBdUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBIdHRwQ2xpZW50IH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xyXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcbmltcG9ydCB7IE9ic2VydmFibGUsIG9mLCBTdWJqZWN0IH0gZnJvbSAncnhqcyc7XHJcbmltcG9ydCB7IGNhdGNoRXJyb3IsIG1hcCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcclxuXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGNsYXNzIE9pZGNDb25maWdTZXJ2aWNlIHtcclxuICAgIHByaXZhdGUgX29uQ29uZmlndXJhdGlvbkxvYWRlZCA9IG5ldyBTdWJqZWN0PGJvb2xlYW4+KCk7XHJcbiAgICBjbGllbnRDb25maWd1cmF0aW9uOiBhbnk7XHJcbiAgICB3ZWxsS25vd25FbmRwb2ludHM6IGFueTtcclxuXHJcbiAgICBwdWJsaWMgZ2V0IG9uQ29uZmlndXJhdGlvbkxvYWRlZCgpOiBPYnNlcnZhYmxlPGJvb2xlYW4+IHtcclxuICAgICAgICByZXR1cm4gdGhpcy5fb25Db25maWd1cmF0aW9uTG9hZGVkLmFzT2JzZXJ2YWJsZSgpO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgaHR0cENsaWVudDogSHR0cENsaWVudCkge31cclxuXHJcbiAgICBsb2FkKGNvbmZpZ1VybDogc3RyaW5nKSB7XHJcbiAgICAgICAgdGhpcy5odHRwQ2xpZW50XHJcbiAgICAgICAgICAgIC5nZXQoY29uZmlnVXJsKVxyXG4gICAgICAgICAgICAucGlwZShcclxuICAgICAgICAgICAgICAgIG1hcChyZXNwb25zZSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5jbGllbnRDb25maWd1cmF0aW9uID0gcmVzcG9uc2U7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2FkX3VzaW5nX3N0c1NlcnZlcih0aGlzLmNsaWVudENvbmZpZ3VyYXRpb24uc3RzU2VydmVyKTtcclxuICAgICAgICAgICAgICAgIH0pLFxyXG4gICAgICAgICAgICAgICAgY2F0Y2hFcnJvcihlcnJvciA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihgT2lkY0NvbmZpZ1NlcnZpY2UgJ2xvYWQnIHRocmV3IGFuIGVycm9yIG9uIGNhbGxpbmcgJHtjb25maWdVcmx9YCwgZXJyb3IpO1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuX29uQ29uZmlndXJhdGlvbkxvYWRlZC5uZXh0KGZhbHNlKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gb2YoZmFsc2UpO1xyXG4gICAgICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAuc3Vic2NyaWJlKCk7XHJcbiAgICB9XHJcblxyXG4gICAgbG9hZF91c2luZ19zdHNTZXJ2ZXIoc3RzU2VydmVyOiBzdHJpbmcpIHtcclxuICAgICAgICBjb25zdCB1cmwgPSBgJHtzdHNTZXJ2ZXJ9Ly53ZWxsLWtub3duL29wZW5pZC1jb25maWd1cmF0aW9uYDtcclxuXHJcbiAgICAgICAgdGhpcy5odHRwQ2xpZW50XHJcbiAgICAgICAgICAgIC5nZXQodXJsKVxyXG4gICAgICAgICAgICAucGlwZShcclxuICAgICAgICAgICAgICAgIG1hcChyZXNwb25zZSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy53ZWxsS25vd25FbmRwb2ludHMgPSByZXNwb25zZTtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLl9vbkNvbmZpZ3VyYXRpb25Mb2FkZWQubmV4dCh0cnVlKTtcclxuICAgICAgICAgICAgICAgIH0pLFxyXG4gICAgICAgICAgICAgICAgY2F0Y2hFcnJvcihlcnJvciA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihgT2lkY0NvbmZpZ1NlcnZpY2UgJ2xvYWRfdXNpbmdfc3RzU2VydmVyJyB0aHJldyBhbiBlcnJvciBvbiBjYWxsaW5nICR7c3RzU2VydmVyfWAsIGVycm9yKTtcclxuICAgICAgICAgICAgICAgICAgICB0aGlzLl9vbkNvbmZpZ3VyYXRpb25Mb2FkZWQubmV4dChmYWxzZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG9mKGZhbHNlKTtcclxuICAgICAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgIClcclxuICAgICAgICAgICAgLnN1YnNjcmliZSgpO1xyXG4gICAgfVxyXG5cclxuICAgIGxvYWRfdXNpbmdfY3VzdG9tX3N0c1NlcnZlcih1cmw6IHN0cmluZykge1xyXG4gICAgICAgIHRoaXMuaHR0cENsaWVudFxyXG4gICAgICAgICAgICAuZ2V0KHVybClcclxuICAgICAgICAgICAgLnBpcGUoXHJcbiAgICAgICAgICAgICAgICBtYXAocmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMud2VsbEtub3duRW5kcG9pbnRzID0gcmVzcG9uc2U7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5fb25Db25maWd1cmF0aW9uTG9hZGVkLm5leHQodHJ1ZSk7XHJcbiAgICAgICAgICAgICAgICB9KSxcclxuICAgICAgICAgICAgICAgIGNhdGNoRXJyb3IoZXJyb3IgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoYE9pZGNDb25maWdTZXJ2aWNlICdsb2FkX3VzaW5nX2N1c3RvbV9zdHNTZXJ2ZXInIHRocmV3IGFuIGVycm9yIG9uIGNhbGxpbmcgJHt1cmx9YCwgZXJyb3IpO1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuX29uQ29uZmlndXJhdGlvbkxvYWRlZC5uZXh0KGZhbHNlKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gb2YoZmFsc2UpO1xyXG4gICAgICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAuc3Vic2NyaWJlKCk7XHJcbiAgICB9XHJcbn1cclxuIl19