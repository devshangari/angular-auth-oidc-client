/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
var OidcDataService = /** @class */ (function () {
    function OidcDataService(httpClient) {
        this.httpClient = httpClient;
    }
    /**
     * @template T
     * @param {?} url
     * @return {?}
     */
    OidcDataService.prototype.getWellknownEndpoints = /**
     * @template T
     * @param {?} url
     * @return {?}
     */
    function (url) {
        /** @type {?} */
        var headers = new HttpHeaders();
        headers = headers.set('Accept', 'application/json');
        return this.httpClient.get(url, {
            headers: headers,
        });
    };
    /**
     * @template T
     * @param {?} url
     * @param {?} token
     * @return {?}
     */
    OidcDataService.prototype.getIdentityUserData = /**
     * @template T
     * @param {?} url
     * @param {?} token
     * @return {?}
     */
    function (url, token) {
        /** @type {?} */
        var headers = new HttpHeaders();
        headers = headers.set('Accept', 'application/json');
        headers = headers.set('Authorization', 'Bearer ' + decodeURIComponent(token));
        return this.httpClient.get(url, {
            headers: headers,
        });
    };
    /**
     * @template T
     * @param {?} url
     * @return {?}
     */
    OidcDataService.prototype.get = /**
     * @template T
     * @param {?} url
     * @return {?}
     */
    function (url) {
        /** @type {?} */
        var headers = new HttpHeaders();
        headers = headers.set('Accept', 'application/json');
        return this.httpClient.get(url, {
            headers: headers,
        });
    };
    OidcDataService.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    OidcDataService.ctorParameters = function () { return [
        { type: HttpClient }
    ]; };
    return OidcDataService;
}());
export { OidcDataService };
if (false) {
    /**
     * @type {?}
     * @private
     */
    OidcDataService.prototype.httpClient;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy1kYXRhLnNlcnZpY2UuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLWF1dGgtb2lkYy1jbGllbnQvIiwic291cmNlcyI6WyJsaWIvZGF0YS1zZXJ2aWNlcy9vaWRjLWRhdGEuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxXQUFXLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUMvRCxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBRzNDO0lBRUkseUJBQW9CLFVBQXNCO1FBQXRCLGVBQVUsR0FBVixVQUFVLENBQVk7SUFBRyxDQUFDOzs7Ozs7SUFFOUMsK0NBQXFCOzs7OztJQUFyQixVQUF5QixHQUFXOztZQUM1QixPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUU7UUFDL0IsT0FBTyxHQUFHLE9BQU8sQ0FBQyxHQUFHLENBQUMsUUFBUSxFQUFFLGtCQUFrQixDQUFDLENBQUM7UUFFcEQsT0FBTyxJQUFJLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBSSxHQUFHLEVBQUU7WUFDL0IsT0FBTyxFQUFFLE9BQU87U0FDbkIsQ0FBQyxDQUFDO0lBQ1AsQ0FBQzs7Ozs7OztJQUVELDZDQUFtQjs7Ozs7O0lBQW5CLFVBQXVCLEdBQVcsRUFBRSxLQUFhOztZQUN6QyxPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUU7UUFDL0IsT0FBTyxHQUFHLE9BQU8sQ0FBQyxHQUFHLENBQUMsUUFBUSxFQUFFLGtCQUFrQixDQUFDLENBQUM7UUFDcEQsT0FBTyxHQUFHLE9BQU8sQ0FBQyxHQUFHLENBQUMsZUFBZSxFQUFFLFNBQVMsR0FBRyxrQkFBa0IsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDO1FBRTlFLE9BQU8sSUFBSSxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUksR0FBRyxFQUFFO1lBQy9CLE9BQU8sRUFBRSxPQUFPO1NBQ25CLENBQUMsQ0FBQztJQUNQLENBQUM7Ozs7OztJQUVELDZCQUFHOzs7OztJQUFILFVBQU8sR0FBVzs7WUFDVixPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUU7UUFDL0IsT0FBTyxHQUFHLE9BQU8sQ0FBQyxHQUFHLENBQUMsUUFBUSxFQUFFLGtCQUFrQixDQUFDLENBQUM7UUFFcEQsT0FBTyxJQUFJLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBSSxHQUFHLEVBQUU7WUFDL0IsT0FBTyxFQUFFLE9BQU87U0FDbkIsQ0FBQyxDQUFDO0lBQ1AsQ0FBQzs7Z0JBOUJKLFVBQVU7Ozs7Z0JBSkYsVUFBVTs7SUFtQ25CLHNCQUFDO0NBQUEsQUEvQkQsSUErQkM7U0E5QlksZUFBZTs7Ozs7O0lBQ1oscUNBQThCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSHR0cENsaWVudCwgSHR0cEhlYWRlcnMgfSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XHJcbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcclxuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xyXG5cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgT2lkY0RhdGFTZXJ2aWNlIHtcclxuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgaHR0cENsaWVudDogSHR0cENsaWVudCkge31cclxuXHJcbiAgICBnZXRXZWxsa25vd25FbmRwb2ludHM8VD4odXJsOiBzdHJpbmcpOiBPYnNlcnZhYmxlPFQ+IHtcclxuICAgICAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpO1xyXG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQWNjZXB0JywgJ2FwcGxpY2F0aW9uL2pzb24nKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuaHR0cENsaWVudC5nZXQ8VD4odXJsLCB7XHJcbiAgICAgICAgICAgIGhlYWRlcnM6IGhlYWRlcnMsXHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0SWRlbnRpdHlVc2VyRGF0YTxUPih1cmw6IHN0cmluZywgdG9rZW46IHN0cmluZyk6IE9ic2VydmFibGU8VD4ge1xyXG4gICAgICAgIGxldCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCk7XHJcbiAgICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KCdBY2NlcHQnLCAnYXBwbGljYXRpb24vanNvbicpO1xyXG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCZWFyZXIgJyArIGRlY29kZVVSSUNvbXBvbmVudCh0b2tlbikpO1xyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5odHRwQ2xpZW50LmdldDxUPih1cmwsIHtcclxuICAgICAgICAgICAgaGVhZGVyczogaGVhZGVycyxcclxuICAgICAgICB9KTtcclxuICAgIH1cclxuXHJcbiAgICBnZXQ8VD4odXJsOiBzdHJpbmcpOiBPYnNlcnZhYmxlPFQ+IHtcclxuICAgICAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpO1xyXG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQWNjZXB0JywgJ2FwcGxpY2F0aW9uL2pzb24nKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuaHR0cENsaWVudC5nZXQ8VD4odXJsLCB7XHJcbiAgICAgICAgICAgIGhlYWRlcnM6IGhlYWRlcnMsXHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcbn1cclxuIl19