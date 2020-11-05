/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
export class OidcDataService {
    /**
     * @param {?} httpClient
     */
    constructor(httpClient) {
        this.httpClient = httpClient;
    }
    /**
     * @template T
     * @param {?} url
     * @return {?}
     */
    getWellknownEndpoints(url) {
        /** @type {?} */
        let headers = new HttpHeaders();
        headers = headers.set('Accept', 'application/json');
        return this.httpClient.get(url, {
            headers: headers,
        });
    }
    /**
     * @template T
     * @param {?} url
     * @param {?} token
     * @return {?}
     */
    getIdentityUserData(url, token) {
        /** @type {?} */
        let headers = new HttpHeaders();
        headers = headers.set('Accept', 'application/json');
        headers = headers.set('Authorization', 'Bearer ' + decodeURIComponent(token));
        return this.httpClient.get(url, {
            headers: headers,
        });
    }
    /**
     * @template T
     * @param {?} url
     * @return {?}
     */
    get(url) {
        /** @type {?} */
        let headers = new HttpHeaders();
        headers = headers.set('Accept', 'application/json');
        return this.httpClient.get(url, {
            headers: headers,
        });
    }
}
OidcDataService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcDataService.ctorParameters = () => [
    { type: HttpClient }
];
if (false) {
    /**
     * @type {?}
     * @private
     */
    OidcDataService.prototype.httpClient;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy1kYXRhLnNlcnZpY2UuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLWF1dGgtb2lkYy1jbGllbnQvIiwic291cmNlcyI6WyJsaWIvZGF0YS1zZXJ2aWNlcy9vaWRjLWRhdGEuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxXQUFXLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUMvRCxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBSTNDLE1BQU0sT0FBTyxlQUFlOzs7O0lBQ3hCLFlBQW9CLFVBQXNCO1FBQXRCLGVBQVUsR0FBVixVQUFVLENBQVk7SUFBRyxDQUFDOzs7Ozs7SUFFOUMscUJBQXFCLENBQUksR0FBVzs7WUFDNUIsT0FBTyxHQUFHLElBQUksV0FBVyxFQUFFO1FBQy9CLE9BQU8sR0FBRyxPQUFPLENBQUMsR0FBRyxDQUFDLFFBQVEsRUFBRSxrQkFBa0IsQ0FBQyxDQUFDO1FBRXBELE9BQU8sSUFBSSxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUksR0FBRyxFQUFFO1lBQy9CLE9BQU8sRUFBRSxPQUFPO1NBQ25CLENBQUMsQ0FBQztJQUNQLENBQUM7Ozs7Ozs7SUFFRCxtQkFBbUIsQ0FBSSxHQUFXLEVBQUUsS0FBYTs7WUFDekMsT0FBTyxHQUFHLElBQUksV0FBVyxFQUFFO1FBQy9CLE9BQU8sR0FBRyxPQUFPLENBQUMsR0FBRyxDQUFDLFFBQVEsRUFBRSxrQkFBa0IsQ0FBQyxDQUFDO1FBQ3BELE9BQU8sR0FBRyxPQUFPLENBQUMsR0FBRyxDQUFDLGVBQWUsRUFBRSxTQUFTLEdBQUcsa0JBQWtCLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQztRQUU5RSxPQUFPLElBQUksQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFJLEdBQUcsRUFBRTtZQUMvQixPQUFPLEVBQUUsT0FBTztTQUNuQixDQUFDLENBQUM7SUFDUCxDQUFDOzs7Ozs7SUFFRCxHQUFHLENBQUksR0FBVzs7WUFDVixPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUU7UUFDL0IsT0FBTyxHQUFHLE9BQU8sQ0FBQyxHQUFHLENBQUMsUUFBUSxFQUFFLGtCQUFrQixDQUFDLENBQUM7UUFFcEQsT0FBTyxJQUFJLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBSSxHQUFHLEVBQUU7WUFDL0IsT0FBTyxFQUFFLE9BQU87U0FDbkIsQ0FBQyxDQUFDO0lBQ1AsQ0FBQzs7O1lBOUJKLFVBQVU7Ozs7WUFKRixVQUFVOzs7Ozs7O0lBTUgscUNBQThCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSHR0cENsaWVudCwgSHR0cEhlYWRlcnMgfSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XHJcbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcclxuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xyXG5cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgT2lkY0RhdGFTZXJ2aWNlIHtcclxuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgaHR0cENsaWVudDogSHR0cENsaWVudCkge31cclxuXHJcbiAgICBnZXRXZWxsa25vd25FbmRwb2ludHM8VD4odXJsOiBzdHJpbmcpOiBPYnNlcnZhYmxlPFQ+IHtcclxuICAgICAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpO1xyXG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQWNjZXB0JywgJ2FwcGxpY2F0aW9uL2pzb24nKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuaHR0cENsaWVudC5nZXQ8VD4odXJsLCB7XHJcbiAgICAgICAgICAgIGhlYWRlcnM6IGhlYWRlcnMsXHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0SWRlbnRpdHlVc2VyRGF0YTxUPih1cmw6IHN0cmluZywgdG9rZW46IHN0cmluZyk6IE9ic2VydmFibGU8VD4ge1xyXG4gICAgICAgIGxldCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCk7XHJcbiAgICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KCdBY2NlcHQnLCAnYXBwbGljYXRpb24vanNvbicpO1xyXG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCZWFyZXIgJyArIGRlY29kZVVSSUNvbXBvbmVudCh0b2tlbikpO1xyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5odHRwQ2xpZW50LmdldDxUPih1cmwsIHtcclxuICAgICAgICAgICAgaGVhZGVyczogaGVhZGVycyxcclxuICAgICAgICB9KTtcclxuICAgIH1cclxuXHJcbiAgICBnZXQ8VD4odXJsOiBzdHJpbmcpOiBPYnNlcnZhYmxlPFQ+IHtcclxuICAgICAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpO1xyXG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQWNjZXB0JywgJ2FwcGxpY2F0aW9uL2pzb24nKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuaHR0cENsaWVudC5nZXQ8VD4odXJsLCB7XHJcbiAgICAgICAgICAgIGhlYWRlcnM6IGhlYWRlcnMsXHJcbiAgICAgICAgfSk7XHJcbiAgICB9XHJcbn1cclxuIl19