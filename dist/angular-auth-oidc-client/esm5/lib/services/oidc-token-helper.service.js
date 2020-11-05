/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
import { LoggerService } from './oidc.logger.service';
var TokenHelperService = /** @class */ (function () {
    function TokenHelperService(loggerService) {
        this.loggerService = loggerService;
        this.PARTS_OF_TOKEN = 3;
    }
    /**
     * @param {?} dataIdToken
     * @return {?}
     */
    TokenHelperService.prototype.getTokenExpirationDate = /**
     * @param {?} dataIdToken
     * @return {?}
     */
    function (dataIdToken) {
        if (!dataIdToken.hasOwnProperty('exp')) {
            return new Date();
        }
        /** @type {?} */
        var date = new Date(0);
        date.setUTCSeconds(dataIdToken.exp);
        return date;
    };
    /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    TokenHelperService.prototype.getHeaderFromToken = /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    function (token, encoded) {
        if (!this.tokenIsValid(token)) {
            return {};
        }
        return this.getPartOfToken(token, 0, encoded);
    };
    /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    TokenHelperService.prototype.getPayloadFromToken = /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    function (token, encoded) {
        if (!this.tokenIsValid(token)) {
            return {};
        }
        return this.getPartOfToken(token, 1, encoded);
    };
    /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    TokenHelperService.prototype.getSignatureFromToken = /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    function (token, encoded) {
        if (!this.tokenIsValid(token)) {
            return {};
        }
        return this.getPartOfToken(token, 2, encoded);
    };
    /**
     * @private
     * @param {?} token
     * @param {?} index
     * @param {?} encoded
     * @return {?}
     */
    TokenHelperService.prototype.getPartOfToken = /**
     * @private
     * @param {?} token
     * @param {?} index
     * @param {?} encoded
     * @return {?}
     */
    function (token, index, encoded) {
        /** @type {?} */
        var partOfToken = this.extractPartOfToken(token, index);
        if (encoded) {
            return partOfToken;
        }
        /** @type {?} */
        var result = this.urlBase64Decode(partOfToken);
        return JSON.parse(result);
    };
    /**
     * @private
     * @param {?} str
     * @return {?}
     */
    TokenHelperService.prototype.urlBase64Decode = /**
     * @private
     * @param {?} str
     * @return {?}
     */
    function (str) {
        /** @type {?} */
        var output = str.replace(/-/g, '+').replace(/_/g, '/');
        switch (output.length % 4) {
            case 0:
                break;
            case 2:
                output += '==';
                break;
            case 3:
                output += '=';
                break;
            default:
                throw Error('Illegal base64url string!');
        }
        /** @type {?} */
        var decoded = typeof window !== 'undefined' ? window.atob(output) : new Buffer(output, 'base64').toString('binary');
        try {
            // Going backwards: from bytestream, to percent-encoding, to original string.
            return decodeURIComponent(decoded.split('')
                .map((/**
             * @param {?} c
             * @return {?}
             */
            function (c) { return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2); }))
                .join(''));
        }
        catch (err) {
            return decoded;
        }
    };
    /**
     * @private
     * @param {?} token
     * @return {?}
     */
    TokenHelperService.prototype.tokenIsValid = /**
     * @private
     * @param {?} token
     * @return {?}
     */
    function (token) {
        if (!token) {
            this.loggerService.logError("token '" + token + "' is not valid --> token falsy");
            return false;
        }
        if (!((/** @type {?} */ (token))).includes('.')) {
            this.loggerService.logError("token '" + token + "' is not valid --> no dots included");
            return false;
        }
        /** @type {?} */
        var parts = token.split('.');
        if (parts.length !== this.PARTS_OF_TOKEN) {
            this.loggerService.logError("token '" + token + "' is not valid --> token has t have exact three dots");
            return false;
        }
        return true;
    };
    /**
     * @private
     * @param {?} token
     * @param {?} index
     * @return {?}
     */
    TokenHelperService.prototype.extractPartOfToken = /**
     * @private
     * @param {?} token
     * @param {?} index
     * @return {?}
     */
    function (token, index) {
        return token.split('.')[index];
    };
    TokenHelperService.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    TokenHelperService.ctorParameters = function () { return [
        { type: LoggerService }
    ]; };
    return TokenHelperService;
}());
export { TokenHelperService };
if (false) {
    /**
     * @type {?}
     * @private
     */
    TokenHelperService.prototype.PARTS_OF_TOKEN;
    /**
     * @type {?}
     * @private
     */
    TokenHelperService.prototype.loggerService;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy10b2tlbi1oZWxwZXIuc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItYXV0aC1vaWRjLWNsaWVudC8iLCJzb3VyY2VzIjpbImxpYi9zZXJ2aWNlcy9vaWRjLXRva2VuLWhlbHBlci5zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBQzNDLE9BQU8sRUFBRSxhQUFhLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQztBQUV0RDtJQUdJLDRCQUE2QixhQUE0QjtRQUE1QixrQkFBYSxHQUFiLGFBQWEsQ0FBZTtRQURqRCxtQkFBYyxHQUFHLENBQUMsQ0FBQztJQUNpQyxDQUFDOzs7OztJQUU3RCxtREFBc0I7Ozs7SUFBdEIsVUFBdUIsV0FBZ0I7UUFDbkMsSUFBSSxDQUFDLFdBQVcsQ0FBQyxjQUFjLENBQUMsS0FBSyxDQUFDLEVBQUU7WUFDcEMsT0FBTyxJQUFJLElBQUksRUFBRSxDQUFDO1NBQ3JCOztZQUVLLElBQUksR0FBRyxJQUFJLElBQUksQ0FBQyxDQUFDLENBQUM7UUFDeEIsSUFBSSxDQUFDLGFBQWEsQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLENBQUM7UUFFcEMsT0FBTyxJQUFJLENBQUM7SUFDaEIsQ0FBQzs7Ozs7O0lBRUQsK0NBQWtCOzs7OztJQUFsQixVQUFtQixLQUFVLEVBQUUsT0FBZ0I7UUFDM0MsSUFBSSxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUMsS0FBSyxDQUFDLEVBQUU7WUFDM0IsT0FBTyxFQUFFLENBQUM7U0FDYjtRQUVELE9BQU8sSUFBSSxDQUFDLGNBQWMsQ0FBQyxLQUFLLEVBQUUsQ0FBQyxFQUFFLE9BQU8sQ0FBQyxDQUFDO0lBQ2xELENBQUM7Ozs7OztJQUVELGdEQUFtQjs7Ozs7SUFBbkIsVUFBb0IsS0FBVSxFQUFFLE9BQWdCO1FBQzVDLElBQUksQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDLEtBQUssQ0FBQyxF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SSxLQUFLLENBQUMsTUFBTSxLQUFLLElBQUksQ0FBQyxjQUFjLEVBQUU7WUFDdEMsSUFBSSxDQUFDLGFBQWEsQ0FBQyxRQUFRLENBQUMsWUFBVSxLQUFLLHlEQUFzRCxDQUFDLENBQUM7WUFDbkcsT0FBTyxLQUFLLENBQUM7U0FDaEI7UUFFRCxPQUFPLElBQUksQ0FBQztJQUNoQixDQUFDOzs7Ozs7O0lBRU8sK0NBQWtCOzs7Ozs7SUFBMUIsVUFBMkIsS0FBYSxFQUFFLEtBQWE7UUFDbkQsT0FBTyxLQUFLLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQ25DLENBQUM7O2dCQXJHSixVQUFVOzs7O2dCQUZGLGFBQWE7O0lBd0d0Qix5QkFBQztDQUFBLEFBdEdELElBc0dDO1NBckdZLGtCQUFrQjs7Ozs7O0lBQzNCLDRDQUEyQjs7Ozs7SUFDZiwyQ0FBNkMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcbmltcG9ydCB7IExvZ2dlclNlcnZpY2UgfSBmcm9tICcuL29pZGMubG9nZ2VyLnNlcnZpY2UnO1xyXG5cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgVG9rZW5IZWxwZXJTZXJ2aWNlIHtcclxuICAgIHByaXZhdGUgUEFSVFNfT0ZfVE9LRU4gPSAzO1xyXG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBsb2dnZXJTZXJ2aWNlOiBMb2dnZXJTZXJ2aWNlKSB7fVxyXG5cclxuICAgIGdldFRva2VuRXhwaXJhdGlvbkRhdGUoZGF0YUlkVG9rZW46IGFueSk6IERhdGUge1xyXG4gICAgICAgIGlmICghZGF0YUlkVG9rZW4uaGFzT3duUHJvcGVydHkoJ2V4cCcpKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBuZXcgRGF0ZSgpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3QgZGF0ZSA9IG5ldyBEYXRlKDApOyAvLyBUaGUgMCBoZXJlIGlzIHRoZSBrZXksIHdoaWNoIHNldHMgdGhlIGRhdGUgdG8gdGhlIGVwb2NoXHJcbiAgICAgICAgZGF0ZS5zZXRVVENTZWNvbmRzKGRhdGFJZFRva2VuLmV4cCk7XHJcblxyXG4gICAgICAgIHJldHVybiBkYXRlO1xyXG4gICAgfVxyXG5cclxuICAgIGdldEhlYWRlckZyb21Ub2tlbih0b2tlbjogYW55LCBlbmNvZGVkOiBib29sZWFuKSB7XHJcbiAgICAgICAgaWYgKCF0aGlzLnRva2VuSXNWYWxpZCh0b2tlbikpIHtcclxuICAgICAgICAgICAgcmV0dXJuIHt9O1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2V0UGFydE9mVG9rZW4odG9rZW4sIDAsIGVuY29kZWQpO1xyXG4gICAgfVxyXG5cclxuICAgIGdldFBheWxvYWRGcm9tVG9rZW4odG9rZW46IGFueSwgZW5jb2RlZDogYm9vbGVhbikge1xyXG4gICAgICAgIGlmICghdGhpcy50b2tlbklzVmFsaWQodG9rZW4pKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB7fTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0aGlzLmdldFBhcnRPZlRva2VuKHRva2VuLCAxLCBlbmNvZGVkKTtcclxuICAgIH1cclxuXHJcbiAgICBnZXRTaWduYXR1cmVGcm9tVG9rZW4odG9rZW46IGFueSwgZW5jb2RlZDogYm9vbGVhbikge1xyXG4gICAgICAgIGlmICghdGhpcy50b2tlbklzVmFsaWQodG9rZW4pKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB7fTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0aGlzLmdldFBhcnRPZlRva2VuKHRva2VuLCAyLCBlbmNvZGVkKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIGdldFBhcnRPZlRva2VuKHRva2VuOiBzdHJpbmcsIGluZGV4OiBudW1iZXIsIGVuY29kZWQ6IGJvb2xlYW4pIHtcclxuICAgICAgICBjb25zdCBwYXJ0T2ZUb2tlbiA9IHRoaXMuZXh0cmFjdFBhcnRPZlRva2VuKHRva2VuLCBpbmRleCk7XHJcblxyXG4gICAgICAgIGlmIChlbmNvZGVkKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBwYXJ0T2ZUb2tlbjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IHJlc3VsdCA9IHRoaXMudXJsQmFzZTY0RGVjb2RlKHBhcnRPZlRva2VuKTtcclxuICAgICAgICByZXR1cm4gSlNPTi5wYXJzZShyZXN1bHQpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgdXJsQmFzZTY0RGVjb2RlKHN0cjogc3RyaW5nKSB7XHJcbiAgICAgICAgbGV0IG91dHB1dCA9IHN0ci5yZXBsYWNlKC8tL2csICcrJykucmVwbGFjZSgvXy9nLCAnLycpO1xyXG4gICAgICAgIHN3aXRjaCAob3V0cHV0Lmxlbmd0aCAlIDQpIHtcclxuICAgICAgICAgICAgY2FzZSAwOlxyXG4gICAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICAgIGNhc2UgMjpcclxuICAgICAgICAgICAgICAgIG91dHB1dCArPSAnPT0nO1xyXG4gICAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICAgIGNhc2UgMzpcclxuICAgICAgICAgICAgICAgIG91dHB1dCArPSAnPSc7XHJcbiAgICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgIHRocm93IEVycm9yKCdJbGxlZ2FsIGJhc2U2NHVybCBzdHJpbmchJyk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBkZWNvZGVkID0gdHlwZW9mIHdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcgPyB3aW5kb3cuYXRvYihvdXRwdXQpIDogbmV3IEJ1ZmZlcihvdXRwdXQsICdiYXNlNjQnKS50b1N0cmluZygnYmluYXJ5Jyk7XHJcblxyXG4gICAgICAgIHRyeSB7XHJcbiAgICAgICAgICAgIC8vIEdvaW5nIGJhY2t3YXJkczogZnJvbSBieXRlc3RyZWFtLCB0byBwZXJjZW50LWVuY29kaW5nLCB0byBvcmlnaW5hbCBzdHJpbmcuXHJcbiAgICAgICAgICAgIHJldHVybiBkZWNvZGVVUklDb21wb25lbnQoZGVjb2RlZC5zcGxpdCgnJylcclxuICAgICAgICAgICAgICAgIC5tYXAoKGM6IHN0cmluZykgPT4gJyUnICsgKCcwMCcgKyBjLmNoYXJDb2RlQXQoMCkudG9TdHJpbmcoMTYpKS5zbGljZSgtMikpXHJcbiAgICAgICAgICAgICAgICAuam9pbignJykpO1xyXG4gICAgICAgIH0gY2F0Y2ggKGVycikge1xyXG4gICAgICAgICAgICByZXR1cm4gZGVjb2RlZDtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSB0b2tlbklzVmFsaWQodG9rZW46IHN0cmluZykge1xyXG4gICAgICAgIGlmICghdG9rZW4pIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0Vycm9yKGB0b2tlbiAnJHt0b2tlbn0nIGlzIG5vdCB2YWxpZCAtLT4gdG9rZW4gZmFsc3lgKTtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKCEodG9rZW4gYXMgc3RyaW5nKS5pbmNsdWRlcygnLicpKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dFcnJvcihgdG9rZW4gJyR7dG9rZW59JyBpcyBub3QgdmFsaWQgLS0+IG5vIGRvdHMgaW5jbHVkZWRgKTtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3QgcGFydHMgPSB0b2tlbi5zcGxpdCgnLicpO1xyXG5cclxuICAgICAgICBpZiAocGFydHMubGVuZ3RoICE9PSB0aGlzLlBBUlRTX09GX1RPS0VOKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dFcnJvcihgdG9rZW4gJyR7dG9rZW59JyBpcyBub3QgdmFsaWQgLS0+IHRva2VuIGhhcyB0IGhhdmUgZXhhY3QgdGhyZWUgZG90c2ApO1xyXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIGV4dHJhY3RQYXJ0T2ZUb2tlbih0b2tlbjogc3RyaW5nLCBpbmRleDogbnVtYmVyKSB7XHJcbiAgICAgICAgcmV0dXJuIHRva2VuLnNwbGl0KCcuJylbaW5kZXhdO1xyXG4gICAgfVxyXG59XHJcbiJdfQ==