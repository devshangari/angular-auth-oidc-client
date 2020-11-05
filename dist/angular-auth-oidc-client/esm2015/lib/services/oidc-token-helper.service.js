/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
import { LoggerService } from './oidc.logger.service';
export class TokenHelperService {
    /**
     * @param {?} loggerService
     */
    constructor(loggerService) {
        this.loggerService = loggerService;
        this.PARTS_OF_TOKEN = 3;
    }
    /**
     * @param {?} dataIdToken
     * @return {?}
     */
    getTokenExpirationDate(dataIdToken) {
        if (!dataIdToken.hasOwnProperty('exp')) {
            return new Date();
        }
        /** @type {?} */
        const date = new Date(0);
        date.setUTCSeconds(dataIdToken.exp);
        return date;
    }
    /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    getHeaderFromToken(token, encoded) {
        if (!this.tokenIsValid(token)) {
            return {};
        }
        return this.getPartOfToken(token, 0, encoded);
    }
    /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    getPayloadFromToken(token, encoded) {
        if (!this.tokenIsValid(token)) {
            return {};
        }
        return this.getPartOfToken(token, 1, encoded);
    }
    /**
     * @param {?} token
     * @param {?} encoded
     * @return {?}
     */
    getSignatureFromToken(token, encoded) {
        if (!this.tokenIsValid(token)) {
            return {};
        }
        return this.getPartOfToken(token, 2, encoded);
    }
    /**
     * @private
     * @param {?} token
     * @param {?} index
     * @param {?} encoded
     * @return {?}
     */
    getPartOfToken(token, index, encoded) {
        /** @type {?} */
        const partOfToken = this.extractPartOfToken(token, index);
        if (encoded) {
            return partOfToken;
        }
        /** @type {?} */
        const result = this.urlBase64Decode(partOfToken);
        return JSON.parse(result);
    }
    /**
     * @private
     * @param {?} str
     * @return {?}
     */
    urlBase64Decode(str) {
        /** @type {?} */
        let output = str.replace(/-/g, '+').replace(/_/g, '/');
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
        const decoded = typeof window !== 'undefined' ? window.atob(output) : new Buffer(output, 'base64').toString('binary');
        try {
            // Going backwards: from bytestream, to percent-encoding, to original string.
            return decodeURIComponent(decoded.split('')
                .map((/**
             * @param {?} c
             * @return {?}
             */
            (c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)))
                .join(''));
        }
        catch (err) {
            return decoded;
        }
    }
    /**
     * @private
     * @param {?} token
     * @return {?}
     */
    tokenIsValid(token) {
        if (!token) {
            this.loggerService.logError(`token '${token}' is not valid --> token falsy`);
            return false;
        }
        if (!((/** @type {?} */ (token))).includes('.')) {
            this.loggerService.logError(`token '${token}' is not valid --> no dots included`);
            return false;
        }
        /** @type {?} */
        const parts = token.split('.');
        if (parts.length !== this.PARTS_OF_TOKEN) {
            this.loggerService.logError(`token '${token}' is not valid --> token has t have exact three dots`);
            return false;
        }
        return true;
    }
    /**
     * @private
     * @param {?} token
     * @param {?} index
     * @return {?}
     */
    extractPartOfToken(token, index) {
        return token.split('.')[index];
    }
}
TokenHelperService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
TokenHelperService.ctorParameters = () => [
    { type: LoggerService }
];
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy10b2tlbi1oZWxwZXIuc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItYXV0aC1vaWRjLWNsaWVudC8iLCJzb3VyY2VzIjpbImxpYi9zZXJ2aWNlcy9vaWRjLXRva2VuLWhlbHBlci5zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBQzNDLE9BQU8sRUFBRSxhQUFhLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQztBQUd0RCxNQUFNLE9BQU8sa0JBQWtCOzs7O0lBRTNCLFlBQTZCLGFBQTRCO1FBQTVCLGtCQUFhLEdBQWIsYUFBYSxDQUFlO1FBRGpELG1CQUFjLEdBQUcsQ0FBQyxDQUFDO0lBQ2lDLENBQUM7Ozs7O0lBRTdELHNCQUFzQixDQUFDLFdBQWdCO1FBQ25DLElBQUksQ0FBQyxXQUFXLENBQUMsY0FBYyxDQUFDLEtBQUssQ0FBQyxFQUFFO1lBQ3BDLE9BQU8sSUFBSSxJQUFJLEVBQUUsQ0FBQztTQUNyQjs7Y0FFSyxJQUFJLEdBQUcsSUFBSSxJQUFJLENBQUMsQ0FBQyxDQUFDO1FBQ3hCLElBQUksQ0FBQyxhQUFhLENBQUMsV0FBVyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBRXBDLE9BQU8sSUFBSSxDQUFDO0lBQ2hCLENBQUM7Ozs7OztJQUVELGtCQUFrQixDQUFDLEtBQVUsRUFBRSxPQUFnQjtRQUMzQyxJQUFJLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxLQUFLLENBQUMsRUFBRTtZQUMzQixPQUFPLEVBQUUsQ0FBQztTQUNiO1FBRUQsT0FBTyxJQUFJLENBQUMsY0FBYyxDQUFDLEtBQUssRUFBRSxDQUFDLEVBQUUsT0FBTyxDQUFDLENBQUM7SUFDbEQsQ0FBQzs7Ozs7O0lBRUQsbUJBQW1CLENBQUMsS0FBVSxFQUFFLE9BQWdCO1FBQzVDLElBQUksQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDLEtBQUssQ0FBQyxFQUFFO1lBQzNCLE9B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UUFBUSxDQUFDLFVBQVUsS0FBSyxzREFBc0QsQ0FBQyxDQUFDO1lBQ25HLE9BQU8sS0FBSyxDQUFDO1NBQ2hCO1FBRUQsT0FBTyxJQUFJLENBQUM7SUFDaEIsQ0FBQzs7Ozs7OztJQUVPLGtCQUFrQixDQUFDLEtBQWEsRUFBRSxLQUFhO1FBQ25ELE9BQU8sS0FBSyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUNuQyxDQUFDOzs7WUFyR0osVUFBVTs7OztZQUZGLGFBQWE7Ozs7Ozs7SUFJbEIsNENBQTJCOzs7OztJQUNmLDJDQUE2QyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcclxuaW1wb3J0IHsgTG9nZ2VyU2VydmljZSB9IGZyb20gJy4vb2lkYy5sb2dnZXIuc2VydmljZSc7XHJcblxyXG5ASW5qZWN0YWJsZSgpXHJcbmV4cG9ydCBjbGFzcyBUb2tlbkhlbHBlclNlcnZpY2Uge1xyXG4gICAgcHJpdmF0ZSBQQVJUU19PRl9UT0tFTiA9IDM7XHJcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGxvZ2dlclNlcnZpY2U6IExvZ2dlclNlcnZpY2UpIHt9XHJcblxyXG4gICAgZ2V0VG9rZW5FeHBpcmF0aW9uRGF0ZShkYXRhSWRUb2tlbjogYW55KTogRGF0ZSB7XHJcbiAgICAgICAgaWYgKCFkYXRhSWRUb2tlbi5oYXNPd25Qcm9wZXJ0eSgnZXhwJykpIHtcclxuICAgICAgICAgICAgcmV0dXJuIG5ldyBEYXRlKCk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBkYXRlID0gbmV3IERhdGUoMCk7IC8vIFRoZSAwIGhlcmUgaXMgdGhlIGtleSwgd2hpY2ggc2V0cyB0aGUgZGF0ZSB0byB0aGUgZXBvY2hcclxuICAgICAgICBkYXRlLnNldFVUQ1NlY29uZHMoZGF0YUlkVG9rZW4uZXhwKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIGRhdGU7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0SGVhZGVyRnJvbVRva2VuKHRva2VuOiBhbnksIGVuY29kZWQ6IGJvb2xlYW4pIHtcclxuICAgICAgICBpZiAoIXRoaXMudG9rZW5Jc1ZhbGlkKHRva2VuKSkge1xyXG4gICAgICAgICAgICByZXR1cm4ge307XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdGhpcy5nZXRQYXJ0T2ZUb2tlbih0b2tlbiwgMCwgZW5jb2RlZCk7XHJcbiAgICB9XHJcblxyXG4gICAgZ2V0UGF5bG9hZEZyb21Ub2tlbih0b2tlbjogYW55LCBlbmNvZGVkOiBib29sZWFuKSB7XHJcbiAgICAgICAgaWYgKCF0aGlzLnRva2VuSXNWYWxpZCh0b2tlbikpIHtcclxuICAgICAgICAgICAgcmV0dXJuIHt9O1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2V0UGFydE9mVG9rZW4odG9rZW4sIDEsIGVuY29kZWQpO1xyXG4gICAgfVxyXG5cclxuICAgIGdldFNpZ25hdHVyZUZyb21Ub2tlbih0b2tlbjogYW55LCBlbmNvZGVkOiBib29sZWFuKSB7XHJcbiAgICAgICAgaWYgKCF0aGlzLnRva2VuSXNWYWxpZCh0b2tlbikpIHtcclxuICAgICAgICAgICAgcmV0dXJuIHt9O1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2V0UGFydE9mVG9rZW4odG9rZW4sIDIsIGVuY29kZWQpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgZ2V0UGFydE9mVG9rZW4odG9rZW46IHN0cmluZywgaW5kZXg6IG51bWJlciwgZW5jb2RlZDogYm9vbGVhbikge1xyXG4gICAgICAgIGNvbnN0IHBhcnRPZlRva2VuID0gdGhpcy5leHRyYWN0UGFydE9mVG9rZW4odG9rZW4sIGluZGV4KTtcclxuXHJcbiAgICAgICAgaWYgKGVuY29kZWQpIHtcclxuICAgICAgICAgICAgcmV0dXJuIHBhcnRPZlRva2VuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3QgcmVzdWx0ID0gdGhpcy51cmxCYXNlNjREZWNvZGUocGFydE9mVG9rZW4pO1xyXG4gICAgICAgIHJldHVybiBKU09OLnBhcnNlKHJlc3VsdCk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSB1cmxCYXNlNjREZWNvZGUoc3RyOiBzdHJpbmcpIHtcclxuICAgICAgICBsZXQgb3V0cHV0ID0gc3RyLnJlcGxhY2UoLy0vZywgJysnKS5yZXBsYWNlKC9fL2csICcvJyk7XHJcbiAgICAgICAgc3dpdGNoIChvdXRwdXQubGVuZ3RoICUgNCkge1xyXG4gICAgICAgICAgICBjYXNlIDA6XHJcbiAgICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgICAgY2FzZSAyOlxyXG4gICAgICAgICAgICAgICAgb3V0cHV0ICs9ICc9PSc7XHJcbiAgICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgICAgY2FzZSAzOlxyXG4gICAgICAgICAgICAgICAgb3V0cHV0ICs9ICc9JztcclxuICAgICAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICAgICAgdGhyb3cgRXJyb3IoJ0lsbGVnYWwgYmFzZTY0dXJsIHN0cmluZyEnKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IGRlY29kZWQgPSB0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJyA/IHdpbmRvdy5hdG9iKG91dHB1dCkgOiBuZXcgQnVmZmVyKG91dHB1dCwgJ2Jhc2U2NCcpLnRvU3RyaW5nKCdiaW5hcnknKTtcclxuXHJcbiAgICAgICAgdHJ5IHtcclxuICAgICAgICAgICAgLy8gR29pbmcgYmFja3dhcmRzOiBmcm9tIGJ5dGVzdHJlYW0sIHRvIHBlcmNlbnQtZW5jb2RpbmcsIHRvIG9yaWdpbmFsIHN0cmluZy5cclxuICAgICAgICAgICAgcmV0dXJuIGRlY29kZVVSSUNvbXBvbmVudChkZWNvZGVkLnNwbGl0KCcnKVxyXG4gICAgICAgICAgICAgICAgLm1hcCgoYzogc3RyaW5nKSA9PiAnJScgKyAoJzAwJyArIGMuY2hhckNvZGVBdCgwKS50b1N0cmluZygxNikpLnNsaWNlKC0yKSlcclxuICAgICAgICAgICAgICAgIC5qb2luKCcnKSk7XHJcbiAgICAgICAgfSBjYXRjaCAoZXJyKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBkZWNvZGVkO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIHRva2VuSXNWYWxpZCh0b2tlbjogc3RyaW5nKSB7XHJcbiAgICAgICAgaWYgKCF0b2tlbikge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRXJyb3IoYHRva2VuICcke3Rva2VufScgaXMgbm90IHZhbGlkIC0tPiB0b2tlbiBmYWxzeWApO1xyXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoISh0b2tlbiBhcyBzdHJpbmcpLmluY2x1ZGVzKCcuJykpIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0Vycm9yKGB0b2tlbiAnJHt0b2tlbn0nIGlzIG5vdCB2YWxpZCAtLT4gbm8gZG90cyBpbmNsdWRlZGApO1xyXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBwYXJ0cyA9IHRva2VuLnNwbGl0KCcuJyk7XHJcblxyXG4gICAgICAgIGlmIChwYXJ0cy5sZW5ndGggIT09IHRoaXMuUEFSVFNfT0ZfVE9LRU4pIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0Vycm9yKGB0b2tlbiAnJHt0b2tlbn0nIGlzIG5vdCB2YWxpZCAtLT4gdG9rZW4gaGFzIHQgaGF2ZSBleGFjdCB0aHJlZSBkb3RzYCk7XHJcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgZXh0cmFjdFBhcnRPZlRva2VuKHRva2VuOiBzdHJpbmcsIGluZGV4OiBudW1iZXIpIHtcclxuICAgICAgICByZXR1cm4gdG9rZW4uc3BsaXQoJy4nKVtpbmRleF07XHJcbiAgICB9XHJcbn1cclxuIl19