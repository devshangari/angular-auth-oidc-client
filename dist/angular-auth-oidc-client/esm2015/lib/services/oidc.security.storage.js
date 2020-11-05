/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
import { AuthConfiguration } from '../modules/auth.configuration';
/**
 * Implement this class-interface to create a custom storage.
 * @abstract
 */
export class OidcSecurityStorage {
}
OidcSecurityStorage.decorators = [
    { type: Injectable }
];
if (false) {
    /**
     * This method must contain the logic to read the storage.
     * @abstract
     * @param {?} key
     * @return {?} The value of the given key
     */
    OidcSecurityStorage.prototype.read = function (key) { };
    /**
     * This method must contain the logic to write the storage.
     * @abstract
     * @param {?} key
     * @param {?} value The value for the given key
     * @return {?}
     */
    OidcSecurityStorage.prototype.write = function (key, value) { };
}
export class BrowserStorage {
    /**
     * @param {?} authConfiguration
     */
    constructor(authConfiguration) {
        this.authConfiguration = authConfiguration;
        this.hasStorage = typeof Storage !== 'undefined';
    }
    /**
     * @param {?} key
     * @return {?}
     */
    read(key) {
        if (this.hasStorage) {
            return JSON.parse(this.authConfiguration.storage.getItem(key + '_' + this.authConfiguration.client_id));
        }
        return;
    }
    /**
     * @param {?} key
     * @param {?} value
     * @return {?}
     */
    write(key, value) {
        if (this.hasStorage) {
            value = value === undefined ? null : value;
            this.authConfiguration.storage.setItem(key + '_' + this.authConfiguration.client_id, JSON.stringify(value));
        }
    }
}
BrowserStorage.decorators = [
    { type: Injectable }
];
/** @nocollapse */
BrowserStorage.ctorParameters = () => [
    { type: AuthConfiguration }
];
if (false) {
    /**
     * @type {?}
     * @private
     */
    BrowserStorage.prototype.hasStorage;
    /**
     * @type {?}
     * @private
     */
    BrowserStorage.prototype.authConfiguration;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS5zdG9yYWdlLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1hdXRoLW9pZGMtY2xpZW50LyIsInNvdXJjZXMiOlsibGliL3NlcnZpY2VzL29pZGMuc2VjdXJpdHkuc3RvcmFnZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSwrQkFBK0IsQ0FBQzs7Ozs7QUFNbEUsTUFBTSxPQUFnQixtQkFBbUI7OztZQUR4QyxVQUFVOzs7Ozs7Ozs7SUFPUCx3REFBdUM7Ozs7Ozs7O0lBT3ZDLGdFQUFxRDs7QUFJekQsTUFBTSxPQUFPLGNBQWM7Ozs7SUFHdkIsWUFBb0IsaUJBQW9DO1FBQXBDLHNCQUFpQixHQUFqQixpQkFBaUIsQ0FBbUI7UUFDcEQsSUFBSSxDQUFDLFVBQVUsR0FBRyxPQUFPLE9BQU8sS0FBSyxXQUFXLENBQUM7SUFDckQsQ0FBQzs7Ozs7SUFFTSxJQUFJLENBQUMsR0FBVztRQUNuQixJQUFJLElBQUksQ0FBQyxVQUFVLEVBQUU7WUFDakIsT0FBTyxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLEdBQUcsR0FBRyxHQUFHLEdBQUcsSUFBSSxDQUFDLGlCQUFpQixDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUM7U0FDM0c7UUFFRCxPQUFPO0lBQ1gsQ0FBQzs7Ozs7O0lBRU0sS0FBSyxDQUFDLEdBQVcsRUFBRSxLQUFVO1FBQ2hDLElBQUksSUFBSSxDQUFDLFVBQVUsRUFBRTtZQUNqQixLQUFLLEdBQUcsS0FBSyxLQUFLLFNBQVMsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUM7WUFDM0MsSUFBSSxDQUFDLGlCQUFpQixDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsR0FBRyxHQUFHLEdBQUcsR0FBRyxJQUFJLENBQUMsaUJBQWlCLENBQUMsU0FBUyxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQztTQUMvRztJQUNMLENBQUM7OztZQXJCSixVQUFVOzs7O1lBdEJGLGlCQUFpQjs7Ozs7OztJQXdCdEIsb0NBQTRCOzs7OztJQUVoQiwyQ0FBNEMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcbmltcG9ydCB7IEF1dGhDb25maWd1cmF0aW9uIH0gZnJvbSAnLi4vbW9kdWxlcy9hdXRoLmNvbmZpZ3VyYXRpb24nO1xyXG5cclxuLyoqXHJcbiAqIEltcGxlbWVudCB0aGlzIGNsYXNzLWludGVyZmFjZSB0byBjcmVhdGUgYSBjdXN0b20gc3RvcmFnZS5cclxuICovXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIE9pZGNTZWN1cml0eVN0b3JhZ2Uge1xyXG4gICAgLyoqXHJcbiAgICAgKiBUaGlzIG1ldGhvZCBtdXN0IGNvbnRhaW4gdGhlIGxvZ2ljIHRvIHJlYWQgdGhlIHN0b3JhZ2UuXHJcbiAgICAgKiBAcGFyYW0ga2V5XHJcbiAgICAgKiBAcmV0dXJuIFRoZSB2YWx1ZSBvZiB0aGUgZ2l2ZW4ga2V5XHJcbiAgICAgKi9cclxuICAgIHB1YmxpYyBhYnN0cmFjdCByZWFkKGtleTogc3RyaW5nKTogYW55O1xyXG5cclxuICAgIC8qKlxyXG4gICAgICogVGhpcyBtZXRob2QgbXVzdCBjb250YWluIHRoZSBsb2dpYyB0byB3cml0ZSB0aGUgc3RvcmFnZS5cclxuICAgICAqIEBwYXJhbSBrZXlcclxuICAgICAqIEBwYXJhbSB2YWx1ZSBUaGUgdmFsdWUgZm9yIHRoZSBnaXZlbiBrZXlcclxuICAgICAqL1xyXG4gICAgcHVibGljIGFic3RyYWN0IHdyaXRlKGtleTogc3RyaW5nLCB2YWx1ZTogYW55KTogdm9pZDtcclxufVxyXG5cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgQnJvd3NlclN0b3JhZ2UgaW1wbGVtZW50cyBPaWRjU2VjdXJpdHlTdG9yYWdlIHtcclxuICAgIHByaXZhdGUgaGFzU3RvcmFnZTogYm9vbGVhbjtcclxuXHJcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGF1dGhDb25maWd1cmF0aW9uOiBBdXRoQ29uZmlndXJhdGlvbikge1xyXG4gICAgICAgIHRoaXMuaGFzU3RvcmFnZSA9IHR5cGVvZiBTdG9yYWdlICE9PSAndW5kZWZpbmVkJztcclxuICAgIH1cclxuXHJcbiAgICBwdWJsaWMgcmVhZChrZXk6IHN0cmluZyk6IGFueSB7XHJcbiAgICAgICAgaWYgKHRoaXMuaGFzU3RvcmFnZSkge1xyXG4gICAgICAgICAgICByZXR1cm4gSlNPTi5wYXJzZSh0aGlzLmF1dGhDb25maWd1cmF0aW9uLnN0b3JhZ2UuZ2V0SXRlbShrZXkgKyAnXycgKyB0aGlzLmF1dGhDb25maWd1cmF0aW9uLmNsaWVudF9pZCkpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIHB1YmxpYyB3cml0ZShrZXk6IHN0cmluZywgdmFsdWU6IGFueSk6IHZvaWQge1xyXG4gICAgICAgIGlmICh0aGlzLmhhc1N0b3JhZ2UpIHtcclxuICAgICAgICAgICAgdmFsdWUgPSB2YWx1ZSA9PT0gdW5kZWZpbmVkID8gbnVsbCA6IHZhbHVlO1xyXG4gICAgICAgICAgICB0aGlzLmF1dGhDb25maWd1cmF0aW9uLnN0b3JhZ2Uuc2V0SXRlbShrZXkgKyAnXycgKyB0aGlzLmF1dGhDb25maWd1cmF0aW9uLmNsaWVudF9pZCwgSlNPTi5zdHJpbmdpZnkodmFsdWUpKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcbn1cclxuIl19