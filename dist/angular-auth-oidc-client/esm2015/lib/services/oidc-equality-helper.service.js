/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
export class EqualityHelperService {
    /**
     * @param {?} value1
     * @param {?} value2
     * @return {?}
     */
    areEqual(value1, value2) {
        if (!value1 || !value2) {
            return false;
        }
        if (this.bothValuesAreArrays(value1, value2)) {
            return this.arraysEqual((/** @type {?} */ (value1)), (/** @type {?} */ (value2)));
        }
        if (this.bothValuesAreStrings(value1, value2)) {
            return value1 === value2;
        }
        if (this.bothValuesAreObjects(value1, value2)) {
            return JSON.stringify(value1).toLowerCase() === JSON.stringify(value2).toLowerCase();
        }
        if (this.oneValueIsStringAndTheOtherIsArray(value1, value2)) {
            if (Array.isArray(value1) && this.valueIsString(value2)) {
                return value1[0] === value2;
            }
            if (Array.isArray(value2) && this.valueIsString(value1)) {
                return value2[0] === value1;
            }
        }
    }
    /**
     * @private
     * @param {?} value1
     * @param {?} value2
     * @return {?}
     */
    oneValueIsStringAndTheOtherIsArray(value1, value2) {
        return (Array.isArray(value1) && this.valueIsString(value2)) || (Array.isArray(value2) && this.valueIsString(value1));
    }
    /**
     * @private
     * @param {?} value1
     * @param {?} value2
     * @return {?}
     */
    bothValuesAreObjects(value1, value2) {
        return this.valueIsObject(value1) && this.valueIsObject(value2);
    }
    /**
     * @private
     * @param {?} value1
     * @param {?} value2
     * @return {?}
     */
    bothValuesAreStrings(value1, value2) {
        return this.valueIsString(value1) && this.valueIsString(value2);
    }
    /**
     * @private
     * @param {?} value1
     * @param {?} value2
     * @return {?}
     */
    bothValuesAreArrays(value1, value2) {
        return Array.isArray(value1) && Array.isArray(value2);
    }
    /**
     * @private
     * @param {?} value
     * @return {?}
     */
    valueIsString(value) {
        return typeof value === 'string' || value instanceof String;
    }
    /**
     * @private
     * @param {?} value
     * @return {?}
     */
    valueIsObject(value) {
        return typeof value === 'object';
    }
    /**
     * @private
     * @param {?} arr1
     * @param {?} arr2
     * @return {?}
     */
    arraysEqual(arr1, arr2) {
        if (arr1.length !== arr2.length) {
            return false;
        }
        for (let i = arr1.length; i--;) {
            if (arr1[i] !== arr2[i]) {
                return false;
            }
        }
        return true;
    }
}
EqualityHelperService.decorators = [
    { type: Injectable }
];
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy1lcXVhbGl0eS1oZWxwZXIuc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItYXV0aC1vaWRjLWNsaWVudC8iLCJzb3VyY2VzIjpbImxpYi9zZXJ2aWNlcy9vaWRjLWVxdWFsaXR5LWhlbHBlci5zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBRzNDLE1BQU0sT0FBTyxxQkFBcUI7Ozs7OztJQUM5QixRQUFRLENBQUMsTUFBa0QsRUFBRSxNQUFrRDtRQUMzRyxJQUFJLENBQUMsTUFBTSxJQUFJLENBQUMsTUFBTSxFQUFFO1lBQ3BCLE9BQU8sS0FBSyxDQUFDO1NBQ2hCO1FBRUQsSUFBSSxJQUFJLENBQUMsbUJBQW1CLENBQUMsTUFBTSxFQUFFLE1BQU0sQ0FBQyxFQUFFO1lBQzFDLE9BQU8sSUFBSSxDQUFDLFdBQVcsQ0FBQyxtQkFBQSxNQUFNLEVBQVMsRUFBRSxtQkFBQSxNQUFNLEVBQVMsQ0FBQyxDQUFDO1NBQzdEO1FBRUQsSUFBSSxJQUFJLENBQUMsb0JBQW9CLENBQUMsTUFBTSxFQUFFLE1BQU0sQ0FBQyxFQUFFO1lBQzNDLE9BQU8sTUFBTSxLQUFLLE1BQU0sQ0FBQztTQUM1QjtRQUVELElBQUksSUFBSSxDQUFDLG9CQUFvQixDQUFDLE1BQU0sRUFBRSxNQUFNLENBQUMsRUFBRTtZQUMzQyxPQUFPLElBQUksQ0FBQyxTQUFTLENBQUMsTUFBTSxDQUFDLENBQUMsV0FBVyxFQUFFLEtBQUssSUFBSSxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQztTQUN4RjtRQUVELElBQUksSUFBSSxDQUFDLGtDQUFrQyxDQUFDLE1BQU0sRUFBRSxNQUFNLENBQUMsRUFBRTtZQUN6RCxJQUFJLEtBQUssQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLElBQUksSUFBSSxDQUFDLGFBQWEsQ0FBQyxNQUFNLENBQUMsRUFBRTtnQkFDckQsT0FBTyxNQUFNLENBQUMsQ0FBQyxDQUFDLEtBQUssTUFBTSxDQUFDO2FBQy9CO1lBQ0QsSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxJQUFJLElBQUksQ0FBQyxhQUFhLENBQUMsTUFBTSxDQUFDLEVBQUU7Z0JBQ3JELE9BQU8sTUFBTSxDQUFDLENBQUMsQ0FBQyxLQUFLLE1BQU0sQ0FBQzthQUMvQjtTQUNKO0lBQ0wsQ0FBQzs7Ozs7OztJQUVPLGtDQUFrQyxDQUFDLE1BQStCLEVBQUUsTUFBK0I7UUFDdkcsT0FBTyxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLElBQUksSUFBSSxDQUFDLGFBQWEsQ0FBQyxNQUFNLENBQUMsQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsSUFBSSxJQUFJLENBQUMsYUFBYSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7SUFDMUgsQ0FBQzs7Ozs7OztJQUVPLG9CQUFvQixDQUFDLE1BQStCLEVBQUUsTUFBK0I7UUFDekYsT0FBTyxJQUFJLENBQUMsYUFBYSxDQUFDLE1BQU0sQ0FBQyxJQUFJLElBQUksQ0FBQyxhQUFhLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDcEUsQ0FBQzs7Ozs7OztJQUVPLG9CQUFvQixDQUFDLE1BQStCLEVBQUUsTUFBK0I7UUFDekYsT0FBTyxJQUFJLENBQUMsYUFBYSxDQUFDLE1BQU0sQ0FBQyxJQUFJLElBQUksQ0FBQyxhQUFhLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDcEUsQ0FBQzs7Ozs7OztJQUVPLG1CQUFtQixDQUFDLE1BQStCLEVBQUUsTUFBK0I7UUFDeEYsT0FBTyxLQUFLLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxJQUFJLEtBQUssQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDMUQsQ0FBQzs7Ozs7O0lBRU8sYUFBYSxDQUFDLEtBQVU7UUFDNUIsT0FBTyxPQUFPLEtBQUssS0FBSyxRQUFRLElBQUksS0FBSyxZQUFZLE1BQU0sQ0FBQztJQUNoRSxDQUFDOzs7Ozs7SUFFTyxhQUFhLENBQUMsS0FBVTtRQUM1QixPQUFPLE9BQU8sS0FBSyxLQUFLLFFBQVEsQ0FBQztJQUNyQyxDQUFDOzs7Ozs7O0lBRU8sV0FBVyxDQUFDLElBQW1CLEVBQUUsSUFBbUI7UUFDeEQsSUFBSSxJQUFJLENBQUMsTUFBTSxLQUFLLElBQUksQ0FBQyxNQUFNLEVBQUU7WUFDN0IsT0FBTyxLQUFLLENBQUM7U0FDaEI7UUFFRCxLQUFLLElBQUksQ0FBQyxHQUFHLElBQUksQ0FBQyxNQUFNLEVBQUUsQ0FBQyxFQUFFLEdBQUk7WUFDN0IsSUFBSSxJQUFJLENBQUMsQ0FBQyxDQUFDLEtBQUssSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFO2dCQUNyQixPQUFPLEtBQUssQ0FBQzthQUNoQjtTQUNKO1FBRUQsT0FBTyxJQUFJLENBQUM7SUFDaEIsQ0FBQzs7O1lBakVKLFVBQVUiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcblxyXG5ASW5qZWN0YWJsZSgpXHJcbmV4cG9ydCBjbGFzcyBFcXVhbGl0eUhlbHBlclNlcnZpY2Uge1xyXG4gICAgYXJlRXF1YWwodmFsdWUxOiBzdHJpbmcgfCBhbnlbXSB8IG9iamVjdCB8IG51bGwgfCB1bmRlZmluZWQsIHZhbHVlMjogc3RyaW5nIHwgYW55W10gfCBvYmplY3QgfCBudWxsIHwgdW5kZWZpbmVkKSB7XHJcbiAgICAgICAgaWYgKCF2YWx1ZTEgfHwgIXZhbHVlMikge1xyXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAodGhpcy5ib3RoVmFsdWVzQXJlQXJyYXlzKHZhbHVlMSwgdmFsdWUyKSkge1xyXG4gICAgICAgICAgICByZXR1cm4gdGhpcy5hcnJheXNFcXVhbCh2YWx1ZTEgYXMgYW55W10sIHZhbHVlMiBhcyBhbnlbXSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAodGhpcy5ib3RoVmFsdWVzQXJlU3RyaW5ncyh2YWx1ZTEsIHZhbHVlMikpIHtcclxuICAgICAgICAgICAgcmV0dXJuIHZhbHVlMSA9PT0gdmFsdWUyO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKHRoaXMuYm90aFZhbHVlc0FyZU9iamVjdHModmFsdWUxLCB2YWx1ZTIpKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh2YWx1ZTEpLnRvTG93ZXJDYXNlKCkgPT09IEpTT04uc3RyaW5naWZ5KHZhbHVlMikudG9Mb3dlckNhc2UoKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmICh0aGlzLm9uZVZhbHVlSXNTdHJpbmdBbmRUaGVPdGhlcklzQXJyYXkodmFsdWUxLCB2YWx1ZTIpKSB7XHJcbiAgICAgICAgICAgIGlmIChBcnJheS5pc0FycmF5KHZhbHVlMSkgJiYgdGhpcy52YWx1ZUlzU3RyaW5nKHZhbHVlMikpIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiB2YWx1ZTFbMF0gPT09IHZhbHVlMjtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBpZiAoQXJyYXkuaXNBcnJheSh2YWx1ZTIpICYmIHRoaXMudmFsdWVJc1N0cmluZyh2YWx1ZTEpKSB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdmFsdWUyWzBdID09PSB2YWx1ZTE7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBvbmVWYWx1ZUlzU3RyaW5nQW5kVGhlT3RoZXJJc0FycmF5KHZhbHVlMTogc3RyaW5nIHwgb2JqZWN0IHwgYW55W10sIHZhbHVlMjogc3RyaW5nIHwgb2JqZWN0IHwgYW55W10pIHtcclxuICAgICAgICByZXR1cm4gKEFycmF5LmlzQXJyYXkodmFsdWUxKSAmJiB0aGlzLnZhbHVlSXNTdHJpbmcodmFsdWUyKSkgfHwgKEFycmF5LmlzQXJyYXkodmFsdWUyKSAmJiB0aGlzLnZhbHVlSXNTdHJpbmcodmFsdWUxKSk7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBib3RoVmFsdWVzQXJlT2JqZWN0cyh2YWx1ZTE6IHN0cmluZyB8IG9iamVjdCB8IGFueVtdLCB2YWx1ZTI6IHN0cmluZyB8IG9iamVjdCB8IGFueVtdKSB7XHJcbiAgICAgICAgcmV0dXJuIHRoaXMudmFsdWVJc09iamVjdCh2YWx1ZTEpICYmIHRoaXMudmFsdWVJc09iamVjdCh2YWx1ZTIpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgYm90aFZhbHVlc0FyZVN0cmluZ3ModmFsdWUxOiBzdHJpbmcgfCBvYmplY3QgfCBhbnlbXSwgdmFsdWUyOiBzdHJpbmcgfCBvYmplY3QgfCBhbnlbXSkge1xyXG4gICAgICAgIHJldHVybiB0aGlzLnZhbHVlSXNTdHJpbmcodmFsdWUxKSAmJiB0aGlzLnZhbHVlSXNTdHJpbmcodmFsdWUyKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIGJvdGhWYWx1ZXNBcmVBcnJheXModmFsdWUxOiBzdHJpbmcgfCBvYmplY3QgfCBhbnlbXSwgdmFsdWUyOiBzdHJpbmcgfCBvYmplY3QgfCBhbnlbXSkge1xyXG4gICAgICAgIHJldHVybiBBcnJheS5pc0FycmF5KHZhbHVlMSkgJiYgQXJyYXkuaXNBcnJheSh2YWx1ZTIpO1xyXG4gICAgfVxyXG5cclxuICAgIHByaXZhdGUgdmFsdWVJc1N0cmluZyh2YWx1ZTogYW55KSB7XHJcbiAgICAgICAgcmV0dXJuIHR5cGVvZiB2YWx1ZSA9PT0gJ3N0cmluZycgfHwgdmFsdWUgaW5zdGFuY2VvZiBTdHJpbmc7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSB2YWx1ZUlzT2JqZWN0KHZhbHVlOiBhbnkpIHtcclxuICAgICAgICByZXR1cm4gdHlwZW9mIHZhbHVlID09PSAnb2JqZWN0JztcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIGFycmF5c0VxdWFsKGFycjE6IEFycmF5PHN0cmluZz4sIGFycjI6IEFycmF5PHN0cmluZz4pIHtcclxuICAgICAgICBpZiAoYXJyMS5sZW5ndGggIT09IGFycjIubGVuZ3RoKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGZvciAobGV0IGkgPSBhcnIxLmxlbmd0aDsgaS0tOyApIHtcclxuICAgICAgICAgICAgaWYgKGFycjFbaV0gIT09IGFycjJbaV0pIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcbn1cclxuIl19