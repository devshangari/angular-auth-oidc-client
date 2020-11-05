/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { ValidationResult } from './validation-result.enum';
var ValidateStateResult = /** @class */ (function () {
    function ValidateStateResult(access_token, id_token, authResponseIsValid, decoded_id_token, state) {
        if (access_token === void 0) { access_token = ''; }
        if (id_token === void 0) { id_token = ''; }
        if (authResponseIsValid === void 0) { authResponseIsValid = false; }
        if (decoded_id_token === void 0) { decoded_id_token = {}; }
        if (state === void 0) { state = ValidationResult.NotSet; }
        this.access_token = access_token;
        this.id_token = id_token;
        this.authResponseIsValid = authResponseIsValid;
        this.decoded_id_token = decoded_id_token;
        this.state = state;
    }
    return ValidateStateResult;
}());
export { ValidateStateResult };
if (false) {
    /** @type {?} */
    ValidateStateResult.prototype.access_token;
    /** @type {?} */
    ValidateStateResult.prototype.id_token;
    /** @type {?} */
    ValidateStateResult.prototype.authResponseIsValid;
    /** @type {?} */
    ValidateStateResult.prototype.decoded_id_token;
    /** @type {?} */
    ValidateStateResult.prototype.state;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmFsaWRhdGUtc3RhdGUtcmVzdWx0Lm1vZGVsLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1hdXRoLW9pZGMtY2xpZW50LyIsInNvdXJjZXMiOlsibGliL21vZGVscy92YWxpZGF0ZS1zdGF0ZS1yZXN1bHQubW9kZWwudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7OztBQUFBLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLDBCQUEwQixDQUFDO0FBRTVEO0lBQ0ksNkJBQ1csWUFBaUIsRUFDakIsUUFBYSxFQUNiLG1CQUEyQixFQUMzQixnQkFBMEIsRUFDMUIsS0FBaUQ7UUFKakQsNkJBQUEsRUFBQSxpQkFBaUI7UUFDakIseUJBQUEsRUFBQSxhQUFhO1FBQ2Isb0NBQUEsRUFBQSwyQkFBMkI7UUFDM0IsaUNBQUEsRUFBQSxxQkFBMEI7UUFDMUIsc0JBQUEsRUFBQSxRQUEwQixnQkFBZ0IsQ0FBQyxNQUFNO1FBSmpELGlCQUFZLEdBQVosWUFBWSxDQUFLO1FBQ2pCLGFBQVEsR0FBUixRQUFRLENBQUs7UUFDYix3QkFBbUIsR0FBbkIsbUJBQW1CLENBQVE7UUFDM0IscUJBQWdCLEdBQWhCLGdCQUFnQixDQUFVO1FBQzFCLFVBQUssR0FBTCxLQUFLLENBQTRDO0lBQ3pELENBQUM7SUFDUiwwQkFBQztBQUFELENBQUMsQUFSRCxJQVFDOzs7O0lBTk8sMkNBQXdCOztJQUN4Qix1Q0FBb0I7O0lBQ3BCLGtEQUFrQzs7SUFDbEMsK0NBQWlDOztJQUNqQyxvQ0FBd0QiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBWYWxpZGF0aW9uUmVzdWx0IH0gZnJvbSAnLi92YWxpZGF0aW9uLXJlc3VsdC5lbnVtJztcclxuXHJcbmV4cG9ydCBjbGFzcyBWYWxpZGF0ZVN0YXRlUmVzdWx0IHtcclxuICAgIGNvbnN0cnVjdG9yKFxyXG4gICAgICAgIHB1YmxpYyBhY2Nlc3NfdG9rZW4gPSAnJyxcclxuICAgICAgICBwdWJsaWMgaWRfdG9rZW4gPSAnJyxcclxuICAgICAgICBwdWJsaWMgYXV0aFJlc3BvbnNlSXNWYWxpZCA9IGZhbHNlLFxyXG4gICAgICAgIHB1YmxpYyBkZWNvZGVkX2lkX3Rva2VuOiBhbnkgPSB7fSxcclxuICAgICAgICBwdWJsaWMgc3RhdGU6IFZhbGlkYXRpb25SZXN1bHQgPSBWYWxpZGF0aW9uUmVzdWx0Lk5vdFNldFxyXG4gICAgKSB7fVxyXG59XHJcbiJdfQ==