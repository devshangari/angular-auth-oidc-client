/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { ValidationResult } from './validation-result.enum';
export class ValidateStateResult {
    /**
     * @param {?=} access_token
     * @param {?=} id_token
     * @param {?=} authResponseIsValid
     * @param {?=} decoded_id_token
     * @param {?=} state
     */
    constructor(access_token = '', id_token = '', authResponseIsValid = false, decoded_id_token = {}, state = ValidationResult.NotSet) {
        this.access_token = access_token;
        this.id_token = id_token;
        this.authResponseIsValid = authResponseIsValid;
        this.decoded_id_token = decoded_id_token;
        this.state = state;
    }
}
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmFsaWRhdGUtc3RhdGUtcmVzdWx0Lm1vZGVsLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1hdXRoLW9pZGMtY2xpZW50LyIsInNvdXJjZXMiOlsibGliL21vZGVscy92YWxpZGF0ZS1zdGF0ZS1yZXN1bHQubW9kZWwudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7OztBQUFBLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLDBCQUEwQixDQUFDO0FBRTVELE1BQU0sT0FBTyxtQkFBbUI7Ozs7Ozs7O0lBQzVCLFlBQ1csZUFBZSxFQUFFLEVBQ2pCLFdBQVcsRUFBRSxFQUNiLHNCQUFzQixLQUFLLEVBQzNCLG1CQUF3QixFQUFFLEVBQzFCLFFBQTBCLGdCQUFnQixDQUFDLE1BQU07UUFKakQsaUJBQVksR0FBWixZQUFZLENBQUs7UUFDakIsYUFBUSxHQUFSLFFBQVEsQ0FBSztRQUNiLHdCQUFtQixHQUFuQixtQkFBbUIsQ0FBUTtRQUMzQixxQkFBZ0IsR0FBaEIsZ0JBQWdCLENBQVU7UUFDMUIsVUFBSyxHQUFMLEtBQUssQ0FBNEM7SUFDekQsQ0FBQztDQUNQOzs7SUFOTywyQ0FBd0I7O0lBQ3hCLHVDQUFvQjs7SUFDcEIsa0RBQWtDOztJQUNsQywrQ0FBaUM7O0lBQ2pDLG9DQUF3RCIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IFZhbGlkYXRpb25SZXN1bHQgfSBmcm9tICcuL3ZhbGlkYXRpb24tcmVzdWx0LmVudW0nO1xyXG5cclxuZXhwb3J0IGNsYXNzIFZhbGlkYXRlU3RhdGVSZXN1bHQge1xyXG4gICAgY29uc3RydWN0b3IoXHJcbiAgICAgICAgcHVibGljIGFjY2Vzc190b2tlbiA9ICcnLFxyXG4gICAgICAgIHB1YmxpYyBpZF90b2tlbiA9ICcnLFxyXG4gICAgICAgIHB1YmxpYyBhdXRoUmVzcG9uc2VJc1ZhbGlkID0gZmFsc2UsXHJcbiAgICAgICAgcHVibGljIGRlY29kZWRfaWRfdG9rZW46IGFueSA9IHt9LFxyXG4gICAgICAgIHB1YmxpYyBzdGF0ZTogVmFsaWRhdGlvblJlc3VsdCA9IFZhbGlkYXRpb25SZXN1bHQuTm90U2V0XHJcbiAgICApIHt9XHJcbn1cclxuIl19