import { AuthorizationState } from './authorization-state.enum';
import { ValidationResult } from './validation-result.enum';
export declare class AuthorizationResult {
    authorizationState: AuthorizationState;
    validationResult: ValidationResult;
    constructor(authorizationState: AuthorizationState, validationResult: ValidationResult);
}
