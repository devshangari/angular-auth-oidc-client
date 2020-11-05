import { ValidationResult } from './validation-result.enum';
export declare class ValidateStateResult {
    access_token: string;
    id_token: string;
    authResponseIsValid: boolean;
    decoded_id_token: any;
    state: ValidationResult;
    constructor(access_token?: string, id_token?: string, authResponseIsValid?: boolean, decoded_id_token?: any, state?: ValidationResult);
}
