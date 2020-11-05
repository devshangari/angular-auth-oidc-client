/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
import { AuthWellKnownEndpoints } from '../models/auth.well-known-endpoints';
import { ValidateStateResult } from '../models/validate-state-result.model';
import { ValidationResult } from '../models/validation-result.enum';
import { AuthConfiguration } from '../modules/auth.configuration';
import { TokenHelperService } from './oidc-token-helper.service';
import { LoggerService } from './oidc.logger.service';
import { OidcSecurityCommon } from './oidc.security.common';
import { OidcSecurityValidation } from './oidc.security.validation';
export class StateValidationService {
    /**
     * @param {?} authConfiguration
     * @param {?} oidcSecurityCommon
     * @param {?} oidcSecurityValidation
     * @param {?} tokenHelperService
     * @param {?} loggerService
     */
    constructor(authConfiguration, oidcSecurityCommon, oidcSecurityValidation, tokenHelperService, loggerService) {
        this.authConfiguration = authConfiguration;
        this.oidcSecurityCommon = oidcSecurityCommon;
        this.oidcSecurityValidation = oidcSecurityValidation;
        this.tokenHelperService = tokenHelperService;
        this.loggerService = loggerService;
        this.authWellKnownEndpoints = new AuthWellKnownEndpoints();
    }
    /**
     * @param {?} authWellKnownEndpoints
     * @return {?}
     */
    setupModule(authWellKnownEndpoints) {
        this.authWellKnownEndpoints = Object.assign({}, authWellKnownEndpoints);
    }
    /**
     * @param {?} result
     * @param {?} jwtKeys
     * @return {?}
     */
    validateState(result, jwtKeys) {
        /** @type {?} */
        const toReturn = new ValidateStateResult();
        if (!this.oidcSecurityValidation.validateStateFromHashCallback(result.state, this.oidcSecurityCommon.authStateControl)) {
            this.loggerService.logWarning('authorizedCallback incorrect state');
            toReturn.state = ValidationResult.StatesDoNotMatch;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (this.authConfiguration.response_type === 'id_token token' || this.authConfiguration.response_type === 'code') {
            toReturn.access_token = result.access_token;
        }
        toReturn.id_token = result.id_token;
        toReturn.decoded_id_token = this.tokenHelperService.getPayloadFromToken(toReturn.id_token, false);
        if (!this.oidcSecurityValidation.validate_signature_id_token(toReturn.id_token, jwtKeys)) {
            this.loggerService.logDebug('authorizedCallback Signature validation failed id_token');
            toReturn.state = ValidationResult.SignatureFailed;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_id_token_nonce(toReturn.decoded_id_token, this.oidcSecurityCommon.authNonce)) {
            this.loggerService.logWarning('authorizedCallback incorrect nonce');
            toReturn.state = ValidationResult.IncorrectNonce;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_required_id_token(toReturn.decoded_id_token)) {
            this.loggerService.logDebug('authorizedCallback Validation, one of the REQUIRED properties missing from id_token');
            toReturn.state = ValidationResult.RequiredPropertyMissing;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_id_token_iat_max_offset(toReturn.decoded_id_token, this.authConfiguration.max_id_token_iat_offset_allowed_in_seconds, this.authConfiguration.disable_iat_offset_validation)) {
            this.loggerService.logWarning('authorizedCallback Validation, iat rejected id_token was issued too far away from the current time');
            toReturn.state = ValidationResult.MaxOffsetExpired;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (this.authWellKnownEndpoints) {
            if (this.authConfiguration.iss_validation_off) {
                this.loggerService.logDebug('iss validation is turned off, this is not recommended!');
            }
            else if (!this.authConfiguration.iss_validation_off &&
                !this.oidcSecurityValidation.validate_id_token_iss(toReturn.decoded_id_token, this.authWellKnownEndpoints.issuer)) {
                this.loggerService.logWarning('authorizedCallback incorrect iss does not match authWellKnownEndpoints issuer');
                toReturn.state = ValidationResult.IssDoesNotMatchIssuer;
                this.handleUnsuccessfulValidation();
                return toReturn;
            }
        }
        else {
            this.loggerService.logWarning('authWellKnownEndpoints is undefined');
            toReturn.state = ValidationResult.NoAuthWellKnownEndPoints;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_id_token_aud(toReturn.decoded_id_token, this.authConfiguration.client_id)) {
            this.loggerService.logWarning('authorizedCallback incorrect aud');
            toReturn.state = ValidationResult.IncorrectAud;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_id_token_exp_not_expired(toReturn.decoded_id_token)) {
            this.loggerService.logWarning('authorizedCallback token expired');
            toReturn.state = ValidationResult.TokenExpired;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        // flow id_token token
        if (this.authConfiguration.response_type !== 'id_token token' && this.authConfiguration.response_type !== 'code') {
            toReturn.authResponseIsValid = true;
            toReturn.state = ValidationResult.Ok;
            this.handleSuccessfulValidation();
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        if (!this.oidcSecurityValidation.validate_id_token_at_hash(toReturn.access_token, toReturn.decoded_id_token.at_hash, this.authConfiguration.response_type === 'code') ||
            !toReturn.access_token) {
            this.loggerService.logWarning('authorizedCallback incorrect at_hash');
            toReturn.state = ValidationResult.IncorrectAtHash;
            this.handleUnsuccessfulValidation();
            return toReturn;
        }
        toReturn.authResponseIsValid = true;
        toReturn.state = ValidationResult.Ok;
        this.handleSuccessfulValidation();
        return toReturn;
    }
    /**
     * @private
     * @return {?}
     */
    handleSuccessfulValidation() {
        this.oidcSecurityCommon.authNonce = '';
        if (this.authConfiguration.auto_clean_state_after_authentication) {
            this.oidcSecurityCommon.authStateControl = '';
        }
        this.loggerService.logDebug('AuthorizedCallback token(s) validated, continue');
    }
    /**
     * @private
     * @return {?}
     */
    handleUnsuccessfulValidation() {
        this.oidcSecurityCommon.authNonce = '';
        if (this.authConfiguration.auto_clean_state_after_authentication) {
            this.oidcSecurityCommon.authStateControl = '';
        }
        this.loggerService.logDebug('AuthorizedCallback token(s) invalid');
    }
}
StateValidationService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
StateValidationService.ctorParameters = () => [
    { type: AuthConfiguration },
    { type: OidcSecurityCommon },
    { type: OidcSecurityValidation },
    { type: TokenHelperService },
    { type: LoggerService }
];
if (false) {
    /**
     * @type {?}
     * @private
     */
    StateValidationService.prototype.authWellKnownEndpoints;
    /**
     * @type {?}
     * @private
     */
    StateValidationService.prototype.authConfiguration;
    /** @type {?} */
    StateValidationService.prototype.oidcSecurityCommon;
    /**
     * @type {?}
     * @private
     */
    StateValidationService.prototype.oidcSecurityValidation;
    /**
     * @type {?}
     * @private
     */
    StateValidationService.prototype.tokenHelperService;
    /**
     * @type {?}
     * @private
     */
    StateValidationService.prototype.loggerService;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy1zZWN1cml0eS1zdGF0ZS12YWxpZGF0aW9uLnNlcnZpY2UuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLWF1dGgtb2lkYy1jbGllbnQvIiwic291cmNlcyI6WyJsaWIvc2VydmljZXMvb2lkYy1zZWN1cml0eS1zdGF0ZS12YWxpZGF0aW9uLnNlcnZpY2UudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7OztBQUFBLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLHNCQUFzQixFQUFFLE1BQU0scUNBQXFDLENBQUM7QUFFN0UsT0FBTyxFQUFFLG1CQUFtQixFQUFFLE1BQU0sdUNBQXVDLENBQUM7QUFDNUUsT0FBTyxFQUFFLGdCQUFnQixFQUFFLE1BQU0sa0NBQWtDLENBQUM7QUFDcEUsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sK0JBQStCLENBQUM7QUFDbEUsT0FBTyxFQUFFLGtCQUFrQixFQUFFLE1BQU0sNkJBQTZCLENBQUM7QUFDakUsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLHVCQUF1QixDQUFDO0FBQ3RELE9BQU8sRUFBRSxrQkFBa0IsRUFBRSxNQUFNLHdCQUF3QixDQUFDO0FBQzVELE9BQU8sRUFBRSxzQkFBc0IsRUFBRSxNQUFNLDRCQUE0QixDQUFDO0FBR3BFLE1BQU0sT0FBTyxzQkFBc0I7Ozs7Ozs7O0lBRS9CLFlBQ1ksaUJBQW9DLEVBQ3JDLGtCQUFzQyxFQUNyQyxzQkFBOEMsRUFDOUMsa0JBQXNDLEVBQ3RDLGFBQTRCO1FBSjVCLHNCQUFpQixHQUFqQixpQkFBaUIsQ0FBbUI7UUFDckMsdUJBQWtCLEdBQWxCLGtCQUFrQixDQUFvQjtRQUNyQywyQkFBc0IsR0FBdEIsc0JBQXNCLENBQXdCO1FBQzlDLHVCQUFrQixHQUFsQixrQkFBa0IsQ0FBb0I7UUFDdEMsa0JBQWEsR0FBYixhQUFhLENBQWU7UUFOaEMsMkJBQXNCLEdBQUcsSUFBSSxzQkFBc0IsRUFBRSxDQUFDO0lB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LElBQUksQ0FBQztRQUNwQyxRQUFRLENBQUMsS0FBSyxHQUFHLGdCQUFnQixDQUFDLEVBQUUsQ0FBQztRQUNyQyxJQUFJLENBQUMsMEJBQTBCLEVBQUUsQ0FBQztRQUNsQyxPQUFPLFFBQVEsQ0FBQztJQUNwQixDQUFDOzs7OztJQUVPLDBCQUEwQjtRQUM5QixJQUFJLENBQUMsa0JBQWtCLENBQUMsU0FBUyxHQUFHLEVBQUUsQ0FBQztRQUV2QyxJQUFJLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxxQ0FBcUMsRUFBRTtZQUM5RCxJQUFJLENBQUMsa0JBQWtCLENBQUMsZ0JBQWdCLEdBQUcsRUFBRSxDQUFDO1NBQ2pEO1FBQ0QsSUFBSSxDQUFDLGFBQWEsQ0FBQyxRQUFRLENBQUMsaURBQWlELENBQUMsQ0FBQztJQUNuRixDQUFDOzs7OztJQUVPLDRCQUE0QjtRQUNoQyxJQUFJLENBQUMsa0JBQWtCLENBQUMsU0FBUyxHQUFHLEVBQUUsQ0FBQztRQUV2QyxJQUFJLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxxQ0FBcUMsRUFBRTtZQUM5RCxJQUFJLENBQUMsa0JBQWtCLENBQUMsZ0JBQWdCLEdBQUcsRUFBRSxDQUFDO1NBQ2pEO1FBQ0QsSUFBSSxDQUFDLGFBQWEsQ0FBQyxRQUFRLENBQUMscUNBQXFDLENBQUMsQ0FBQztJQUN2RSxDQUFDOzs7WUEzSUosVUFBVTs7OztZQU5GLGlCQUFpQjtZQUdqQixrQkFBa0I7WUFDbEIsc0JBQXNCO1lBSHRCLGtCQUFrQjtZQUNsQixhQUFhOzs7Ozs7O0lBTWxCLHdEQUE4RDs7Ozs7SUFFMUQsbURBQTRDOztJQUM1QyxvREFBNkM7Ozs7O0lBQzdDLHdEQUFzRDs7Ozs7SUFDdEQsb0RBQThDOzs7OztJQUM5QywrQ0FBb0MiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcbmltcG9ydCB7IEF1dGhXZWxsS25vd25FbmRwb2ludHMgfSBmcm9tICcuLi9tb2RlbHMvYXV0aC53ZWxsLWtub3duLWVuZHBvaW50cyc7XHJcbmltcG9ydCB7IEp3dEtleXMgfSBmcm9tICcuLi9tb2RlbHMvand0a2V5cyc7XHJcbmltcG9ydCB7IFZhbGlkYXRlU3RhdGVSZXN1bHQgfSBmcm9tICcuLi9tb2RlbHMvdmFsaWRhdGUtc3RhdGUtcmVzdWx0Lm1vZGVsJztcclxuaW1wb3J0IHsgVmFsaWRhdGlvblJlc3VsdCB9IGZyb20gJy4uL21vZGVscy92YWxpZGF0aW9uLXJlc3VsdC5lbnVtJztcclxuaW1wb3J0IHsgQXV0aENvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi9tb2R1bGVzL2F1dGguY29uZmlndXJhdGlvbic7XHJcbmltcG9ydCB7IFRva2VuSGVscGVyU2VydmljZSB9IGZyb20gJy4vb2lkYy10b2tlbi1oZWxwZXIuc2VydmljZSc7XHJcbmltcG9ydCB7IExvZ2dlclNlcnZpY2UgfSBmcm9tICcuL29pZGMubG9nZ2VyLnNlcnZpY2UnO1xyXG5pbXBvcnQgeyBPaWRjU2VjdXJpdHlDb21tb24gfSBmcm9tICcuL29pZGMuc2VjdXJpdHkuY29tbW9uJztcclxuaW1wb3J0IHsgT2lkY1NlY3VyaXR5VmFsaWRhdGlvbiB9IGZyb20gJy4vb2lkYy5zZWN1cml0eS52YWxpZGF0aW9uJztcclxuXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGNsYXNzIFN0YXRlVmFsaWRhdGlvblNlcnZpY2Uge1xyXG4gICAgcHJpdmF0ZSBhdXRoV2VsbEtub3duRW5kcG9pbnRzID0gbmV3IEF1dGhXZWxsS25vd25FbmRwb2ludHMoKTtcclxuICAgIGNvbnN0cnVjdG9yKFxyXG4gICAgICAgIHByaXZhdGUgYXV0aENvbmZpZ3VyYXRpb246IEF1dGhDb25maWd1cmF0aW9uLFxyXG4gICAgICAgIHB1YmxpYyBvaWRjU2VjdXJpdHlDb21tb246IE9pZGNTZWN1cml0eUNvbW1vbixcclxuICAgICAgICBwcml2YXRlIG9pZGNTZWN1cml0eVZhbGlkYXRpb246IE9pZGNTZWN1cml0eVZhbGlkYXRpb24sXHJcbiAgICAgICAgcHJpdmF0ZSB0b2tlbkhlbHBlclNlcnZpY2U6IFRva2VuSGVscGVyU2VydmljZSxcclxuICAgICAgICBwcml2YXRlIGxvZ2dlclNlcnZpY2U6IExvZ2dlclNlcnZpY2VcclxuICAgICkge31cclxuXHJcbiAgICBzZXR1cE1vZHVsZShhdXRoV2VsbEtub3duRW5kcG9pbnRzOiBBdXRoV2VsbEtub3duRW5kcG9pbnRzKSB7XHJcbiAgICAgICAgdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzID0gT2JqZWN0LmFzc2lnbih7fSwgYXV0aFdlbGxLbm93bkVuZHBvaW50cyk7XHJcbiAgICB9XHJcblxyXG4gICAgdmFsaWRhdGVTdGF0ZShyZXN1bHQ6IGFueSwgand0S2V5czogSnd0S2V5cyk6IFZhbGlkYXRlU3RhdGVSZXN1bHQge1xyXG4gICAgICAgIGNvbnN0IHRvUmV0dXJuID0gbmV3IFZhbGlkYXRlU3RhdGVSZXN1bHQoKTtcclxuICAgICAgICBpZiAoIXRoaXMub2lkY1NlY3VyaXR5VmFsaWRhdGlvbi52YWxpZGF0ZVN0YXRlRnJvbUhhc2hDYWxsYmFjayhyZXN1bHQuc3RhdGUsIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmF1dGhTdGF0ZUNvbnRyb2wpKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdhdXRob3JpemVkQ2FsbGJhY2sgaW5jb3JyZWN0IHN0YXRlJyk7XHJcbiAgICAgICAgICAgIHRvUmV0dXJuLnN0YXRlID0gVmFsaWRhdGlvblJlc3VsdC5TdGF0ZXNEb05vdE1hdGNoO1xyXG4gICAgICAgICAgICB0aGlzLmhhbmRsZVVuc3VjY2Vzc2Z1bFZhbGlkYXRpb24oKTtcclxuICAgICAgICAgICAgcmV0dXJuIHRvUmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ucmVzcG9uc2VfdHlwZSA9PT0gJ2lkX3Rva2VuIHRva2VuJyB8fCB0aGlzLmF1dGhDb25maWd1cmF0aW9uLnJlc3BvbnNlX3R5cGUgPT09ICdjb2RlJykge1xyXG4gICAgICAgICAgICB0b1JldHVybi5hY2Nlc3NfdG9rZW4gPSByZXN1bHQuYWNjZXNzX3Rva2VuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgdG9SZXR1cm4uaWRfdG9rZW4gPSByZXN1bHQuaWRfdG9rZW47XHJcblxyXG4gICAgICAgIHRvUmV0dXJuLmRlY29kZWRfaWRfdG9rZW4gPSB0aGlzLnRva2VuSGVscGVyU2VydmljZS5nZXRQYXlsb2FkRnJvbVRva2VuKHRvUmV0dXJuLmlkX3Rva2VuLCBmYWxzZSk7XHJcblxyXG4gICAgICAgIGlmICghdGhpcy5vaWRjU2VjdXJpdHlWYWxpZGF0aW9uLnZhbGlkYXRlX3NpZ25hdHVyZV9pZF90b2tlbih0b1JldHVybi5pZF90b2tlbiwgand0S2V5cykpIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdhdXRob3JpemVkQ2FsbGJhY2sgU2lnbmF0dXJlIHZhbGlkYXRpb24gZmFpbGVkIGlkX3Rva2VuJyk7XHJcbiAgICAgICAgICAgIHRvUmV0dXJuLnN0YXRlID0gVmFsaWRhdGlvblJlc3VsdC5TaWduYXR1cmVGYWlsZWQ7XHJcbiAgICAgICAgICAgIHRoaXMuaGFuZGxlVW5zdWNjZXNzZnVsVmFsaWRhdGlvbigpO1xyXG4gICAgICAgICAgICByZXR1cm4gdG9SZXR1cm47XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoIXRoaXMub2lkY1NlY3VyaXR5VmFsaWRhdGlvbi52YWxpZGF0ZV9pZF90b2tlbl9ub25jZSh0b1JldHVybi5kZWNvZGVkX2lkX3Rva2VuLCB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoTm9uY2UpKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdhdXRob3JpemVkQ2FsbGJhY2sgaW5jb3JyZWN0IG5vbmNlJyk7XHJcbiAgICAgICAgICAgIHRvUmV0dXJuLnN0YXRlID0gVmFsaWRhdGlvblJlc3VsdC5JbmNvcnJlY3ROb25jZTtcclxuICAgICAgICAgICAgdGhpcy5oYW5kbGVVbnN1Y2Nlc3NmdWxWYWxpZGF0aW9uKCk7XHJcbiAgICAgICAgICAgIHJldHVybiB0b1JldHVybjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmICghdGhpcy5vaWRjU2VjdXJpdHlWYWxpZGF0aW9uLnZhbGlkYXRlX3JlcXVpcmVkX2lkX3Rva2VuKHRvUmV0dXJuLmRlY29kZWRfaWRfdG9rZW4pKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnYXV0aG9yaXplZENhbGxiYWNrIFZhbGlkYXRpb24sIG9uZSBvZiB0aGUgUkVRVUlSRUQgcHJvcGVydGllcyBtaXNzaW5nIGZyb20gaWRfdG9rZW4nKTtcclxuICAgICAgICAgICAgdG9SZXR1cm4uc3RhdGUgPSBWYWxpZGF0aW9uUmVzdWx0LlJlcXVpcmVkUHJvcGVydHlNaXNzaW5nO1xyXG4gICAgICAgICAgICB0aGlzLmhhbmRsZVVuc3VjY2Vzc2Z1bFZhbGlkYXRpb24oKTtcclxuICAgICAgICAgICAgcmV0dXJuIHRvUmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKFxyXG4gICAgICAgICAgICAhdGhpcy5vaWRjU2VjdXJpdHlWYWxpZGF0aW9uLnZhbGlkYXRlX2lkX3Rva2VuX2lhdF9tYXhfb2Zmc2V0KFxyXG4gICAgICAgICAgICAgICAgdG9SZXR1cm4uZGVjb2RlZF9pZF90b2tlbixcclxuICAgICAgICAgICAgICAgIHRoaXMuYXV0aENvbmZpZ3VyYXRpb24ubWF4X2lkX3Rva2VuX2lhdF9vZmZzZXRfYWxsb3dlZF9pbl9zZWNvbmRzLFxyXG4gICAgICAgICAgICAgICAgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5kaXNhYmxlX2lhdF9vZmZzZXRfdmFsaWRhdGlvblxyXG4gICAgICAgICAgICApXHJcbiAgICAgICAgKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdhdXRob3JpemVkQ2FsbGJhY2sgVmFsaWRhdGlvbiwgaWF0IHJlamVjdGVkIGlkX3Rva2VuIHdhcyBpc3N1ZWQgdG9vIGZhciBhd2F5IGZyb20gdGhlIGN1cnJlbnQgdGltZScpO1xyXG4gICAgICAgICAgICB0b1JldHVybi5zdGF0ZSA9IFZhbGlkYXRpb25SZXN1bHQuTWF4T2Zmc2V0RXhwaXJlZDtcclxuICAgICAgICAgICAgdGhpcy5oYW5kbGVVbnN1Y2Nlc3NmdWxWYWxpZGF0aW9uKCk7XHJcbiAgICAgICAgICAgIHJldHVybiB0b1JldHVybjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmICh0aGlzLmF1dGhXZWxsS25vd25FbmRwb2ludHMpIHtcclxuICAgICAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uaXNzX3ZhbGlkYXRpb25fb2ZmKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ2lzcyB2YWxpZGF0aW9uIGlzIHR1cm5lZCBvZmYsIHRoaXMgaXMgbm90IHJlY29tbWVuZGVkIScpO1xyXG4gICAgICAgICAgICB9IGVsc2UgaWYgKCF0aGlzLmF1dGhDb25maWd1cmF0aW9uLmlzc192YWxpZGF0aW9uX29mZiAmJlxyXG4gICAgICAgICAgICAgICAgIXRoaXMub2lkY1NlY3VyaXR5VmFsaWRhdGlvbi52YWxpZGF0ZV9pZF90b2tlbl9pc3ModG9SZXR1cm4uZGVjb2RlZF9pZF90b2tlbiwgdGhpcy5hdXRoV2VsbEtub3duRW5kcG9pbnRzLmlzc3VlcikpIHtcclxuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdhdXRob3JpemVkQ2FsbGJhY2sgaW5jb3JyZWN0IGlzcyBkb2VzIG5vdCBtYXRjaCBhdXRoV2VsbEtub3duRW5kcG9pbnRzIGlzc3VlcicpO1xyXG4gICAgICAgICAgICAgICAgdG9SZXR1cm4uc3RhdGUgPSBWYWxpZGF0aW9uUmVzdWx0Lklzc0RvZXNOb3RNYXRjaElzc3VlcjtcclxuICAgICAgICAgICAgICAgIHRoaXMuaGFuZGxlVW5zdWNjZXNzZnVsVmFsaWRhdGlvbigpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRvUmV0dXJuO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2F1dGhXZWxsS25vd25FbmRwb2ludHMgaXMgdW5kZWZpbmVkJyk7XHJcbiAgICAgICAgICAgIHRvUmV0dXJuLnN0YXRlID0gVmFsaWRhdGlvblJlc3VsdC5Ob0F1dGhXZWxsS25vd25FbmRQb2ludHM7XHJcbiAgICAgICAgICAgIHRoaXMuaGFuZGxlVW5zdWNjZXNzZnVsVmFsaWRhdGlvbigpO1xyXG4gICAgICAgICAgICByZXR1cm4gdG9SZXR1cm47XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoIXRoaXMub2lkY1NlY3VyaXR5VmFsaWRhdGlvbi52YWxpZGF0ZV9pZF90b2tlbl9hdWQodG9SZXR1cm4uZGVjb2RlZF9pZF90b2tlbiwgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5jbGllbnRfaWQpKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdhdXRob3JpemVkQ2FsbGJhY2sgaW5jb3JyZWN0IGF1ZCcpO1xyXG4gICAgICAgICAgICB0b1JldHVybi5zdGF0ZSA9IFZhbGlkYXRpb25SZXN1bHQuSW5jb3JyZWN0QXVkO1xyXG4gICAgICAgICAgICB0aGlzLmhhbmRsZVVuc3VjY2Vzc2Z1bFZhbGlkYXRpb24oKTtcclxuICAgICAgICAgICAgcmV0dXJuIHRvUmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKCF0aGlzLm9pZGNTZWN1cml0eVZhbGlkYXRpb24udmFsaWRhdGVfaWRfdG9rZW5fZXhwX25vdF9leHBpcmVkKHRvUmV0dXJuLmRlY29kZWRfaWRfdG9rZW4pKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdhdXRob3JpemVkQ2FsbGJhY2sgdG9rZW4gZXhwaXJlZCcpO1xyXG4gICAgICAgICAgICB0b1JldHVybi5zdGF0ZSA9IFZhbGlkYXRpb25SZXN1bHQuVG9rZW5FeHBpcmVkO1xyXG4gICAgICAgICAgICB0aGlzLmhhbmRsZVVuc3VjY2Vzc2Z1bFZhbGlkYXRpb24oKTtcclxuICAgICAgICAgICAgcmV0dXJuIHRvUmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgLy8gZmxvdyBpZF90b2tlbiB0b2tlblxyXG4gICAgICAgIGlmICh0aGlzLmF1dGhDb25maWd1cmF0aW9uLnJlc3BvbnNlX3R5cGUgIT09ICdpZF90b2tlbiB0b2tlbicgJiYgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5yZXNwb25zZV90eXBlICE9PSAnY29kZScpIHtcclxuICAgICAgICAgICAgdG9SZXR1cm4uYXV0aFJlc3BvbnNlSXNWYWxpZCA9IHRydWU7XHJcbiAgICAgICAgICAgIHRvUmV0dXJuLnN0YXRlID0gVmFsaWRhdGlvblJlc3VsdC5PaztcclxuICAgICAgICAgICAgdGhpcy5oYW5kbGVTdWNjZXNzZnVsVmFsaWRhdGlvbigpO1xyXG4gICAgICAgICAgICB0aGlzLmhhbmRsZVVuc3VjY2Vzc2Z1bFZhbGlkYXRpb24oKTtcclxuICAgICAgICAgICAgcmV0dXJuIHRvUmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKCF0aGlzLm9pZGNTZWN1cml0eVZhbGlkYXRpb24udmFsaWRhdGVfaWRfdG9rZW5fYXRfaGFzaCh0b1JldHVybi5hY2Nlc3NfdG9rZW4sXHJcbiAgICAgICAgICAgIHRvUmV0dXJuLmRlY29kZWRfaWRfdG9rZW4uYXRfaGFzaCxcclxuICAgICAgICAgICAgdGhpcy5hdXRoQ29uZmlndXJhdGlvbi5yZXNwb25zZV90eXBlID09PSAnY29kZScpIHx8XHJcbiAgICAgICAgICAgICF0b1JldHVybi5hY2Nlc3NfdG9rZW5cclxuICAgICAgICApIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2F1dGhvcml6ZWRDYWxsYmFjayBpbmNvcnJlY3QgYXRfaGFzaCcpO1xyXG4gICAgICAgICAgICB0b1JldHVybi5zdGF0ZSA9IFZhbGlkYXRpb25SZXN1bHQuSW5jb3JyZWN0QXRIYXNoO1xyXG4gICAgICAgICAgICB0aGlzLmhhbmRsZVVuc3VjY2Vzc2Z1bFZhbGlkYXRpb24oKTtcclxuICAgICAgICAgICAgcmV0dXJuIHRvUmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgdG9SZXR1cm4uYXV0aFJlc3BvbnNlSXNWYWxpZCA9IHRydWU7XHJcbiAgICAgICAgdG9SZXR1cm4uc3RhdGUgPSBWYWxpZGF0aW9uUmVzdWx0Lk9rO1xyXG4gICAgICAgIHRoaXMuaGFuZGxlU3VjY2Vzc2Z1bFZhbGlkYXRpb24oKTtcclxuICAgICAgICByZXR1cm4gdG9SZXR1cm47XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBoYW5kbGVTdWNjZXNzZnVsVmFsaWRhdGlvbigpIHtcclxuICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoTm9uY2UgPSAnJztcclxuXHJcbiAgICAgICAgaWYgKHRoaXMuYXV0aENvbmZpZ3VyYXRpb24uYXV0b19jbGVhbl9zdGF0ZV9hZnRlcl9hdXRoZW50aWNhdGlvbikge1xyXG4gICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5hdXRoU3RhdGVDb250cm9sID0gJyc7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnQXV0aG9yaXplZENhbGxiYWNrIHRva2VuKHMpIHZhbGlkYXRlZCwgY29udGludWUnKTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIGhhbmRsZVVuc3VjY2Vzc2Z1bFZhbGlkYXRpb24oKSB7XHJcbiAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aE5vbmNlID0gJyc7XHJcblxyXG4gICAgICAgIGlmICh0aGlzLmF1dGhDb25maWd1cmF0aW9uLmF1dG9fY2xlYW5fc3RhdGVfYWZ0ZXJfYXV0aGVudGljYXRpb24pIHtcclxuICAgICAgICAgICAgdGhpcy5vaWRjU2VjdXJpdHlDb21tb24uYXV0aFN0YXRlQ29udHJvbCA9ICcnO1xyXG4gICAgICAgIH1cclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ0F1dGhvcml6ZWRDYWxsYmFjayB0b2tlbihzKSBpbnZhbGlkJyk7XHJcbiAgICB9XHJcbn1cclxuIl19