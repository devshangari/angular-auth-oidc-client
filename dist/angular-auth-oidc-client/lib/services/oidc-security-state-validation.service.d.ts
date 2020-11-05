import { AuthWellKnownEndpoints } from '../models/auth.well-known-endpoints';
import { JwtKeys } from '../models/jwtkeys';
import { ValidateStateResult } from '../models/validate-state-result.model';
import { AuthConfiguration } from '../modules/auth.configuration';
import { TokenHelperService } from './oidc-token-helper.service';
import { LoggerService } from './oidc.logger.service';
import { OidcSecurityCommon } from './oidc.security.common';
import { OidcSecurityValidation } from './oidc.security.validation';
export declare class StateValidationService {
    private authConfiguration;
    oidcSecurityCommon: OidcSecurityCommon;
    private oidcSecurityValidation;
    private tokenHelperService;
    private loggerService;
    private authWellKnownEndpoints;
    constructor(authConfiguration: AuthConfiguration, oidcSecurityCommon: OidcSecurityCommon, oidcSecurityValidation: OidcSecurityValidation, tokenHelperService: TokenHelperService, loggerService: LoggerService);
    setupModule(authWellKnownEndpoints: AuthWellKnownEndpoints): void;
    validateState(result: any, jwtKeys: JwtKeys): ValidateStateResult;
    private handleSuccessfulValidation;
    private handleUnsuccessfulValidation;
}
