import { Observable } from 'rxjs';
import { OidcDataService } from '../data-services/oidc-data.service';
import { AuthWellKnownEndpoints } from '../models/auth.well-known-endpoints';
import { LoggerService } from './oidc.logger.service';
import { OidcSecurityCommon } from './oidc.security.common';
export declare class OidcSecurityUserService {
    private oidcDataService;
    private oidcSecurityCommon;
    private loggerService;
    private userData;
    private authWellKnownEndpoints;
    constructor(oidcDataService: OidcDataService, oidcSecurityCommon: OidcSecurityCommon, loggerService: LoggerService);
    setupModule(authWellKnownEndpoints: AuthWellKnownEndpoints): void;
    initUserData(): Observable<any>;
    getUserData(): any;
    setUserData(value: any): void;
    private getIdentityUserData;
}
