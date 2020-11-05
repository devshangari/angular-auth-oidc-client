import { Observable } from 'rxjs';
import { IFrameService } from './existing-iframe.service';
import { LoggerService } from './oidc.logger.service';
export declare class OidcSecuritySilentRenew {
    private loggerService;
    private iFrameService;
    private sessionIframe;
    private isRenewInitialized;
    constructor(loggerService: LoggerService, iFrameService: IFrameService);
    initRenew(): void;
    startRenew(url: string): Observable<any>;
}
