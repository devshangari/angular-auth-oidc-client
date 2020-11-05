import { LoggerService } from './oidc.logger.service';
export declare class TokenHelperService {
    private readonly loggerService;
    private PARTS_OF_TOKEN;
    constructor(loggerService: LoggerService);
    getTokenExpirationDate(dataIdToken: any): Date;
    getHeaderFromToken(token: any, encoded: boolean): any;
    getPayloadFromToken(token: any, encoded: boolean): any;
    getSignatureFromToken(token: any, encoded: boolean): any;
    private getPartOfToken;
    private urlBase64Decode;
    private tokenIsValid;
    private extractPartOfToken;
}
