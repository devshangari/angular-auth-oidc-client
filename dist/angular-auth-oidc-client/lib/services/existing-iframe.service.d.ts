import { LoggerService } from './oidc.logger.service';
export declare class IFrameService {
    private loggerService;
    constructor(loggerService: LoggerService);
    getExistingIFrame(identifier: string): HTMLElement;
    addIFrameToWindowBody(identifier: string): HTMLIFrameElement;
    private getIFrameFromParentWindow;
    private getIFrameFromWindow;
}
