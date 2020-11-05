import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
export declare class OidcConfigService {
    private readonly httpClient;
    private _onConfigurationLoaded;
    clientConfiguration: any;
    wellKnownEndpoints: any;
    readonly onConfigurationLoaded: Observable<boolean>;
    constructor(httpClient: HttpClient);
    load(configUrl: string): void;
    load_using_stsServer(stsServer: string): void;
    load_using_custom_stsServer(url: string): void;
}
