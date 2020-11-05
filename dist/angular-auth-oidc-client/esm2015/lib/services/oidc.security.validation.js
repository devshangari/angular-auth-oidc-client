/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
import { hextob64u, KEYUTIL, KJUR } from 'jsrsasign';
import { EqualityHelperService } from './oidc-equality-helper.service';
import { TokenHelperService } from './oidc-token-helper.service';
import { LoggerService } from './oidc.logger.service';
// http://openid.net/specs/openid-connect-implicit-1_0.html
// id_token
// id_token C1: The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
// MUST exactly match the value of the iss (issuer) Claim.
//
// id_token C2: The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified
// by the iss (issuer) Claim as an audience.The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience,
// or if it contains additional audiences not trusted by the Client.
//
// id_token C3: If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
//
// id_token C4: If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
//
// id_token C5: The Client MUST validate the signature of the ID Token according to JWS [JWS] using the algorithm specified in the
// alg Header Parameter of the JOSE Header.The Client MUST use the keys provided by the Issuer.
//
// id_token C6: The alg value SHOULD be RS256. Validation of tokens using other signing algorithms is described in the OpenID Connect Core 1.0
// [OpenID.Core] specification.
//
// id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account
// for clock skew).
//
// id_token C8: The iat Claim can be used to reject tokens that were issued too far away from the current time,
// limiting the amount of time that nonces need to be stored to prevent attacks.The acceptable range is Client specific.
//
// id_token C9: The value of the nonce Claim MUST be checked to verify that it is the same value as the one that was sent
// in the Authentication Request.The Client SHOULD check the nonce value for replay attacks.The precise method for detecting replay attacks
// is Client specific.
//
// id_token C10: If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate.
// The meaning and processing of acr Claim Values is out of scope for this document.
//
// id_token C11: When a max_age request is made, the Client SHOULD check the auth_time Claim value and request re- authentication
// if it determines too much time has elapsed since the last End- User authentication.
// Access Token Validation
// access_token C1: Hash the octets of the ASCII representation of the access_token with the hash algorithm specified in JWA[JWA]
// for the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, the hash algorithm used is SHA-256.
// access_token C2: Take the left- most half of the hash and base64url- encode it.
// access_token C3: The value of at_hash in the ID Token MUST match the value produced in the previous step if at_hash is present in the ID Token.
export class OidcSecurityValidation {
    /**
     * @param {?} arrayHelperService
     * @param {?} tokenHelperService
     * @param {?} loggerService
     */
    constructor(arrayHelperService, tokenHelperService, loggerService) {
        this.arrayHelperService = arrayHelperService;
        this.tokenHelperService = tokenHelperService;
        this.loggerService = loggerService;
    }
    // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
    /**
     * @param {?} token
     * @param {?=} offsetSeconds
     * @return {?}
     */
    isTokenExpired(token, offsetSeconds) {
        /** @type {?} */
        let decoded;
        decoded = this.tokenHelperService.getPayloadFromToken(token, false);
        return !this.validate_id_token_exp_not_expired(decoded, offsetSeconds);
    }
    // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
    /**
     * @param {?} decoded_id_token
     * @param {?=} offsetSeconds
     * @return {?}
     */
    validate_id_token_exp_not_expired(decoded_id_token, offsetSeconds) {
        /** @type {?} */
        const tokenExpirationDate = this.tokenHelperService.getTokenExpirationDate(decoded_id_token);
        offsetSeconds = offsetSeconds || 0;
        if (!tokenExpirationDate) {
            return false;
        }
        /** @type {?} */
        const tokenExpirationValue = tokenExpirationDate.valueOf();
        /** @type {?} */
        const nowWithOffset = new Date().valueOf() + offsetSeconds * 1000;
        /** @type {?} */
        const tokenNotExpired = tokenExpirationValue > nowWithOffset;
        this.loggerService.logDebug(`Token not expired?: ${tokenExpirationValue} > ${nowWithOffset}  (${tokenNotExpired})`);
        // Token not expired?
        return tokenNotExpired;
    }
    // iss
    // REQUIRED. Issuer Identifier for the Issuer of the response.The iss value is a case-sensitive URL using the https scheme that contains scheme, host,
    // and optionally, port number and path components and no query or fragment components.
    //
    // sub
    // REQUIRED. Subject Identifier.Locally unique and never reassigned identifier within the Issuer for the End- User,
    // which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
    // It MUST NOT exceed 255 ASCII characters in length.The sub value is a case-sensitive string.
    //
    // aud
    // REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value.
    // It MAY also contain identifiers for other audiences.In the general case, the aud value is an array of case-sensitive strings.
    // In the common special case when there is one audience, the aud value MAY be a single case-sensitive string.
    //
    // exp
    // REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
    // The processing of this parameter requires that the current date/ time MUST be before the expiration date/ time listed in the value.
    // Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.
    // Its value is a JSON [RFC7159] number representing the number of seconds from 1970- 01 - 01T00: 00:00Z as measured in UTC until the date/ time.
    // See RFC 3339 [RFC3339] for details regarding date/ times in general and UTC in particular.
    //
    // iat
    // REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970- 01 - 01T00: 00:00Z as measured
    // in UTC until the date/ time.
    /**
     * @param {?} dataIdToken
     * @return {?}
     */
    validate_required_id_token(dataIdToken) {
        /** @type {?} */
        let validated = true;
        if (!dataIdToken.hasOwnProperty('iss')) {
            validated = false;
            this.loggerService.logWarning('iss is missing, this is required in the id_token');
        }
        if (!dataIdToken.hasOwnProperty('sub')) {
            validated = false;
            this.loggerService.logWarning('sub is missing, this is required in the id_token');
        }
        if (!dataIdToken.hasOwnProperty('aud')) {
            validated = false;
            this.loggerService.logWarning('aud is missing, this is required in the id_token');
        }
        if (!dataIdToken.hasOwnProperty('exp')) {
            validated = false;
            this.loggerService.logWarning('exp is missing, this is required in the id_token');
        }
        if (!dataIdToken.hasOwnProperty('iat')) {
            validated = false;
            this.loggerService.logWarning('iat is missing, this is required in the id_token');
        }
        return validated;
    }
    // id_token C8: The iat Claim can be used to reject tokens that were issued too far away from the current time,
    // limiting the amount of time that nonces need to be stored to prevent attacks.The acceptable range is Client specific.
    /**
     * @param {?} dataIdToken
     * @param {?} max_offset_allowed_in_seconds
     * @param {?} disable_iat_offset_validation
     * @return {?}
     */
    validate_id_token_iat_max_offset(dataIdToken, max_offset_allowed_in_seconds, disable_iat_offset_validation) {
        if (disable_iat_offset_validation) {
            return true;
        }
        if (!dataIdToken.hasOwnProperty('iat')) {
            return false;
        }
        /** @type {?} */
        const dateTime_iat_id_token = new Date(0);
        dateTime_iat_id_token.setUTCSeconds(dataIdToken.iat);
        max_offset_allowed_in_seconds = max_offset_allowed_in_seconds || 0;
        if (dateTime_iat_id_token == null) {
            return false;
        }
        this.loggerService.logDebug('validate_id_token_iat_max_offset: ' +
            (new Date().valueOf() - dateTime_iat_id_token.valueOf()) +
            ' < ' +
            max_offset_allowed_in_seconds * 1000);
        return new Date().valueOf() - dateTime_iat_id_token.valueOf() < max_offset_allowed_in_seconds * 1000;
    }
    // id_token C9: The value of the nonce Claim MUST be checked to verify that it is the same value as the one
    // that was sent in the Authentication Request.The Client SHOULD check the nonce value for replay attacks.
    // The precise method for detecting replay attacks is Client specific.
    /**
     * @param {?} dataIdToken
     * @param {?} local_nonce
     * @return {?}
     */
    validate_id_token_nonce(dataIdToken, local_nonce) {
        if (dataIdToken.nonce !== local_nonce) {
            this.loggerService.logDebug('Validate_id_token_nonce failed, dataIdToken.nonce: ' + dataIdToken.nonce + ' local_nonce:' + local_nonce);
            return false;
        }
        return true;
    }
    // id_token C1: The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
    // MUST exactly match the value of the iss (issuer) Claim.
    /**
     * @param {?} dataIdToken
     * @param {?} authWellKnownEndpoints_issuer
     * @return {?}
     */
    validate_id_token_iss(dataIdToken, authWellKnownEndpoints_issuer) {
        if (((/** @type {?} */ (dataIdToken.iss))) !== ((/** @type {?} */ (authWellKnownEndpoints_issuer)))) {
            this.loggerService.logDebug('Validate_id_token_iss failed, dataIdToken.iss: ' +
                dataIdToken.iss +
                ' authWellKnownEndpoints issuer:' +
                authWellKnownEndpoints_issuer);
            return false;
        }
        return true;
    }
    // id_token C2: The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified
    // by the iss (issuer) Claim as an audience.
    // The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences
    // not trusted by the Client.
    /**
     * @param {?} dataIdToken
     * @param {?} aud
     * @return {?}
     */
    validate_id_token_aud(dataIdToken, aud) {
        if (dataIdToken.aud instanceof Array) {
            /** @type {?} */
            const result = this.arrayHelperService.areEqual(dataIdToken.aud, aud);
            if (!result) {
                this.loggerService.logDebug('Validate_id_token_aud  array failed, dataIdToken.aud: ' + dataIdToken.aud + ' client_id:' + aud);
                return false;
            }
            return true;
        }
        else if (dataIdToken.aud !== aud) {
            this.loggerService.logDebug('Validate_id_token_aud failed, dataIdToken.aud: ' + dataIdToken.aud + ' client_id:' + aud);
            return false;
        }
        return true;
    }
    /**
     * @param {?} state
     * @param {?} local_state
     * @return {?}
     */
    validateStateFromHashCallback(state, local_state) {
        if (((/** @type {?} */ (state))) !== ((/** @type {?} */ (local_state)))) {
            this.loggerService.logDebug('ValidateStateFromHashCallback failed, state: ' + state + ' local_state:' + local_state);
            return false;
        }
        return true;
    }
    /**
     * @param {?} id_token_sub
     * @param {?} userdata_sub
     * @return {?}
     */
    validate_userdata_sub_id_token(id_token_sub, userdata_sub) {
        if (((/** @type {?} */ (id_token_sub))) !== ((/** @type {?} */ (userdata_sub)))) {
            this.loggerService.logDebug('validate_userdata_sub_id_token failed, id_token_sub: ' + id_token_sub + ' userdata_sub:' + userdata_sub);
            return false;
        }
        return true;
    }
    // id_token C5: The Client MUST validate the signature of the ID Token according to JWS [JWS] using the algorithm specified in the alg
    // Header Parameter of the JOSE Header.The Client MUST use the keys provided by the Issuer.
    // id_token C6: The alg value SHOULD be RS256. Validation of tokens using other signing algorithms is described in the
    // OpenID Connect Core 1.0 [OpenID.Core] specification.
    /**
     * @param {?} id_token
     * @param {?} jwtkeys
     * @return {?}
     */
    validate_signature_id_token(id_token, jwtkeys) {
        if (!jwtkeys || !jwtkeys.keys) {
            return false;
        }
        /** @type {?} */
        const header_data = this.tokenHelperService.getHeaderFromToken(id_token, false);
        if (Object.keys(header_data).length === 0 && header_data.constructor === Object) {
            this.loggerService.logWarning('id token has no header data');
            return false;
        }
        /** @type {?} */
        const kid = header_data.kid;
        /** @type {?} */
        const alg = header_data.alg;
        if ('RS256' !== ((/** @type {?} */ (alg)))) {
            this.loggerService.logWarning('Only RS256 supported');
            return false;
        }
        /** @type {?} */
        let isValid = false;
        if (!header_data.hasOwnProperty('kid')) {
            // exactly 1 key in the jwtkeys and no kid in the Jose header
            // kty	"RSA" use "sig"
            /** @type {?} */
            let amountOfMatchingKeys = 0;
            for (const key of jwtkeys.keys) {
                if (((/** @type {?} */ (key.kty))) === 'RSA' && ((/** @type {?} */ (key.use))) === 'sig') {
                    amountOfMatchingKeys = amountOfMatchingKeys + 1;
                }
            }
            if (amountOfMatchingKeys === 0) {
                this.loggerService.logWarning('no keys found, incorrect Signature, validation failed for id_token');
                return false;
            }
            else if (amountOfMatchingKeys > 1) {
                this.loggerService.logWarning('no ID Token kid claim in JOSE header and multiple supplied in jwks_uri');
                return false;
            }
            else {
                for (const key of jwtkeys.keys) {
                    if (((/** @type {?} */ (key.kty))) === 'RSA' && ((/** @type {?} */ (key.use))) === 'sig') {
                        /** @type {?} */
                        const publickey = KEYUTIL.getKey(key);
                        isValid = KJUR.jws.JWS.verify(id_token, publickey, ['RS256']);
                        if (!isValid) {
                            this.loggerService.logWarning('incorrect Signature, validation failed for id_token');
                        }
                        return isValid;
                    }
                }
            }
        }
        else {
            // kid in the Jose header of id_token
            for (const key of jwtkeys.keys) {
                if (((/** @type {?} */ (key.kid))) === ((/** @type {?} */ (kid)))) {
                    /** @type {?} */
                    const publickey = KEYUTIL.getKey(key);
                    isValid = KJUR.jws.JWS.verify(id_token, publickey, ['RS256']);
                    if (!isValid) {
                        this.loggerService.logWarning('incorrect Signature, validation failed for id_token');
                    }
                    return isValid;
                }
            }
        }
        return isValid;
    }
    /**
     * @param {?} response_type
     * @return {?}
     */
    config_validate_response_type(response_type) {
        if (response_type === 'id_token token' || response_type === 'id_token') {
            return true;
        }
        if (response_type === 'code') {
            return true;
        }
        this.loggerService.logWarning('module configure incorrect, invalid response_type:' + response_type);
        return false;
    }
    // Accepts ID Token without 'kid' claim in JOSE header if only one JWK supplied in 'jwks_url'
    //// private validate_no_kid_in_header_only_one_allowed_in_jwtkeys(header_data: any, jwtkeys: any): boolean {
    ////    this.oidcSecurityCommon.logDebug('amount of jwtkeys.keys: ' + jwtkeys.keys.length);
    ////    if (!header_data.hasOwnProperty('kid')) {
    ////        // no kid defined in Jose header
    ////        if (jwtkeys.keys.length != 1) {
    ////            this.oidcSecurityCommon.logDebug('jwtkeys.keys.length != 1 and no kid in header');
    ////            return false;
    ////        }
    ////    }
    ////    return true;
    //// }
    // Access Token Validation
    // access_token C1: Hash the octets of the ASCII representation of the access_token with the hash algorithm specified in JWA[JWA]
    // for the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, the hash algorithm used is SHA-256.
    // access_token C2: Take the left- most half of the hash and base64url- encode it.
    // access_token C3: The value of at_hash in the ID Token MUST match the value produced in the previous step if at_hash
    // is present in the ID Token.
    /**
     * @param {?} access_token
     * @param {?} at_hash
     * @param {?} isCodeFlow
     * @return {?}
     */
    validate_id_token_at_hash(access_token, at_hash, isCodeFlow) {
        this.loggerService.logDebug('at_hash from the server:' + at_hash);
        // The at_hash is optional for the code flow
        if (isCodeFlow) {
            if (!((/** @type {?} */ (at_hash)))) {
                this.loggerService.logDebug('Code Flow active, and no at_hash in the id_token, skipping check!');
                return true;
            }
        }
        /** @type {?} */
        const testdata = this.generate_at_hash('' + access_token);
        this.loggerService.logDebug('at_hash client validation not decoded:' + testdata);
        if (testdata === ((/** @type {?} */ (at_hash)))) {
            return true; // isValid;
        }
        else {
            /** @type {?} */
            const testValue = this.generate_at_hash('' + decodeURIComponent(access_token));
            this.loggerService.logDebug('-gen access--' + testValue);
            if (testValue === ((/** @type {?} */ (at_hash)))) {
                return true; // isValid
            }
        }
        return false;
    }
    /**
     * @private
     * @param {?} access_token
     * @return {?}
     */
    generate_at_hash(access_token) {
        /** @type {?} */
        const hash = KJUR.crypto.Util.hashString(access_token, 'sha256');
        /** @type {?} */
        const first128bits = hash.substr(0, hash.length / 2);
        /** @type {?} */
        const testdata = hextob64u(first128bits);
        return testdata;
    }
    /**
     * @param {?} code_challenge
     * @return {?}
     */
    generate_code_verifier(code_challenge) {
        /** @type {?} */
        const hash = KJUR.crypto.Util.hashString(code_challenge, 'sha256');
        /** @type {?} */
        const testdata = hextob64u(hash);
        return testdata;
    }
}
OidcSecurityValidation.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OidcSecurityValidation.ctorParameters = () => [
    { type: EqualityHelperService },
    { type: TokenHelperService },
    { type: LoggerService }
];
if (false) {
    /**
     * @type {?}
     * @private
     */
    OidcSecurityValidation.prototype.arrayHelperService;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityValidation.prototype.tokenHelperService;
    /**
     * @type {?}
     * @private
     */
    OidcSecurityValidation.prototype.loggerService;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS52YWxpZGF0aW9uLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1hdXRoLW9pZGMtY2xpZW50LyIsInNvdXJjZXMiOlsibGliL3NlcnZpY2VzL29pZGMuc2VjdXJpdHkudmFsaWRhdGlvbi50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsU0FBUyxFQUFFLE9BQU8sRUFBRSxJQUFJLEVBQUUsTUFBTSxXQUFXLENBQUM7QUFDckQsT0FBTyxFQUFFLHFCQUFxQixFQUFFLE1BQU0sZ0NBQWdDLENBQUM7QUFDdkUsT0FBTyxFQUFFLGtCQUFrQixFQUFFLE1BQU0sNkJBQTZCLENBQUM7QUFDakUsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLHVCQUF1QixDQUFDOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBNkN0RCxNQUFNLE9BQU8sc0JBQXNCOzs7Ozs7SUFDL0IsWUFDWSxrQkFBeUMsRUFDekMsa0JBQXNDLEVBQ3RDLGFBQTRCO1FBRjVCLHVCQUFrQixHQUFsQixrQkFBa0IsQ0FBdUI7UUFDekMsdUJBQWtCLEdBQWxCLGtCQUFrQixDQUFvQjtRQUN0QyxrQkFBYSxHQUFiLGFBQWEsQ0FBZTtJQUNyQyxDQUFDOzs7Ozs7O0lBR0osY0FBYyxDQUFDLEtBQWEsRUFBRSxhQUFzQjs7WUFDNUMsT0FBWTtRQUNoQixPQUFPLEdBQUcsSUFBSSxDQUFDLGtCQUFrQixDQUFDLG1CQUFtQixDQUFDLEtBQUssRUFBRSxLQUFLLENBQUMsQ0FBQztRQUVwRSxPQUFPLENBQUMsSUFBSSxDQUFDLGlDQUFpQyxDQUFDLE9BQU8sRUFBRSxhQUFhLENBQUMsQ0FBQztJQUMzRSxDQUFDOzs7Ozs7O0lBR0QsaUNBQWlDLENBQUMsZ0JBQXdCLEVBQUUsYUFBc0I7O2NBQ3hFLG1CQUFtQixHQUFHLElBQUksQ0FBQyxrQkFBa0Is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QUFDLG1CQUFBLE9BQU8sRUFBVSxDQUFDLEVBQUU7Z0JBQ25DLE9BQU8sSUFBSSxDQUFDLENBQUMsVUFBVTthQUMxQjtTQUNKO1FBRUQsT0FBTyxLQUFLLENBQUM7SUFDakIsQ0FBQzs7Ozs7O0lBRU8sZ0JBQWdCLENBQUMsWUFBaUI7O2NBQ2hDLElBQUksR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsWUFBWSxFQUFFLFFBQVEsQ0FBQzs7Y0FDMUQsWUFBWSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLElBQUksQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDOztjQUM5QyxRQUFRLEdBQUcsU0FBUyxDQUFDLFlBQVksQ0FBQztRQUV4QyxPQUFPLFFBQVEsQ0FBQztJQUNwQixDQUFDOzs7OztJQUVELHNCQUFzQixDQUFDLGNBQW1COztjQUNoQyxJQUFJLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLGNBQWMsRUFBRSxRQUFRLENBQUM7O2NBQzVELFFBQVEsR0FBRyxTQUFTLENBQUMsSUFBSSxDQUFDO1FBRWhDLE9BQU8sUUFBUSxDQUFDO0lBQ3BCLENBQUM7OztZQTdVSixVQUFVOzs7O1lBOUNGLHFCQUFxQjtZQUNyQixrQkFBa0I7WUFDbEIsYUFBYTs7Ozs7OztJQStDZCxvREFBaUQ7Ozs7O0lBQ2pELG9EQUE4Qzs7Ozs7SUFDOUMsK0NBQW9DIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xyXG5pbXBvcnQgeyBoZXh0b2I2NHUsIEtFWVVUSUwsIEtKVVIgfSBmcm9tICdqc3JzYXNpZ24nO1xyXG5pbXBvcnQgeyBFcXVhbGl0eUhlbHBlclNlcnZpY2UgfSBmcm9tICcuL29pZGMtZXF1YWxpdHktaGVscGVyLnNlcnZpY2UnO1xyXG5pbXBvcnQgeyBUb2tlbkhlbHBlclNlcnZpY2UgfSBmcm9tICcuL29pZGMtdG9rZW4taGVscGVyLnNlcnZpY2UnO1xyXG5pbXBvcnQgeyBMb2dnZXJTZXJ2aWNlIH0gZnJvbSAnLi9vaWRjLmxvZ2dlci5zZXJ2aWNlJztcclxuXHJcbi8vIGh0dHA6Ly9vcGVuaWQubmV0L3NwZWNzL29wZW5pZC1jb25uZWN0LWltcGxpY2l0LTFfMC5odG1sXHJcblxyXG4vLyBpZF90b2tlblxyXG4vLyBpZF90b2tlbiBDMTogVGhlIElzc3VlciBJZGVudGlmaWVyIGZvciB0aGUgT3BlbklEIFByb3ZpZGVyICh3aGljaCBpcyB0eXBpY2FsbHkgb2J0YWluZWQgZHVyaW5nIERpc2NvdmVyeSlcclxuLy8gTVVTVCBleGFjdGx5IG1hdGNoIHRoZSB2YWx1ZSBvZiB0aGUgaXNzIChpc3N1ZXIpIENsYWltLlxyXG4vL1xyXG4vLyBpZF90b2tlbiBDMjogVGhlIENsaWVudCBNVVNUIHZhbGlkYXRlIHRoYXQgdGhlIGF1ZCAoYXVkaWVuY2UpIENsYWltIGNvbnRhaW5zIGl0cyBjbGllbnRfaWQgdmFsdWUgcmVnaXN0ZXJlZCBhdCB0aGUgSXNzdWVyIGlkZW50aWZpZWRcclxuLy8gYnkgdGhlIGlzcyAoaXNzdWVyKSBDbGFpbSBhcyBhbiBhdWRpZW5jZS5UaGUgSUQgVG9rZW4gTVVTVCBiZSByZWplY3RlZCBpZiB0aGUgSUQgVG9rZW4gZG9lcyBub3QgbGlzdCB0aGUgQ2xpZW50IGFzIGEgdmFsaWQgYXVkaWVuY2UsXHJcbi8vIG9yIGlmIGl0IGNvbnRhaW5zIGFkZGl0aW9uYWwgYXVkaWVuY2VzIG5vdCB0cnVzdGVkIGJ5IHRoZSBDbGllbnQuXHJcbi8vXHJcbi8vIGlkX3Rva2VuIEMzOiBJZiB0aGUgSUQgVG9rZW4gY29udGFpbnMgbXVsdGlwbGUgYXVkaWVuY2VzLCB0aGUgQ2xpZW50IFNIT1VMRCB2ZXJpZnkgdGhhdCBhbiBhenAgQ2xhaW0gaXMgcHJlc2VudC5cclxuLy9cclxuLy8gaWRfdG9rZW4gQzQ6IElmIGFuIGF6cCAoYXV0aG9yaXplZCBwYXJ0eSkgQ2xhaW0gaXMgcHJlc2VudCwgdGhlIENsaWVudCBTSE9VTEQgdmVyaWZ5IHRoYXQgaXRzIGNsaWVudF9pZCBpcyB0aGUgQ2xhaW0gVmFsdWUuXHJcbi8vXHJcbi8vIGlkX3Rva2VuIEM1OiBUaGUgQ2xpZW50IE1VU1QgdmFsaWRhdGUgdGhlIHNpZ25hdHVyZSBvZiB0aGUgSUQgVG9rZW4gYWNjb3JkaW5nIHRvIEpXUyBbSldTXSB1c2luZyB0aGUgYWxnb3JpdGhtIHNwZWNpZmllZCBpbiB0aGVcclxuLy8gYWxnIEhlYWRlciBQYXJhbWV0ZXIgb2YgdGhlIEpPU0UgSGVhZGVyLlRoZSBDbGllbnQgTVVTVCB1c2UgdGhlIGtleXMgcHJvdmlkZWQgYnkgdGhlIElzc3Vlci5cclxuLy9cclxuLy8gaWRfdG9rZW4gQzY6IFRoZSBhbGcgdmFsdWUgU0hPVUxEIGJlIFJTMjU2LiBWYWxpZGF0aW9uIG9mIHRva2VucyB1c2luZyBvdGhlciBzaWduaW5nIGFsZ29yaXRobXMgaXMgZGVzY3JpYmVkIGluIHRoZSBPcGVuSUQgQ29ubmVjdCBDb3JlIDEuMFxyXG4vLyBbT3BlbklELkNvcmVdIHNwZWNpZmljYXRpb24uXHJcbi8vXHJcbi8vIGlkX3Rva2VuIEM3OiBUaGUgY3VycmVudCB0aW1lIE1VU1QgYmUgYmVmb3JlIHRoZSB0aW1lIHJlcHJlc2VudGVkIGJ5IHRoZSBleHAgQ2xhaW0gKHBvc3NpYmx5IGFsbG93aW5nIGZvciBzb21lIHNtYWxsIGxlZXdheSB0byBhY2NvdW50XHJcbi8vIGZvciBjbG9jayBza2V3KS5cclxuLy9cclxuLy8gaWRfdG9rZW4gQzg6IFRoZSBpYXQgQ2xhaW0gY2FuIGJlIHVzZWQgdG8gcmVqZWN0IHRva2VucyB0aGF0IHdlcmUgaXNzdWVkIHRvbyBmYXIgYXdheSBmcm9tIHRoZSBjdXJyZW50IHRpbWUsXHJcbi8vIGxpbWl0aW5nIHRoZSBhbW91bnQgb2YgdGltZSB0aGF0IG5vbmNlcyBuZWVkIHRvIGJlIHN0b3JlZCB0byBwcmV2ZW50IGF0dGFja3MuVGhlIGFjY2VwdGFibGUgcmFuZ2UgaXMgQ2xpZW50IHNwZWNpZmljLlxyXG4vL1xyXG4vLyBpZF90b2tlbiBDOTogVGhlIHZhbHVlIG9mIHRoZSBub25jZSBDbGFpbSBNVVNUIGJlIGNoZWNrZWQgdG8gdmVyaWZ5IHRoYXQgaXQgaXMgdGhlIHNhbWUgdmFsdWUgYXMgdGhlIG9uZSB0aGF0IHdhcyBzZW50XHJcbi8vIGluIHRoZSBBdXRoZW50aWNhdGlvbiBSZXF1ZXN0LlRoZSBDbGllbnQgU0hPVUxEIGNoZWNrIHRoZSBub25jZSB2YWx1ZSBmb3IgcmVwbGF5IGF0dGFja3MuVGhlIHByZWNpc2UgbWV0aG9kIGZvciBkZXRlY3RpbmcgcmVwbGF5IGF0dGFja3NcclxuLy8gaXMgQ2xpZW50IHNwZWNpZmljLlxyXG4vL1xyXG4vLyBpZF90b2tlbiBDMTA6IElmIHRoZSBhY3IgQ2xhaW0gd2FzIHJlcXVlc3RlZCwgdGhlIENsaWVudCBTSE9VTEQgY2hlY2sgdGhhdCB0aGUgYXNzZXJ0ZWQgQ2xhaW0gVmFsdWUgaXMgYXBwcm9wcmlhdGUuXHJcbi8vIFRoZSBtZWFuaW5nIGFuZCBwcm9jZXNzaW5nIG9mIGFjciBDbGFpbSBWYWx1ZXMgaXMgb3V0IG9mIHNjb3BlIGZvciB0aGlzIGRvY3VtZW50LlxyXG4vL1xyXG4vLyBpZF90b2tlbiBDMTE6IFdoZW4gYSBtYXhfYWdlIHJlcXVlc3QgaXMgbWFkZSwgdGhlIENsaWVudCBTSE9VTEQgY2hlY2sgdGhlIGF1dGhfdGltZSBDbGFpbSB2YWx1ZSBhbmQgcmVxdWVzdCByZS0gYXV0aGVudGljYXRpb25cclxuLy8gaWYgaXQgZGV0ZXJtaW5lcyB0b28gbXVjaCB0aW1lIGhhcyBlbGFwc2VkIHNpbmNlIHRoZSBsYXN0IEVuZC0gVXNlciBhdXRoZW50aWNhdGlvbi5cclxuXHJcbi8vIEFjY2VzcyBUb2tlbiBWYWxpZGF0aW9uXHJcbi8vIGFjY2Vzc190b2tlbiBDMTogSGFzaCB0aGUgb2N0ZXRzIG9mIHRoZSBBU0NJSSByZXByZXNlbnRhdGlvbiBvZiB0aGUgYWNjZXNzX3Rva2VuIHdpdGggdGhlIGhhc2ggYWxnb3JpdGhtIHNwZWNpZmllZCBpbiBKV0FbSldBXVxyXG4vLyBmb3IgdGhlIGFsZyBIZWFkZXIgUGFyYW1ldGVyIG9mIHRoZSBJRCBUb2tlbidzIEpPU0UgSGVhZGVyLiBGb3IgaW5zdGFuY2UsIGlmIHRoZSBhbGcgaXMgUlMyNTYsIHRoZSBoYXNoIGFsZ29yaXRobSB1c2VkIGlzIFNIQS0yNTYuXHJcbi8vIGFjY2Vzc190b2tlbiBDMjogVGFrZSB0aGUgbGVmdC0gbW9zdCBoYWxmIG9mIHRoZSBoYXNoIGFuZCBiYXNlNjR1cmwtIGVuY29kZSBpdC5cclxuLy8gYWNjZXNzX3Rva2VuIEMzOiBUaGUgdmFsdWUgb2YgYXRfaGFzaCBpbiB0aGUgSUQgVG9rZW4gTVVTVCBtYXRjaCB0aGUgdmFsdWUgcHJvZHVjZWQgaW4gdGhlIHByZXZpb3VzIHN0ZXAgaWYgYXRfaGFzaCBpcyBwcmVzZW50IGluIHRoZSBJRCBUb2tlbi5cclxuXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGNsYXNzIE9pZGNTZWN1cml0eVZhbGlkYXRpb24ge1xyXG4gICAgY29uc3RydWN0b3IoXHJcbiAgICAgICAgcHJpdmF0ZSBhcnJheUhlbHBlclNlcnZpY2U6IEVxdWFsaXR5SGVscGVyU2VydmljZSxcclxuICAgICAgICBwcml2YXRlIHRva2VuSGVscGVyU2VydmljZTogVG9rZW5IZWxwZXJTZXJ2aWNlLFxyXG4gICAgICAgIHByaXZhdGUgbG9nZ2VyU2VydmljZTogTG9nZ2VyU2VydmljZVxyXG4gICAgKSB7fVxyXG5cclxuICAgIC8vIGlkX3Rva2VuIEM3OiBUaGUgY3VycmVudCB0aW1lIE1VU1QgYmUgYmVmb3JlIHRoZSB0aW1lIHJlcHJlc2VudGVkIGJ5IHRoZSBleHAgQ2xhaW0gKHBvc3NpYmx5IGFsbG93aW5nIGZvciBzb21lIHNtYWxsIGxlZXdheSB0byBhY2NvdW50IGZvciBjbG9jayBza2V3KS5cclxuICAgIGlzVG9rZW5FeHBpcmVkKHRva2VuOiBzdHJpbmcsIG9mZnNldFNlY29uZHM/OiBudW1iZXIpOiBib29sZWFuIHtcclxuICAgICAgICBsZXQgZGVjb2RlZDogYW55O1xyXG4gICAgICAgIGRlY29kZWQgPSB0aGlzLnRva2VuSGVscGVyU2VydmljZS5nZXRQYXlsb2FkRnJvbVRva2VuKHRva2VuLCBmYWxzZSk7XHJcblxyXG4gICAgICAgIHJldHVybiAhdGhpcy52YWxpZGF0ZV9pZF90b2tlbl9leHBfbm90X2V4cGlyZWQoZGVjb2RlZCwgb2Zmc2V0U2Vjb25kcyk7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gaWRfdG9rZW4gQzc6IFRoZSBjdXJyZW50IHRpbWUgTVVTVCBiZSBiZWZvcmUgdGhlIHRpbWUgcmVwcmVzZW50ZWQgYnkgdGhlIGV4cCBDbGFpbSAocG9zc2libHkgYWxsb3dpbmcgZm9yIHNvbWUgc21hbGwgbGVld2F5IHRvIGFjY291bnQgZm9yIGNsb2NrIHNrZXcpLlxyXG4gICAgdmFsaWRhdGVfaWRfdG9rZW5fZXhwX25vdF9leHBpcmVkKGRlY29kZWRfaWRfdG9rZW46IHN0cmluZywgb2Zmc2V0U2Vjb25kcz86IG51bWJlcik6IGJvb2xlYW4ge1xyXG4gICAgICAgIGNvbnN0IHRva2VuRXhwaXJhdGlvbkRhdGUgPSB0aGlzLnRva2VuSGVscGVyU2VydmljZS5nZXRUb2tlbkV4cGlyYXRpb25EYXRlKGRlY29kZWRfaWRfdG9rZW4pO1xyXG4gICAgICAgIG9mZnNldFNlY29uZHMgPSBvZmZzZXRTZWNvbmRzIHx8IDA7XHJcblxyXG4gICAgICAgIGlmICghdG9rZW5FeHBpcmF0aW9uRGF0ZSkge1xyXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCB0b2tlbkV4cGlyYXRpb25WYWx1ZSA9IHRva2VuRXhwaXJhdGlvbkRhdGUudmFsdWVPZigpO1xyXG4gICAgICAgIGNvbnN0IG5vd1dpdGhPZmZzZXQgPSBuZXcgRGF0ZSgpLnZhbHVlT2YoKSArIG9mZnNldFNlY29uZHMgKiAxMDAwO1xyXG4gICAgICAgIGNvbnN0IHRva2VuTm90RXhwaXJlZCA9IHRva2VuRXhwaXJhdGlvblZhbHVlID4gbm93V2l0aE9mZnNldDtcclxuXHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKGBUb2tlbiBub3QgZXhwaXJlZD86ICR7dG9rZW5FeHBpcmF0aW9uVmFsdWV9ID4gJHtub3dXaXRoT2Zmc2V0fSAgKCR7dG9rZW5Ob3RFeHBpcmVkfSlgKTtcclxuXHJcbiAgICAgICAgLy8gVG9rZW4gbm90IGV4cGlyZWQ/XHJcbiAgICAgICAgcmV0dXJuIHRva2VuTm90RXhwaXJlZDtcclxuICAgIH1cclxuXHJcbiAgICAvLyBpc3NcclxuICAgIC8vIFJFUVVJUkVELiBJc3N1ZXIgSWRlbnRpZmllciBmb3IgdGhlIElzc3VlciBvZiB0aGUgcmVzcG9uc2UuVGhlIGlzcyB2YWx1ZSBpcyBhIGNhc2Utc2Vuc2l0aXZlIFVSTCB1c2luZyB0aGUgaHR0cHMgc2NoZW1lIHRoYXQgY29udGFpbnMgc2NoZW1lLCBob3N0LFxyXG4gICAgLy8gYW5kIG9wdGlvbmFsbHksIHBvcnQgbnVtYmVyIGFuZCBwYXRoIGNvbXBvbmVudHMgYW5kIG5vIHF1ZXJ5IG9yIGZyYWdtZW50IGNvbXBvbmVudHMuXHJcbiAgICAvL1xyXG4gICAgLy8gc3ViXHJcbiAgICAvLyBSRVFVSVJFRC4gU3ViamVjdCBJZGVudGlmaWVyLkxvY2FsbHkgdW5pcXVlIGFuZCBuZXZlciByZWFzc2lnbmVkIGlkZW50aWZpZXIgd2l0aGluIHRoZSBJc3N1ZXIgZm9yIHRoZSBFbmQtIFVzZXIsXHJcbiAgICAvLyB3aGljaCBpcyBpbnRlbmRlZCB0byBiZSBjb25zdW1lZCBieSB0aGUgQ2xpZW50LCBlLmcuLCAyNDQwMDMyMCBvciBBSXRPYXdtd3RXd2NUMGs1MUJheWV3TnZ1dHJKVXFzdmw2cXM3QTQuXHJcbiAgICAvLyBJdCBNVVNUIE5PVCBleGNlZWQgMjU1IEFTQ0lJIGNoYXJhY3RlcnMgaW4gbGVuZ3RoLlRoZSBzdWIgdmFsdWUgaXMgYSBjYXNlLXNlbnNpdGl2ZSBzdHJpbmcuXHJcbiAgICAvL1xyXG4gICAgLy8gYXVkXHJcbiAgICAvLyBSRVFVSVJFRC4gQXVkaWVuY2UocykgdGhhdCB0aGlzIElEIFRva2VuIGlzIGludGVuZGVkIGZvci4gSXQgTVVTVCBjb250YWluIHRoZSBPQXV0aCAyLjAgY2xpZW50X2lkIG9mIHRoZSBSZWx5aW5nIFBhcnR5IGFzIGFuIGF1ZGllbmNlIHZhbHVlLlxyXG4gICAgLy8gSXQgTUFZIGFsc28gY29udGFpbiBpZGVudGlmaWVycyBmb3Igb3RoZXIgYXVkaWVuY2VzLkluIHRoZSBnZW5lcmFsIGNhc2UsIHRoZSBhdWQgdmFsdWUgaXMgYW4gYXJyYXkgb2YgY2FzZS1zZW5zaXRpdmUgc3RyaW5ncy5cclxuICAgIC8vIEluIHRoZSBjb21tb24gc3BlY2lhbCBjYXNlIHdoZW4gdGhlcmUgaXMgb25lIGF1ZGllbmNlLCB0aGUgYXVkIHZhbHVlIE1BWSBiZSBhIHNpbmdsZSBjYXNlLXNlbnNpdGl2ZSBzdHJpbmcuXHJcbiAgICAvL1xyXG4gICAgLy8gZXhwXHJcbiAgICAvLyBSRVFVSVJFRC4gRXhwaXJhdGlvbiB0aW1lIG9uIG9yIGFmdGVyIHdoaWNoIHRoZSBJRCBUb2tlbiBNVVNUIE5PVCBiZSBhY2NlcHRlZCBmb3IgcHJvY2Vzc2luZy5cclxuICAgIC8vIFRoZSBwcm9jZXNzaW5nIG9mIHRoaXMgcGFyYW1ldGVyIHJlcXVpcmVzIHRoYXQgdGhlIGN1cnJlbnQgZGF0ZS8gdGltZSBNVVNUIGJlIGJlZm9yZSB0aGUgZXhwaXJhdGlvbiBkYXRlLyB0aW1lIGxpc3RlZCBpbiB0aGUgdmFsdWUuXHJcbiAgICAvLyBJbXBsZW1lbnRlcnMgTUFZIHByb3ZpZGUgZm9yIHNvbWUgc21hbGwgbGVld2F5LCB1c3VhbGx5IG5vIG1vcmUgdGhhbiBhIGZldyBtaW51dGVzLCB0byBhY2NvdW50IGZvciBjbG9jayBza2V3LlxyXG4gICAgLy8gSXRzIHZhbHVlIGlzIGEgSlNPTiBbUkZDNzE1OV0gbnVtYmVyIHJlcHJlc2VudGluZyB0aGUgbnVtYmVyIG9mIHNlY29uZHMgZnJvbSAxOTcwLSAwMSAtIDAxVDAwOiAwMDowMFogYXMgbWVhc3VyZWQgaW4gVVRDIHVudGlsIHRoZSBkYXRlLyB0aW1lLlxyXG4gICAgLy8gU2VlIFJGQyAzMzM5IFtSRkMzMzM5XSBmb3IgZGV0YWlscyByZWdhcmRpbmcgZGF0ZS8gdGltZXMgaW4gZ2VuZXJhbCBhbmQgVVRDIGluIHBhcnRpY3VsYXIuXHJcbiAgICAvL1xyXG4gICAgLy8gaWF0XHJcbiAgICAvLyBSRVFVSVJFRC4gVGltZSBhdCB3aGljaCB0aGUgSldUIHdhcyBpc3N1ZWQuIEl0cyB2YWx1ZSBpcyBhIEpTT04gbnVtYmVyIHJlcHJlc2VudGluZyB0aGUgbnVtYmVyIG9mIHNlY29uZHMgZnJvbSAxOTcwLSAwMSAtIDAxVDAwOiAwMDowMFogYXMgbWVhc3VyZWRcclxuICAgIC8vIGluIFVUQyB1bnRpbCB0aGUgZGF0ZS8gdGltZS5cclxuICAgIHZhbGlkYXRlX3JlcXVpcmVkX2lkX3Rva2VuKGRhdGFJZFRva2VuOiBhbnkpOiBib29sZWFuIHtcclxuICAgICAgICBsZXQgdmFsaWRhdGVkID0gdHJ1ZTtcclxuICAgICAgICBpZiAoIWRhdGFJZFRva2VuLmhhc093blByb3BlcnR5KCdpc3MnKSkge1xyXG4gICAgICAgICAgICB2YWxpZGF0ZWQgPSBmYWxzZTtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2lzcyBpcyBtaXNzaW5nLCB0aGlzIGlzIHJlcXVpcmVkIGluIHRoZSBpZF90b2tlbicpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKCFkYXRhSWRUb2tlbi5oYXNPd25Qcm9wZXJ0eSgnc3ViJykpIHtcclxuICAgICAgICAgICAgdmFsaWRhdGVkID0gZmFsc2U7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdzdWIgaXMgbWlzc2luZywgdGhpcyBpcyByZXF1aXJlZCBpbiB0aGUgaWRfdG9rZW4nKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmICghZGF0YUlkVG9rZW4uaGFzT3duUHJvcGVydHkoJ2F1ZCcpKSB7XHJcbiAgICAgICAgICAgIHZhbGlkYXRlZCA9IGZhbHNlO1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnYXVkIGlzIG1pc3NpbmcsIHRoaXMgaXMgcmVxdWlyZWQgaW4gdGhlIGlkX3Rva2VuJyk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoIWRhdGFJZFRva2VuLmhhc093blByb3BlcnR5KCdleHAnKSkge1xyXG4gICAgICAgICAgICB2YWxpZGF0ZWQgPSBmYWxzZTtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2V4cCBpcyBtaXNzaW5nLCB0aGlzIGlzIHJlcXVpcmVkIGluIHRoZSBpZF90b2tlbicpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKCFkYXRhSWRUb2tlbi5oYXNPd25Qcm9wZXJ0eSgnaWF0JykpIHtcclxuICAgICAgICAgICAgdmFsaWRhdGVkID0gZmFsc2U7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdpYXQgaXMgbWlzc2luZywgdGhpcyBpcyByZXF1aXJlZCBpbiB0aGUgaWRfdG9rZW4nKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB2YWxpZGF0ZWQ7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gaWRfdG9rZW4gQzg6IFRoZSBpYXQgQ2xhaW0gY2FuIGJlIHVzZWQgdG8gcmVqZWN0IHRva2VucyB0aGF0IHdlcmUgaXNzdWVkIHRvbyBmYXIgYXdheSBmcm9tIHRoZSBjdXJyZW50IHRpbWUsXHJcbiAgICAvLyBsaW1pdGluZyB0aGUgYW1vdW50IG9mIHRpbWUgdGhhdCBub25jZXMgbmVlZCB0byBiZSBzdG9yZWQgdG8gcHJldmVudCBhdHRhY2tzLlRoZSBhY2NlcHRhYmxlIHJhbmdlIGlzIENsaWVudCBzcGVjaWZpYy5cclxuICAgIHZhbGlkYXRlX2lkX3Rva2VuX2lhdF9tYXhfb2Zmc2V0KGRhdGFJZFRva2VuOiBhbnksXHJcbiAgICAgICAgbWF4X29mZnNldF9hbGxvd2VkX2luX3NlY29uZHM6IG51bWJlcixcclxuICAgICAgICBkaXNhYmxlX2lhdF9vZmZzZXRfdmFsaWRhdGlvbjogYm9vbGVhbik6IGJvb2xlYW4ge1xyXG5cclxuICAgICAgICBpZiAoZGlzYWJsZV9pYXRfb2Zmc2V0X3ZhbGlkYXRpb24pIHtcclxuICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoIWRhdGFJZFRva2VuLmhhc093blByb3BlcnR5KCdpYXQnKSkge1xyXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBkYXRlVGltZV9pYXRfaWRfdG9rZW4gPSBuZXcgRGF0ZSgwKTsgLy8gVGhlIDAgaGVyZSBpcyB0aGUga2V5LCB3aGljaCBzZXRzIHRoZSBkYXRlIHRvIHRoZSBlcG9jaFxyXG4gICAgICAgIGRhdGVUaW1lX2lhdF9pZF90b2tlbi5zZXRVVENTZWNvbmRzKGRhdGFJZFRva2VuLmlhdCk7XHJcblxyXG4gICAgICAgIG1heF9vZmZzZXRfYWxsb3dlZF9pbl9zZWNvbmRzID0gbWF4X29mZnNldF9hbGxvd2VkX2luX3NlY29uZHMgfHwgMDtcclxuXHJcbiAgICAgICAgaWYgKGRhdGVUaW1lX2lhdF9pZF90b2tlbiA9PSBudWxsKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZyhcclxuICAgICAgICAgICAgJ3ZhbGlkYXRlX2lkX3Rva2VuX2lhdF9tYXhfb2Zmc2V0OiAnICtcclxuICAgICAgICAgICAgICAgIChuZXcgRGF0ZSgpLnZhbHVlT2YoKSAtIGRhdGVUaW1lX2lhdF9pZF90b2tlbi52YWx1ZU9mKCkpICtcclxuICAgICAgICAgICAgICAgICcgPCAnICtcclxuICAgICAgICAgICAgICAgIG1heF9vZmZzZXRfYWxsb3dlZF9pbl9zZWNvbmRzICogMTAwMFxyXG4gICAgICAgICk7XHJcbiAgICAgICAgcmV0dXJuIG5ldyBEYXRlKCkudmFsdWVPZigpIC0gZGF0ZVRpbWVfaWF0X2lkX3Rva2VuLnZhbHVlT2YoKSA8IG1heF9vZmZzZXRfYWxsb3dlZF9pbl9zZWNvbmRzICogMTAwMDtcclxuICAgIH1cclxuXHJcbiAgICAvLyBpZF90b2tlbiBDOTogVGhlIHZhbHVlIG9mIHRoZSBub25jZSBDbGFpbSBNVVNUIGJlIGNoZWNrZWQgdG8gdmVyaWZ5IHRoYXQgaXQgaXMgdGhlIHNhbWUgdmFsdWUgYXMgdGhlIG9uZVxyXG4gICAgLy8gdGhhdCB3YXMgc2VudCBpbiB0aGUgQXV0aGVudGljYXRpb24gUmVxdWVzdC5UaGUgQ2xpZW50IFNIT1VMRCBjaGVjayB0aGUgbm9uY2UgdmFsdWUgZm9yIHJlcGxheSBhdHRhY2tzLlxyXG4gICAgLy8gVGhlIHByZWNpc2UgbWV0aG9kIGZvciBkZXRlY3RpbmcgcmVwbGF5IGF0dGFja3MgaXMgQ2xpZW50IHNwZWNpZmljLlxyXG4gICAgdmFsaWRhdGVfaWRfdG9rZW5fbm9uY2UoZGF0YUlkVG9rZW46IGFueSwgbG9jYWxfbm9uY2U6IGFueSk6IGJvb2xlYW4ge1xyXG4gICAgICAgIGlmIChkYXRhSWRUb2tlbi5ub25jZSAhPT0gbG9jYWxfbm9uY2UpIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdWYWxpZGF0ZV9pZF90b2tlbl9ub25jZSBmYWlsZWQsIGRhdGFJZFRva2VuLm5vbmNlOiAnICsgZGF0YUlkVG9rZW4ubm9uY2UgKyAnIGxvY2FsX25vbmNlOicgKyBsb2NhbF9ub25jZSk7XHJcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIGlkX3Rva2VuIEMxOiBUaGUgSXNzdWVyIElkZW50aWZpZXIgZm9yIHRoZSBPcGVuSUQgUHJvdmlkZXIgKHdoaWNoIGlzIHR5cGljYWxseSBvYnRhaW5lZCBkdXJpbmcgRGlzY292ZXJ5KVxyXG4gICAgLy8gTVVTVCBleGFjdGx5IG1hdGNoIHRoZSB2YWx1ZSBvZiB0aGUgaXNzIChpc3N1ZXIpIENsYWltLlxyXG4gICAgdmFsaWRhdGVfaWRfdG9rZW5faXNzKGRhdGFJZFRva2VuOiBhbnksIGF1dGhXZWxsS25vd25FbmRwb2ludHNfaXNzdWVyOiBhbnkpOiBib29sZWFuIHtcclxuICAgICAgICBpZiAoKGRhdGFJZFRva2VuLmlzcyBhcyBzdHJpbmcpICE9PSAoYXV0aFdlbGxLbm93bkVuZHBvaW50c19pc3N1ZXIgYXMgc3RyaW5nKSkge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoXHJcbiAgICAgICAgICAgICAgICAnVmFsaWRhdGVfaWRfdG9rZW5faXNzIGZhaWxlZCwgZGF0YUlkVG9rZW4uaXNzOiAnICtcclxuICAgICAgICAgICAgICAgICAgICBkYXRhSWRUb2tlbi5pc3MgK1xyXG4gICAgICAgICAgICAgICAgICAgICcgYXV0aFdlbGxLbm93bkVuZHBvaW50cyBpc3N1ZXI6JyArXHJcbiAgICAgICAgICAgICAgICAgICAgYXV0aFdlbGxLbm93bkVuZHBvaW50c19pc3N1ZXJcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gaWRfdG9rZW4gQzI6IFRoZSBDbGllbnQgTVVTVCB2YWxpZGF0ZSB0aGF0IHRoZSBhdWQgKGF1ZGllbmNlKSBDbGFpbSBjb250YWlucyBpdHMgY2xpZW50X2lkIHZhbHVlIHJlZ2lzdGVyZWQgYXQgdGhlIElzc3VlciBpZGVudGlmaWVkXHJcbiAgICAvLyBieSB0aGUgaXNzIChpc3N1ZXIpIENsYWltIGFzIGFuIGF1ZGllbmNlLlxyXG4gICAgLy8gVGhlIElEIFRva2VuIE1VU1QgYmUgcmVqZWN0ZWQgaWYgdGhlIElEIFRva2VuIGRvZXMgbm90IGxpc3QgdGhlIENsaWVudCBhcyBhIHZhbGlkIGF1ZGllbmNlLCBvciBpZiBpdCBjb250YWlucyBhZGRpdGlvbmFsIGF1ZGllbmNlc1xyXG4gICAgLy8gbm90IHRydXN0ZWQgYnkgdGhlIENsaWVudC5cclxuICAgIHZhbGlkYXRlX2lkX3Rva2VuX2F1ZChkYXRhSWRUb2tlbjogYW55LCBhdWQ6IGFueSk6IGJvb2xlYW4ge1xyXG4gICAgICAgIGlmIChkYXRhSWRUb2tlbi5hdWQgaW5zdGFuY2VvZiBBcnJheSkge1xyXG4gICAgICAgICAgICBjb25zdCByZXN1bHQgPSB0aGlzLmFycmF5SGVscGVyU2VydmljZS5hcmVFcXVhbChkYXRhSWRUb2tlbi5hdWQsIGF1ZCk7XHJcblxyXG4gICAgICAgICAgICBpZiAoIXJlc3VsdCkge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdWYWxpZGF0ZV9pZF90b2tlbl9hdWQgIGFycmF5IGZhaWxlZCwgZGF0YUlkVG9rZW4uYXVkOiAnICsgZGF0YUlkVG9rZW4uYXVkICsgJyBjbGllbnRfaWQ6JyArIGF1ZCk7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgIH0gZWxzZSBpZiAoZGF0YUlkVG9rZW4uYXVkICE9PSBhdWQpIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdWYWxpZGF0ZV9pZF90b2tlbl9hdWQgZmFpbGVkLCBkYXRhSWRUb2tlbi5hdWQ6ICcgKyBkYXRhSWRUb2tlbi5hdWQgKyAnIGNsaWVudF9pZDonICsgYXVkKTtcclxuXHJcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIHZhbGlkYXRlU3RhdGVGcm9tSGFzaENhbGxiYWNrKHN0YXRlOiBhbnksIGxvY2FsX3N0YXRlOiBhbnkpOiBib29sZWFuIHtcclxuICAgICAgICBpZiAoKHN0YXRlIGFzIHN0cmluZykgIT09IChsb2NhbF9zdGF0ZSBhcyBzdHJpbmcpKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnVmFsaWRhdGVTdGF0ZUZyb21IYXNoQ2FsbGJhY2sgZmFpbGVkLCBzdGF0ZTogJyArIHN0YXRlICsgJyBsb2NhbF9zdGF0ZTonICsgbG9jYWxfc3RhdGUpO1xyXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuXHJcbiAgICB2YWxpZGF0ZV91c2VyZGF0YV9zdWJfaWRfdG9rZW4oaWRfdG9rZW5fc3ViOiBhbnksIHVzZXJkYXRhX3N1YjogYW55KTogYm9vbGVhbiB7XHJcbiAgICAgICAgaWYgKChpZF90b2tlbl9zdWIgYXMgc3RyaW5nKSAhPT0gKHVzZXJkYXRhX3N1YiBhcyBzdHJpbmcpKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygndmFsaWRhdGVfdXNlcmRhdGFfc3ViX2lkX3Rva2VuIGZhaWxlZCwgaWRfdG9rZW5fc3ViOiAnICsgaWRfdG9rZW5fc3ViICsgJyB1c2VyZGF0YV9zdWI6JyArIHVzZXJkYXRhX3N1Yik7XHJcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIGlkX3Rva2VuIEM1OiBUaGUgQ2xpZW50IE1VU1QgdmFsaWRhdGUgdGhlIHNpZ25hdHVyZSBvZiB0aGUgSUQgVG9rZW4gYWNjb3JkaW5nIHRvIEpXUyBbSldTXSB1c2luZyB0aGUgYWxnb3JpdGhtIHNwZWNpZmllZCBpbiB0aGUgYWxnXHJcbiAgICAvLyBIZWFkZXIgUGFyYW1ldGVyIG9mIHRoZSBKT1NFIEhlYWRlci5UaGUgQ2xpZW50IE1VU1QgdXNlIHRoZSBrZXlzIHByb3ZpZGVkIGJ5IHRoZSBJc3N1ZXIuXHJcbiAgICAvLyBpZF90b2tlbiBDNjogVGhlIGFsZyB2YWx1ZSBTSE9VTEQgYmUgUlMyNTYuIFZhbGlkYXRpb24gb2YgdG9rZW5zIHVzaW5nIG90aGVyIHNpZ25pbmcgYWxnb3JpdGhtcyBpcyBkZXNjcmliZWQgaW4gdGhlXHJcbiAgICAvLyBPcGVuSUQgQ29ubmVjdCBDb3JlIDEuMCBbT3BlbklELkNvcmVdIHNwZWNpZmljYXRpb24uXHJcbiAgICB2YWxpZGF0ZV9zaWduYXR1cmVfaWRfdG9rZW4oaWRfdG9rZW46IGFueSwgand0a2V5czogYW55KTogYm9vbGVhbiB7XHJcbiAgICAgICAgaWYgKCFqd3RrZXlzIHx8ICFqd3RrZXlzLmtleXMpIHtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3QgaGVhZGVyX2RhdGEgPSB0aGlzLnRva2VuSGVscGVyU2VydmljZS5nZXRIZWFkZXJGcm9tVG9rZW4oaWRfdG9rZW4sIGZhbHNlKTtcclxuXHJcbiAgICAgICAgaWYgKE9iamVjdC5rZXlzKGhlYWRlcl9kYXRhKS5sZW5ndGggPT09IDAgJiYgaGVhZGVyX2RhdGEuY29uc3RydWN0b3IgPT09IE9iamVjdCkge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnaWQgdG9rZW4gaGFzIG5vIGhlYWRlciBkYXRhJyk7XHJcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IGtpZCA9IGhlYWRlcl9kYXRhLmtpZDtcclxuICAgICAgICBjb25zdCBhbGcgPSBoZWFkZXJfZGF0YS5hbGc7XHJcblxyXG4gICAgICAgIGlmICgnUlMyNTYnICE9PSAoYWxnIGFzIHN0cmluZykpIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ09ubHkgUlMyNTYgc3VwcG9ydGVkJyk7XHJcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGxldCBpc1ZhbGlkID0gZmFsc2U7XHJcblxyXG4gICAgICAgIGlmICghaGVhZGVyX2RhdGEuaGFzT3duUHJvcGVydHkoJ2tpZCcpKSB7XHJcbiAgICAgICAgICAgIC8vIGV4YWN0bHkgMSBrZXkgaW4gdGhlIGp3dGtleXMgYW5kIG5vIGtpZCBpbiB0aGUgSm9zZSBoZWFkZXJcclxuICAgICAgICAgICAgLy8ga3R5XHRcIlJTQVwiIHVzZSBcInNpZ1wiXHJcbiAgICAgICAgICAgIGxldCBhbW91bnRPZk1hdGNoaW5nS2V5cyA9IDA7XHJcbiAgICAgICAgICAgIGZvciAoY29uc3Qga2V5IG9mIGp3dGtleXMua2V5cykge1xyXG4gICAgICAgICAgICAgICAgaWYgKChrZXkua3R5IGFzIHN0cmluZykgPT09ICdSU0EnICYmIChrZXkudXNlIGFzIHN0cmluZykgPT09ICdzaWcnKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgYW1vdW50T2ZNYXRjaGluZ0tleXMgPSBhbW91bnRPZk1hdGNoaW5nS2V5cyArIDE7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIGlmIChhbW91bnRPZk1hdGNoaW5nS2V5cyA9PT0gMCkge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ25vIGtleXMgZm91bmQsIGluY29ycmVjdCBTaWduYXR1cmUsIHZhbGlkYXRpb24gZmFpbGVkIGZvciBpZF90b2tlbicpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICB9IGVsc2UgaWYgKGFtb3VudE9mTWF0Y2hpbmdLZXlzID4gMSkge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ25vIElEIFRva2VuIGtpZCBjbGFpbSBpbiBKT1NFIGhlYWRlciBhbmQgbXVsdGlwbGUgc3VwcGxpZWQgaW4gandrc191cmknKTtcclxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICAgIGZvciAoY29uc3Qga2V5IG9mIGp3dGtleXMua2V5cykge1xyXG4gICAgICAgICAgICAgICAgICAgIGlmICgoa2V5Lmt0eSBhcyBzdHJpbmcpID09PSAnUlNBJyAmJiAoa2V5LnVzZSBhcyBzdHJpbmcpID09PSAnc2lnJykge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBwdWJsaWNrZXkgPSBLRVlVVElMLmdldEtleShrZXkpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBpc1ZhbGlkID0gS0pVUi5qd3MuSldTLnZlcmlmeShpZF90b2tlbiwgcHVibGlja2V5LCBbJ1JTMjU2J10pO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWlzVmFsaWQpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdpbmNvcnJlY3QgU2lnbmF0dXJlLCB2YWxpZGF0aW9uIGZhaWxlZCBmb3IgaWRfdG9rZW4nKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gaXNWYWxpZDtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAvLyBraWQgaW4gdGhlIEpvc2UgaGVhZGVyIG9mIGlkX3Rva2VuXHJcbiAgICAgICAgICAgIGZvciAoY29uc3Qga2V5IG9mIGp3dGtleXMua2V5cykge1xyXG4gICAgICAgICAgICAgICAgaWYgKChrZXkua2lkIGFzIHN0cmluZykgPT09IChraWQgYXMgc3RyaW5nKSkge1xyXG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IHB1YmxpY2tleSA9IEtFWVVUSUwuZ2V0S2V5KGtleSk7XHJcbiAgICAgICAgICAgICAgICAgICAgaXNWYWxpZCA9IEtKVVIuandzLkpXUy52ZXJpZnkoaWRfdG9rZW4sIHB1YmxpY2tleSwgWydSUzI1NiddKTtcclxuICAgICAgICAgICAgICAgICAgICBpZiAoIWlzVmFsaWQpIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2luY29ycmVjdCBTaWduYXR1cmUsIHZhbGlkYXRpb24gZmFpbGVkIGZvciBpZF90b2tlbicpO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gaXNWYWxpZDtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIGlzVmFsaWQ7XHJcbiAgICB9XHJcblxyXG4gICAgY29uZmlnX3ZhbGlkYXRlX3Jlc3BvbnNlX3R5cGUocmVzcG9uc2VfdHlwZTogc3RyaW5nKTogYm9vbGVhbiB7XHJcbiAgICAgICAgaWYgKHJlc3BvbnNlX3R5cGUgPT09ICdpZF90b2tlbiB0b2tlbicgfHwgcmVzcG9uc2VfdHlwZSA9PT0gJ2lkX3Rva2VuJykge1xyXG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmIChyZXNwb25zZV90eXBlID09PSAnY29kZScpIHtcclxuICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnbW9kdWxlIGNvbmZpZ3VyZSBpbmNvcnJlY3QsIGludmFsaWQgcmVzcG9uc2VfdHlwZTonICsgcmVzcG9uc2VfdHlwZSk7XHJcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIEFjY2VwdHMgSUQgVG9rZW4gd2l0aG91dCAna2lkJyBjbGFpbSBpbiBKT1NFIGhlYWRlciBpZiBvbmx5IG9uZSBKV0sgc3VwcGxpZWQgaW4gJ2p3a3NfdXJsJ1xyXG4gICAgLy8vLyBwcml2YXRlIHZhbGlkYXRlX25vX2tpZF9pbl9oZWFkZXJfb25seV9vbmVfYWxsb3dlZF9pbl9qd3RrZXlzKGhlYWRlcl9kYXRhOiBhbnksIGp3dGtleXM6IGFueSk6IGJvb2xlYW4ge1xyXG4gICAgLy8vLyAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5sb2dEZWJ1ZygnYW1vdW50IG9mIGp3dGtleXMua2V5czogJyArIGp3dGtleXMua2V5cy5sZW5ndGgpO1xyXG4gICAgLy8vLyAgICBpZiAoIWhlYWRlcl9kYXRhLmhhc093blByb3BlcnR5KCdraWQnKSkge1xyXG4gICAgLy8vLyAgICAgICAgLy8gbm8ga2lkIGRlZmluZWQgaW4gSm9zZSBoZWFkZXJcclxuICAgIC8vLy8gICAgICAgIGlmIChqd3RrZXlzLmtleXMubGVuZ3RoICE9IDEpIHtcclxuICAgIC8vLy8gICAgICAgICAgICB0aGlzLm9pZGNTZWN1cml0eUNvbW1vbi5sb2dEZWJ1Zygnand0a2V5cy5rZXlzLmxlbmd0aCAhPSAxIGFuZCBubyBraWQgaW4gaGVhZGVyJyk7XHJcbiAgICAvLy8vICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgLy8vLyAgICAgICAgfVxyXG4gICAgLy8vLyAgICB9XHJcblxyXG4gICAgLy8vLyAgICByZXR1cm4gdHJ1ZTtcclxuICAgIC8vLy8gfVxyXG5cclxuICAgIC8vIEFjY2VzcyBUb2tlbiBWYWxpZGF0aW9uXHJcbiAgICAvLyBhY2Nlc3NfdG9rZW4gQzE6IEhhc2ggdGhlIG9jdGV0cyBvZiB0aGUgQVNDSUkgcmVwcmVzZW50YXRpb24gb2YgdGhlIGFjY2Vzc190b2tlbiB3aXRoIHRoZSBoYXNoIGFsZ29yaXRobSBzcGVjaWZpZWQgaW4gSldBW0pXQV1cclxuICAgIC8vIGZvciB0aGUgYWxnIEhlYWRlciBQYXJhbWV0ZXIgb2YgdGhlIElEIFRva2VuJ3MgSk9TRSBIZWFkZXIuIEZvciBpbnN0YW5jZSwgaWYgdGhlIGFsZyBpcyBSUzI1NiwgdGhlIGhhc2ggYWxnb3JpdGhtIHVzZWQgaXMgU0hBLTI1Ni5cclxuICAgIC8vIGFjY2Vzc190b2tlbiBDMjogVGFrZSB0aGUgbGVmdC0gbW9zdCBoYWxmIG9mIHRoZSBoYXNoIGFuZCBiYXNlNjR1cmwtIGVuY29kZSBpdC5cclxuICAgIC8vIGFjY2Vzc190b2tlbiBDMzogVGhlIHZhbHVlIG9mIGF0X2hhc2ggaW4gdGhlIElEIFRva2VuIE1VU1QgbWF0Y2ggdGhlIHZhbHVlIHByb2R1Y2VkIGluIHRoZSBwcmV2aW91cyBzdGVwIGlmIGF0X2hhc2hcclxuICAgIC8vIGlzIHByZXNlbnQgaW4gdGhlIElEIFRva2VuLlxyXG4gICAgdmFsaWRhdGVfaWRfdG9rZW5fYXRfaGFzaChhY2Nlc3NfdG9rZW46IGFueSwgYXRfaGFzaDogYW55LCBpc0NvZGVGbG93OiBib29sZWFuKTogYm9vbGVhbiB7XHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdhdF9oYXNoIGZyb20gdGhlIHNlcnZlcjonICsgYXRfaGFzaCk7XHJcblxyXG4gICAgICAgIC8vIFRoZSBhdF9oYXNoIGlzIG9wdGlvbmFsIGZvciB0aGUgY29kZSBmbG93XHJcbiAgICAgICAgaWYgKGlzQ29kZUZsb3cpIHtcclxuICAgICAgICAgICAgaWYgKCEoYXRfaGFzaCBhcyBzdHJpbmcpKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ0NvZGUgRmxvdyBhY3RpdmUsIGFuZCBubyBhdF9oYXNoIGluIHRoZSBpZF90b2tlbiwgc2tpcHBpbmcgY2hlY2shJyk7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3QgdGVzdGRhdGEgPSB0aGlzLmdlbmVyYXRlX2F0X2hhc2goJycgKyBhY2Nlc3NfdG9rZW4pO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnYXRfaGFzaCBjbGllbnQgdmFsaWRhdGlvbiBub3QgZGVjb2RlZDonICsgdGVzdGRhdGEpO1xyXG4gICAgICAgIGlmICh0ZXN0ZGF0YSA9PT0gKGF0X2hhc2ggYXMgc3RyaW5nKSkge1xyXG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTsgLy8gaXNWYWxpZDtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICBjb25zdCB0ZXN0VmFsdWUgPSB0aGlzLmdlbmVyYXRlX2F0X2hhc2goJycgKyBkZWNvZGVVUklDb21wb25lbnQoYWNjZXNzX3Rva2VuKSk7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnLWdlbiBhY2Nlc3MtLScgKyB0ZXN0VmFsdWUpO1xyXG4gICAgICAgICAgICBpZiAodGVzdFZhbHVlID09PSAoYXRfaGFzaCBhcyBzdHJpbmcpKSB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTsgLy8gaXNWYWxpZFxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcblxyXG4gICAgcHJpdmF0ZSBnZW5lcmF0ZV9hdF9oYXNoKGFjY2Vzc190b2tlbjogYW55KTogc3RyaW5nIHtcclxuICAgICAgICBjb25zdCBoYXNoID0gS0pVUi5jcnlwdG8uVXRpbC5oYXNoU3RyaW5nKGFjY2Vzc190b2tlbiwgJ3NoYTI1NicpO1xyXG4gICAgICAgIGNvbnN0IGZpcnN0MTI4Yml0cyA9IGhhc2guc3Vic3RyKDAsIGhhc2gubGVuZ3RoIC8gMik7XHJcbiAgICAgICAgY29uc3QgdGVzdGRhdGEgPSBoZXh0b2I2NHUoZmlyc3QxMjhiaXRzKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIHRlc3RkYXRhO1xyXG4gICAgfVxyXG5cclxuICAgIGdlbmVyYXRlX2NvZGVfdmVyaWZpZXIoY29kZV9jaGFsbGVuZ2U6IGFueSk6IHN0cmluZyB7XHJcbiAgICAgICAgY29uc3QgaGFzaCA9IEtKVVIuY3J5cHRvLlV0aWwuaGFzaFN0cmluZyhjb2RlX2NoYWxsZW5nZSwgJ3NoYTI1NicpO1xyXG4gICAgICAgIGNvbnN0IHRlc3RkYXRhID0gaGV4dG9iNjR1KGhhc2gpO1xyXG5cclxuICAgICAgICByZXR1cm4gdGVzdGRhdGE7XHJcbiAgICB9XHJcbn1cclxuIl19