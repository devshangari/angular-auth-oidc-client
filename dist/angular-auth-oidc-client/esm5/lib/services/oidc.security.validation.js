/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import * as tslib_1 from "tslib";
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
var OidcSecurityValidation = /** @class */ (function () {
    function OidcSecurityValidation(arrayHelperService, tokenHelperService, loggerService) {
        this.arrayHelperService = arrayHelperService;
        this.tokenHelperService = tokenHelperService;
        this.loggerService = loggerService;
    }
    // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
    // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
    /**
     * @param {?} token
     * @param {?=} offsetSeconds
     * @return {?}
     */
    OidcSecurityValidation.prototype.isTokenExpired = 
    // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
    /**
     * @param {?} token
     * @param {?=} offsetSeconds
     * @return {?}
     */
    function (token, offsetSeconds) {
        /** @type {?} */
        var decoded;
        decoded = this.tokenHelperService.getPayloadFromToken(token, false);
        return !this.validate_id_token_exp_not_expired(decoded, offsetSeconds);
    };
    // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
    // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
    /**
     * @param {?} decoded_id_token
     * @param {?=} offsetSeconds
     * @return {?}
     */
    OidcSecurityValidation.prototype.validate_id_token_exp_not_expired = 
    // id_token C7: The current time MUST be before the time represented by the exp Claim (possibly allowing for some small leeway to account for clock skew).
    /**
     * @param {?} decoded_id_token
     * @param {?=} offsetSeconds
     * @return {?}
     */
    function (decoded_id_token, offsetSeconds) {
        /** @type {?} */
        var tokenExpirationDate = this.tokenHelperService.getTokenExpirationDate(decoded_id_token);
        offsetSeconds = offsetSeconds || 0;
        if (!tokenExpirationDate) {
            return false;
        }
        /** @type {?} */
        var tokenExpirationValue = tokenExpirationDate.valueOf();
        /** @type {?} */
        var nowWithOffset = new Date().valueOf() + offsetSeconds * 1000;
        /** @type {?} */
        var tokenNotExpired = tokenExpirationValue > nowWithOffset;
        this.loggerService.logDebug("Token not expired?: " + tokenExpirationValue + " > " + nowWithOffset + "  (" + tokenNotExpired + ")");
        // Token not expired?
        return tokenNotExpired;
    };
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
    OidcSecurityValidation.prototype.validate_required_id_token = 
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
    function (dataIdToken) {
        /** @type {?} */
        var validated = true;
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
    };
    // id_token C8: The iat Claim can be used to reject tokens that were issued too far away from the current time,
    // limiting the amount of time that nonces need to be stored to prevent attacks.The acceptable range is Client specific.
    // id_token C8: The iat Claim can be used to reject tokens that were issued too far away from the current time,
    // limiting the amount of time that nonces need to be stored to prevent attacks.The acceptable range is Client specific.
    /**
     * @param {?} dataIdToken
     * @param {?} max_offset_allowed_in_seconds
     * @param {?} disable_iat_offset_validation
     * @return {?}
     */
    OidcSecurityValidation.prototype.validate_id_token_iat_max_offset = 
    // id_token C8: The iat Claim can be used to reject tokens that were issued too far away from the current time,
    // limiting the amount of time that nonces need to be stored to prevent attacks.The acceptable range is Client specific.
    /**
     * @param {?} dataIdToken
     * @param {?} max_offset_allowed_in_seconds
     * @param {?} disable_iat_offset_validation
     * @return {?}
     */
    function (dataIdToken, max_offset_allowed_in_seconds, disable_iat_offset_validation) {
        if (disable_iat_offset_validation) {
            return true;
        }
        if (!dataIdToken.hasOwnProperty('iat')) {
            return false;
        }
        /** @type {?} */
        var dateTime_iat_id_token = new Date(0);
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
    };
    // id_token C9: The value of the nonce Claim MUST be checked to verify that it is the same value as the one
    // that was sent in the Authentication Request.The Client SHOULD check the nonce value for replay attacks.
    // The precise method for detecting replay attacks is Client specific.
    // id_token C9: The value of the nonce Claim MUST be checked to verify that it is the same value as the one
    // that was sent in the Authentication Request.The Client SHOULD check the nonce value for replay attacks.
    // The precise method for detecting replay attacks is Client specific.
    /**
     * @param {?} dataIdToken
     * @param {?} local_nonce
     * @return {?}
     */
    OidcSecurityValidation.prototype.validate_id_token_nonce = 
    // id_token C9: The value of the nonce Claim MUST be checked to verify that it is the same value as the one
    // that was sent in the Authentication Request.The Client SHOULD check the nonce value for replay attacks.
    // The precise method for detecting replay attacks is Client specific.
    /**
     * @param {?} dataIdToken
     * @param {?} local_nonce
     * @return {?}
     */
    function (dataIdToken, local_nonce) {
        if (dataIdToken.nonce !== local_nonce) {
            this.loggerService.logDebug('Validate_id_token_nonce failed, dataIdToken.nonce: ' + dataIdToken.nonce + ' local_nonce:' + local_nonce);
            return false;
        }
        return true;
    };
    // id_token C1: The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
    // MUST exactly match the value of the iss (issuer) Claim.
    // id_token C1: The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
    // MUST exactly match the value of the iss (issuer) Claim.
    /**
     * @param {?} dataIdToken
     * @param {?} authWellKnownEndpoints_issuer
     * @return {?}
     */
    OidcSecurityValidation.prototype.validate_id_token_iss = 
    // id_token C1: The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
    // MUST exactly match the value of the iss (issuer) Claim.
    /**
     * @param {?} dataIdToken
     * @param {?} authWellKnownEndpoints_issuer
     * @return {?}
     */
    function (dataIdToken, authWellKnownEndpoints_issuer) {
        if (((/** @type {?} */ (dataIdToken.iss))) !== ((/** @type {?} */ (authWellKnownEndpoints_issuer)))) {
            this.loggerService.logDebug('Validate_id_token_iss failed, dataIdToken.iss: ' +
                dataIdToken.iss +
                ' authWellKnownEndpoints issuer:' +
                authWellKnownEndpoints_issuer);
            return false;
        }
        return true;
    };
    // id_token C2: The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified
    // by the iss (issuer) Claim as an audience.
    // The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences
    // not trusted by the Client.
    // id_token C2: The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified
    // by the iss (issuer) Claim as an audience.
    // The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences
    // not trusted by the Client.
    /**
     * @param {?} dataIdToken
     * @param {?} aud
     * @return {?}
     */
    OidcSecurityValidation.prototype.validate_id_token_aud = 
    // id_token C2: The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified
    // by the iss (issuer) Claim as an audience.
    // The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences
    // not trusted by the Client.
    /**
     * @param {?} dataIdToken
     * @param {?} aud
     * @return {?}
     */
    function (dataIdToken, aud) {
        if (dataIdToken.aud instanceof Array) {
            /** @type {?} */
            var result = this.arrayHelperService.areEqual(dataIdToken.aud, aud);
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
    };
    /**
     * @param {?} state
     * @param {?} local_state
     * @return {?}
     */
    OidcSecurityValidation.prototype.validateStateFromHashCallback = /**
     * @param {?} state
     * @param {?} local_state
     * @return {?}
     */
    function (state, local_state) {
        if (((/** @type {?} */ (state))) !== ((/** @type {?} */ (local_state)))) {
            this.loggerService.logDebug('ValidateStateFromHashCallback failed, state: ' + state + ' local_state:' + local_state);
            return false;
        }
        return true;
    };
    /**
     * @param {?} id_token_sub
     * @param {?} userdata_sub
     * @return {?}
     */
    OidcSecurityValidation.prototype.validate_userdata_sub_id_token = /**
     * @param {?} id_token_sub
     * @param {?} userdata_sub
     * @return {?}
     */
    function (id_token_sub, userdata_sub) {
        if (((/** @type {?} */ (id_token_sub))) !== ((/** @type {?} */ (userdata_sub)))) {
            this.loggerService.logDebug('validate_userdata_sub_id_token failed, id_token_sub: ' + id_token_sub + ' userdata_sub:' + userdata_sub);
            return false;
        }
        return true;
    };
    // id_token C5: The Client MUST validate the signature of the ID Token according to JWS [JWS] using the algorithm specified in the alg
    // Header Parameter of the JOSE Header.The Client MUST use the keys provided by the Issuer.
    // id_token C6: The alg value SHOULD be RS256. Validation of tokens using other signing algorithms is described in the
    // OpenID Connect Core 1.0 [OpenID.Core] specification.
    // id_token C5: The Client MUST validate the signature of the ID Token according to JWS [JWS] using the algorithm specified in the alg
    // Header Parameter of the JOSE Header.The Client MUST use the keys provided by the Issuer.
    // id_token C6: The alg value SHOULD be RS256. Validation of tokens using other signing algorithms is described in the
    // OpenID Connect Core 1.0 [OpenID.Core] specification.
    /**
     * @param {?} id_token
     * @param {?} jwtkeys
     * @return {?}
     */
    OidcSecurityValidation.prototype.validate_signature_id_token = 
    // id_token C5: The Client MUST validate the signature of the ID Token according to JWS [JWS] using the algorithm specified in the alg
    // Header Parameter of the JOSE Header.The Client MUST use the keys provided by the Issuer.
    // id_token C6: The alg value SHOULD be RS256. Validation of tokens using other signing algorithms is described in the
    // OpenID Connect Core 1.0 [OpenID.Core] specification.
    /**
     * @param {?} id_token
     * @param {?} jwtkeys
     * @return {?}
     */
    function (id_token, jwtkeys) {
        var e_1, _a, e_2, _b, e_3, _c;
        if (!jwtkeys || !jwtkeys.keys) {
            return false;
        }
        /** @type {?} */
        var header_data = this.tokenHelperService.getHeaderFromToken(id_token, false);
        if (Object.keys(header_data).length === 0 && header_data.constructor === Object) {
            this.loggerService.logWarning('id token has no header data');
            return false;
        }
        /** @type {?} */
        var kid = header_data.kid;
        /** @type {?} */
        var alg = header_data.alg;
        if ('RS256' !== ((/** @type {?} */ (alg)))) {
            this.loggerService.logWarning('Only RS256 supported');
            return false;
        }
        /** @type {?} */
        var isValid = false;
        if (!header_data.hasOwnProperty('kid')) {
            // exactly 1 key in the jwtkeys and no kid in the Jose header
            // kty	"RSA" use "sig"
            /** @type {?} */
            var amountOfMatchingKeys = 0;
            try {
                for (var _d = tslib_1.__values(jwtkeys.keys), _e = _d.next(); !_e.done; _e = _d.next()) {
                    var key = _e.value;
                    if (((/** @type {?} */ (key.kty))) === 'RSA' && ((/** @type {?} */ (key.use))) === 'sig') {
                        amountOfMatchingKeys = amountOfMatchingKeys + 1;
                    }
                }
            }
            catch (e_1_1) { e_1 = { error: e_1_1 }; }
            finally {
                try {
                    if (_e && !_e.done && (_a = _d.return)) _a.call(_d);
                }
                finally { if (e_1) throw e_1.error; }
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
                try {
                    for (var _f = tslib_1.__values(jwtkeys.keys), _g = _f.next(); !_g.done; _g = _f.next()) {
                        var key = _g.value;
                        if (((/** @type {?} */ (key.kty))) === 'RSA' && ((/** @type {?} */ (key.use))) === 'sig') {
                            /** @type {?} */
                            var publickey = KEYUTIL.getKey(key);
                            isValid = KJUR.jws.JWS.verify(id_token, publickey, ['RS256']);
                            if (!isValid) {
                                this.loggerService.logWarning('incorrect Signature, validation failed for id_token');
                            }
                            return isValid;
                        }
                    }
                }
                catch (e_2_1) { e_2 = { error: e_2_1 }; }
                finally {
                    try {
                        if (_g && !_g.done && (_b = _f.return)) _b.call(_f);
                    }
                    finally { if (e_2) throw e_2.error; }
                }
            }
        }
        else {
            try {
                // kid in the Jose header of id_token
                for (var _h = tslib_1.__values(jwtkeys.keys), _j = _h.next(); !_j.done; _j = _h.next()) {
                    var key = _j.value;
                    if (((/** @type {?} */ (key.kid))) === ((/** @type {?} */ (kid)))) {
                        /** @type {?} */
                        var publickey = KEYUTIL.getKey(key);
                        isValid = KJUR.jws.JWS.verify(id_token, publickey, ['RS256']);
                        if (!isValid) {
                            this.loggerService.logWarning('incorrect Signature, validation failed for id_token');
                        }
                        return isValid;
                    }
                }
            }
            catch (e_3_1) { e_3 = { error: e_3_1 }; }
            finally {
                try {
                    if (_j && !_j.done && (_c = _h.return)) _c.call(_h);
                }
                finally { if (e_3) throw e_3.error; }
            }
        }
        return isValid;
    };
    /**
     * @param {?} response_type
     * @return {?}
     */
    OidcSecurityValidation.prototype.config_validate_response_type = /**
     * @param {?} response_type
     * @return {?}
     */
    function (response_type) {
        if (response_type === 'id_token token' || response_type === 'id_token') {
            return true;
        }
        if (response_type === 'code') {
            return true;
        }
        this.loggerService.logWarning('module configure incorrect, invalid response_type:' + response_type);
        return false;
    };
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
    OidcSecurityValidation.prototype.validate_id_token_at_hash = 
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
    function (access_token, at_hash, isCodeFlow) {
        this.loggerService.logDebug('at_hash from the server:' + at_hash);
        // The at_hash is optional for the code flow
        if (isCodeFlow) {
            if (!((/** @type {?} */ (at_hash)))) {
                this.loggerService.logDebug('Code Flow active, and no at_hash in the id_token, skipping check!');
                return true;
            }
        }
        /** @type {?} */
        var testdata = this.generate_at_hash('' + access_token);
        this.loggerService.logDebug('at_hash client validation not decoded:' + testdata);
        if (testdata === ((/** @type {?} */ (at_hash)))) {
            return true; // isValid;
        }
        else {
            /** @type {?} */
            var testValue = this.generate_at_hash('' + decodeURIComponent(access_token));
            this.loggerService.logDebug('-gen access--' + testValue);
            if (testValue === ((/** @type {?} */ (at_hash)))) {
                return true; // isValid
            }
        }
        return false;
    };
    /**
     * @private
     * @param {?} access_token
     * @return {?}
     */
    OidcSecurityValidation.prototype.generate_at_hash = /**
     * @private
     * @param {?} access_token
     * @return {?}
     */
    function (access_token) {
        /** @type {?} */
        var hash = KJUR.crypto.Util.hashString(access_token, 'sha256');
        /** @type {?} */
        var first128bits = hash.substr(0, hash.length / 2);
        /** @type {?} */
        var testdata = hextob64u(first128bits);
        return testdata;
    };
    /**
     * @param {?} code_challenge
     * @return {?}
     */
    OidcSecurityValidation.prototype.generate_code_verifier = /**
     * @param {?} code_challenge
     * @return {?}
     */
    function (code_challenge) {
        /** @type {?} */
        var hash = KJUR.crypto.Util.hashString(code_challenge, 'sha256');
        /** @type {?} */
        var testdata = hextob64u(hash);
        return testdata;
    };
    OidcSecurityValidation.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    OidcSecurityValidation.ctorParameters = function () { return [
        { type: EqualityHelperService },
        { type: TokenHelperService },
        { type: LoggerService }
    ]; };
    return OidcSecurityValidation;
}());
export { OidcSecurityValidation };
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2lkYy5zZWN1cml0eS52YWxpZGF0aW9uLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1hdXRoLW9pZGMtY2xpZW50LyIsInNvdXJjZXMiOlsibGliL3NlcnZpY2VzL29pZGMuc2VjdXJpdHkudmFsaWRhdGlvbi50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7OztBQUFBLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLFNBQVMsRUFBRSxPQUFPLEVBQUUsSUFBSSxFQUFFLE1BQU0sV0FBVyxDQUFDO0FBQ3JELE9BQU8sRUFBRSxxQkFBcUIsRUFBRSxNQUFNLGdDQUFnQyxDQUFDO0FBQ3ZFLE9BQU8sRUFBRSxrQkFBa0IsRUFBRSxNQUFNLDZCQUE2QixDQUFDO0FBQ2pFLE9BQU8sRUFBRSxhQUFhLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQTRDdEQ7SUFFSSxnQ0FDWSxrQkFBeUMsRUFDekMsa0JBQXNDLEVBQ3RDLGFBQTRCO1FBRjVCLHVCQUFrQixHQUFsQixrQkFBa0IsQ0FBdUI7UUFDekMsdUJBQWtCLEdBQWxCLGtCQUFrQixDQUFvQjtRQUN0QyxrQkFBYSxHQUFiLGFBQWEsQ0FBZTtJQUNyQyxDQUFDO0lBRUosMEpBQTBKOzs7Ozs7O0lBQzFKLCtDQUFjOzs7Ozs7O0lBQWQsVUFBZSxLQUFhLEVBQUUsYUFBc0I7O1lBQzVDLE9BQVk7UUFDaEIsT0FBTyxHQUFHLElBQUksQ0FBQyxrQkFBa0IsQ0FBQyxtQkFBbUIsQ0FBQyxLQUFLLEVBQUUsS0FBSyxDQUFDLENBQUM7UUFFcEUsT0FBTyxDQUFDLElBQUksQ0FBQyxpQ0FBaUMsQ0FBQyxPQUFPLEVBQUUsYUFBYSxDQUFDLENBQUM7SUFDM0UsQ0FBQztJQUVELDBKQUEwSjs7Ozs7OztJQUMxSixrRUFBaUM7Ozs7Ozs7SUFBakMsVUFBa0MsZ0JBQXdCLEVBQUUsYUFBc0I7O1lBQ3hF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YXIvY29yZSc7XHJcbmltcG9ydCB7IGhleHRvYjY0dSwgS0VZVVRJTCwgS0pVUiB9IGZyb20gJ2pzcnNhc2lnbic7XHJcbmltcG9ydCB7IEVxdWFsaXR5SGVscGVyU2VydmljZSB9IGZyb20gJy4vb2lkYy1lcXVhbGl0eS1oZWxwZXIuc2VydmljZSc7XHJcbmltcG9ydCB7IFRva2VuSGVscGVyU2VydmljZSB9IGZyb20gJy4vb2lkYy10b2tlbi1oZWxwZXIuc2VydmljZSc7XHJcbmltcG9ydCB7IExvZ2dlclNlcnZpY2UgfSBmcm9tICcuL29pZGMubG9nZ2VyLnNlcnZpY2UnO1xyXG5cclxuLy8gaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3QtaW1wbGljaXQtMV8wLmh0bWxcclxuXHJcbi8vIGlkX3Rva2VuXHJcbi8vIGlkX3Rva2VuIEMxOiBUaGUgSXNzdWVyIElkZW50aWZpZXIgZm9yIHRoZSBPcGVuSUQgUHJvdmlkZXIgKHdoaWNoIGlzIHR5cGljYWxseSBvYnRhaW5lZCBkdXJpbmcgRGlzY292ZXJ5KVxyXG4vLyBNVVNUIGV4YWN0bHkgbWF0Y2ggdGhlIHZhbHVlIG9mIHRoZSBpc3MgKGlzc3VlcikgQ2xhaW0uXHJcbi8vXHJcbi8vIGlkX3Rva2VuIEMyOiBUaGUgQ2xpZW50IE1VU1QgdmFsaWRhdGUgdGhhdCB0aGUgYXVkIChhdWRpZW5jZSkgQ2xhaW0gY29udGFpbnMgaXRzIGNsaWVudF9pZCB2YWx1ZSByZWdpc3RlcmVkIGF0IHRoZSBJc3N1ZXIgaWRlbnRpZmllZFxyXG4vLyBieSB0aGUgaXNzIChpc3N1ZXIpIENsYWltIGFzIGFuIGF1ZGllbmNlLlRoZSBJRCBUb2tlbiBNVVNUIGJlIHJlamVjdGVkIGlmIHRoZSBJRCBUb2tlbiBkb2VzIG5vdCBsaXN0IHRoZSBDbGllbnQgYXMgYSB2YWxpZCBhdWRpZW5jZSxcclxuLy8gb3IgaWYgaXQgY29udGFpbnMgYWRkaXRpb25hbCBhdWRpZW5jZXMgbm90IHRydXN0ZWQgYnkgdGhlIENsaWVudC5cclxuLy9cclxuLy8gaWRfdG9rZW4gQzM6IElmIHRoZSBJRCBUb2tlbiBjb250YWlucyBtdWx0aXBsZSBhdWRpZW5jZXMsIHRoZSBDbGllbnQgU0hPVUxEIHZlcmlmeSB0aGF0IGFuIGF6cCBDbGFpbSBpcyBwcmVzZW50LlxyXG4vL1xyXG4vLyBpZF90b2tlbiBDNDogSWYgYW4gYXpwIChhdXRob3JpemVkIHBhcnR5KSBDbGFpbSBpcyBwcmVzZW50LCB0aGUgQ2xpZW50IFNIT1VMRCB2ZXJpZnkgdGhhdCBpdHMgY2xpZW50X2lkIGlzIHRoZSBDbGFpbSBWYWx1ZS5cclxuLy9cclxuLy8gaWRfdG9rZW4gQzU6IFRoZSBDbGllbnQgTVVTVCB2YWxpZGF0ZSB0aGUgc2lnbmF0dXJlIG9mIHRoZSBJRCBUb2tlbiBhY2NvcmRpbmcgdG8gSldTIFtKV1NdIHVzaW5nIHRoZSBhbGdvcml0aG0gc3BlY2lmaWVkIGluIHRoZVxyXG4vLyBhbGcgSGVhZGVyIFBhcmFtZXRlciBvZiB0aGUgSk9TRSBIZWFkZXIuVGhlIENsaWVudCBNVVNUIHVzZSB0aGUga2V5cyBwcm92aWRlZCBieSB0aGUgSXNzdWVyLlxyXG4vL1xyXG4vLyBpZF90b2tlbiBDNjogVGhlIGFsZyB2YWx1ZSBTSE9VTEQgYmUgUlMyNTYuIFZhbGlkYXRpb24gb2YgdG9rZW5zIHVzaW5nIG90aGVyIHNpZ25pbmcgYWxnb3JpdGhtcyBpcyBkZXNjcmliZWQgaW4gdGhlIE9wZW5JRCBDb25uZWN0IENvcmUgMS4wXHJcbi8vIFtPcGVuSUQuQ29yZV0gc3BlY2lmaWNhdGlvbi5cclxuLy9cclxuLy8gaWRfdG9rZW4gQzc6IFRoZSBjdXJyZW50IHRpbWUgTVVTVCBiZSBiZWZvcmUgdGhlIHRpbWUgcmVwcmVzZW50ZWQgYnkgdGhlIGV4cCBDbGFpbSAocG9zc2libHkgYWxsb3dpbmcgZm9yIHNvbWUgc21hbGwgbGVld2F5IHRvIGFjY291bnRcclxuLy8gZm9yIGNsb2NrIHNrZXcpLlxyXG4vL1xyXG4vLyBpZF90b2tlbiBDODogVGhlIGlhdCBDbGFpbSBjYW4gYmUgdXNlZCB0byByZWplY3QgdG9rZW5zIHRoYXQgd2VyZSBpc3N1ZWQgdG9vIGZhciBhd2F5IGZyb20gdGhlIGN1cnJlbnQgdGltZSxcclxuLy8gbGltaXRpbmcgdGhlIGFtb3VudCBvZiB0aW1lIHRoYXQgbm9uY2VzIG5lZWQgdG8gYmUgc3RvcmVkIHRvIHByZXZlbnQgYXR0YWNrcy5UaGUgYWNjZXB0YWJsZSByYW5nZSBpcyBDbGllbnQgc3BlY2lmaWMuXHJcbi8vXHJcbi8vIGlkX3Rva2VuIEM5OiBUaGUgdmFsdWUgb2YgdGhlIG5vbmNlIENsYWltIE1VU1QgYmUgY2hlY2tlZCB0byB2ZXJpZnkgdGhhdCBpdCBpcyB0aGUgc2FtZSB2YWx1ZSBhcyB0aGUgb25lIHRoYXQgd2FzIHNlbnRcclxuLy8gaW4gdGhlIEF1dGhlbnRpY2F0aW9uIFJlcXVlc3QuVGhlIENsaWVudCBTSE9VTEQgY2hlY2sgdGhlIG5vbmNlIHZhbHVlIGZvciByZXBsYXkgYXR0YWNrcy5UaGUgcHJlY2lzZSBtZXRob2QgZm9yIGRldGVjdGluZyByZXBsYXkgYXR0YWNrc1xyXG4vLyBpcyBDbGllbnQgc3BlY2lmaWMuXHJcbi8vXHJcbi8vIGlkX3Rva2VuIEMxMDogSWYgdGhlIGFjciBDbGFpbSB3YXMgcmVxdWVzdGVkLCB0aGUgQ2xpZW50IFNIT1VMRCBjaGVjayB0aGF0IHRoZSBhc3NlcnRlZCBDbGFpbSBWYWx1ZSBpcyBhcHByb3ByaWF0ZS5cclxuLy8gVGhlIG1lYW5pbmcgYW5kIHByb2Nlc3Npbmcgb2YgYWNyIENsYWltIFZhbHVlcyBpcyBvdXQgb2Ygc2NvcGUgZm9yIHRoaXMgZG9jdW1lbnQuXHJcbi8vXHJcbi8vIGlkX3Rva2VuIEMxMTogV2hlbiBhIG1heF9hZ2UgcmVxdWVzdCBpcyBtYWRlLCB0aGUgQ2xpZW50IFNIT1VMRCBjaGVjayB0aGUgYXV0aF90aW1lIENsYWltIHZhbHVlIGFuZCByZXF1ZXN0IHJlLSBhdXRoZW50aWNhdGlvblxyXG4vLyBpZiBpdCBkZXRlcm1pbmVzIHRvbyBtdWNoIHRpbWUgaGFzIGVsYXBzZWQgc2luY2UgdGhlIGxhc3QgRW5kLSBVc2VyIGF1dGhlbnRpY2F0aW9uLlxyXG5cclxuLy8gQWNjZXNzIFRva2VuIFZhbGlkYXRpb25cclxuLy8gYWNjZXNzX3Rva2VuIEMxOiBIYXNoIHRoZSBvY3RldHMgb2YgdGhlIEFTQ0lJIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBhY2Nlc3NfdG9rZW4gd2l0aCB0aGUgaGFzaCBhbGdvcml0aG0gc3BlY2lmaWVkIGluIEpXQVtKV0FdXHJcbi8vIGZvciB0aGUgYWxnIEhlYWRlciBQYXJhbWV0ZXIgb2YgdGhlIElEIFRva2VuJ3MgSk9TRSBIZWFkZXIuIEZvciBpbnN0YW5jZSwgaWYgdGhlIGFsZyBpcyBSUzI1NiwgdGhlIGhhc2ggYWxnb3JpdGhtIHVzZWQgaXMgU0hBLTI1Ni5cclxuLy8gYWNjZXNzX3Rva2VuIEMyOiBUYWtlIHRoZSBsZWZ0LSBtb3N0IGhhbGYgb2YgdGhlIGhhc2ggYW5kIGJhc2U2NHVybC0gZW5jb2RlIGl0LlxyXG4vLyBhY2Nlc3NfdG9rZW4gQzM6IFRoZSB2YWx1ZSBvZiBhdF9oYXNoIGluIHRoZSBJRCBUb2tlbiBNVVNUIG1hdGNoIHRoZSB2YWx1ZSBwcm9kdWNlZCBpbiB0aGUgcHJldmlvdXMgc3RlcCBpZiBhdF9oYXNoIGlzIHByZXNlbnQgaW4gdGhlIElEIFRva2VuLlxyXG5cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgT2lkY1NlY3VyaXR5VmFsaWRhdGlvbiB7XHJcbiAgICBjb25zdHJ1Y3RvcihcclxuICAgICAgICBwcml2YXRlIGFycmF5SGVscGVyU2VydmljZTogRXF1YWxpdHlIZWxwZXJTZXJ2aWNlLFxyXG4gICAgICAgIHByaXZhdGUgdG9rZW5IZWxwZXJTZXJ2aWNlOiBUb2tlbkhlbHBlclNlcnZpY2UsXHJcbiAgICAgICAgcHJpdmF0ZSBsb2dnZXJTZXJ2aWNlOiBMb2dnZXJTZXJ2aWNlXHJcbiAgICApIHt9XHJcblxyXG4gICAgLy8gaWRfdG9rZW4gQzc6IFRoZSBjdXJyZW50IHRpbWUgTVVTVCBiZSBiZWZvcmUgdGhlIHRpbWUgcmVwcmVzZW50ZWQgYnkgdGhlIGV4cCBDbGFpbSAocG9zc2libHkgYWxsb3dpbmcgZm9yIHNvbWUgc21hbGwgbGVld2F5IHRvIGFjY291bnQgZm9yIGNsb2NrIHNrZXcpLlxyXG4gICAgaXNUb2tlbkV4cGlyZWQodG9rZW46IHN0cmluZywgb2Zmc2V0U2Vjb25kcz86IG51bWJlcik6IGJvb2xlYW4ge1xyXG4gICAgICAgIGxldCBkZWNvZGVkOiBhbnk7XHJcbiAgICAgICAgZGVjb2RlZCA9IHRoaXMudG9rZW5IZWxwZXJTZXJ2aWNlLmdldFBheWxvYWRGcm9tVG9rZW4odG9rZW4sIGZhbHNlKTtcclxuXHJcbiAgICAgICAgcmV0dXJuICF0aGlzLnZhbGlkYXRlX2lkX3Rva2VuX2V4cF9ub3RfZXhwaXJlZChkZWNvZGVkLCBvZmZzZXRTZWNvbmRzKTtcclxuICAgIH1cclxuXHJcbiAgICAvLyBpZF90b2tlbiBDNzogVGhlIGN1cnJlbnQgdGltZSBNVVNUIGJlIGJlZm9yZSB0aGUgdGltZSByZXByZXNlbnRlZCBieSB0aGUgZXhwIENsYWltIChwb3NzaWJseSBhbGxvd2luZyBmb3Igc29tZSBzbWFsbCBsZWV3YXkgdG8gYWNjb3VudCBmb3IgY2xvY2sgc2tldykuXHJcbiAgICB2YWxpZGF0ZV9pZF90b2tlbl9leHBfbm90X2V4cGlyZWQoZGVjb2RlZF9pZF90b2tlbjogc3RyaW5nLCBvZmZzZXRTZWNvbmRzPzogbnVtYmVyKTogYm9vbGVhbiB7XHJcbiAgICAgICAgY29uc3QgdG9rZW5FeHBpcmF0aW9uRGF0ZSA9IHRoaXMudG9rZW5IZWxwZXJTZXJ2aWNlLmdldFRva2VuRXhwaXJhdGlvbkRhdGUoZGVjb2RlZF9pZF90b2tlbik7XHJcbiAgICAgICAgb2Zmc2V0U2Vjb25kcyA9IG9mZnNldFNlY29uZHMgfHwgMDtcclxuXHJcbiAgICAgICAgaWYgKCF0b2tlbkV4cGlyYXRpb25EYXRlKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IHRva2VuRXhwaXJhdGlvblZhbHVlID0gdG9rZW5FeHBpcmF0aW9uRGF0ZS52YWx1ZU9mKCk7XHJcbiAgICAgICAgY29uc3Qgbm93V2l0aE9mZnNldCA9IG5ldyBEYXRlKCkudmFsdWVPZigpICsgb2Zmc2V0U2Vjb25kcyAqIDEwMDA7XHJcbiAgICAgICAgY29uc3QgdG9rZW5Ob3RFeHBpcmVkID0gdG9rZW5FeHBpcmF0aW9uVmFsdWUgPiBub3dXaXRoT2Zmc2V0O1xyXG5cclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoYFRva2VuIG5vdCBleHBpcmVkPzogJHt0b2tlbkV4cGlyYXRpb25WYWx1ZX0gPiAke25vd1dpdGhPZmZzZXR9ICAoJHt0b2tlbk5vdEV4cGlyZWR9KWApO1xyXG5cclxuICAgICAgICAvLyBUb2tlbiBub3QgZXhwaXJlZD9cclxuICAgICAgICByZXR1cm4gdG9rZW5Ob3RFeHBpcmVkO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIGlzc1xyXG4gICAgLy8gUkVRVUlSRUQuIElzc3VlciBJZGVudGlmaWVyIGZvciB0aGUgSXNzdWVyIG9mIHRoZSByZXNwb25zZS5UaGUgaXNzIHZhbHVlIGlzIGEgY2FzZS1zZW5zaXRpdmUgVVJMIHVzaW5nIHRoZSBodHRwcyBzY2hlbWUgdGhhdCBjb250YWlucyBzY2hlbWUsIGhvc3QsXHJcbiAgICAvLyBhbmQgb3B0aW9uYWxseSwgcG9ydCBudW1iZXIgYW5kIHBhdGggY29tcG9uZW50cyBhbmQgbm8gcXVlcnkgb3IgZnJhZ21lbnQgY29tcG9uZW50cy5cclxuICAgIC8vXHJcbiAgICAvLyBzdWJcclxuICAgIC8vIFJFUVVJUkVELiBTdWJqZWN0IElkZW50aWZpZXIuTG9jYWxseSB1bmlxdWUgYW5kIG5ldmVyIHJlYXNzaWduZWQgaWRlbnRpZmllciB3aXRoaW4gdGhlIElzc3VlciBmb3IgdGhlIEVuZC0gVXNlcixcclxuICAgIC8vIHdoaWNoIGlzIGludGVuZGVkIHRvIGJlIGNvbnN1bWVkIGJ5IHRoZSBDbGllbnQsIGUuZy4sIDI0NDAwMzIwIG9yIEFJdE9hd213dFd3Y1QwazUxQmF5ZXdOdnV0ckpVcXN2bDZxczdBNC5cclxuICAgIC8vIEl0IE1VU1QgTk9UIGV4Y2VlZCAyNTUgQVNDSUkgY2hhcmFjdGVycyBpbiBsZW5ndGguVGhlIHN1YiB2YWx1ZSBpcyBhIGNhc2Utc2Vuc2l0aXZlIHN0cmluZy5cclxuICAgIC8vXHJcbiAgICAvLyBhdWRcclxuICAgIC8vIFJFUVVJUkVELiBBdWRpZW5jZShzKSB0aGF0IHRoaXMgSUQgVG9rZW4gaXMgaW50ZW5kZWQgZm9yLiBJdCBNVVNUIGNvbnRhaW4gdGhlIE9BdXRoIDIuMCBjbGllbnRfaWQgb2YgdGhlIFJlbHlpbmcgUGFydHkgYXMgYW4gYXVkaWVuY2UgdmFsdWUuXHJcbiAgICAvLyBJdCBNQVkgYWxzbyBjb250YWluIGlkZW50aWZpZXJzIGZvciBvdGhlciBhdWRpZW5jZXMuSW4gdGhlIGdlbmVyYWwgY2FzZSwgdGhlIGF1ZCB2YWx1ZSBpcyBhbiBhcnJheSBvZiBjYXNlLXNlbnNpdGl2ZSBzdHJpbmdzLlxyXG4gICAgLy8gSW4gdGhlIGNvbW1vbiBzcGVjaWFsIGNhc2Ugd2hlbiB0aGVyZSBpcyBvbmUgYXVkaWVuY2UsIHRoZSBhdWQgdmFsdWUgTUFZIGJlIGEgc2luZ2xlIGNhc2Utc2Vuc2l0aXZlIHN0cmluZy5cclxuICAgIC8vXHJcbiAgICAvLyBleHBcclxuICAgIC8vIFJFUVVJUkVELiBFeHBpcmF0aW9uIHRpbWUgb24gb3IgYWZ0ZXIgd2hpY2ggdGhlIElEIFRva2VuIE1VU1QgTk9UIGJlIGFjY2VwdGVkIGZvciBwcm9jZXNzaW5nLlxyXG4gICAgLy8gVGhlIHByb2Nlc3Npbmcgb2YgdGhpcyBwYXJhbWV0ZXIgcmVxdWlyZXMgdGhhdCB0aGUgY3VycmVudCBkYXRlLyB0aW1lIE1VU1QgYmUgYmVmb3JlIHRoZSBleHBpcmF0aW9uIGRhdGUvIHRpbWUgbGlzdGVkIGluIHRoZSB2YWx1ZS5cclxuICAgIC8vIEltcGxlbWVudGVycyBNQVkgcHJvdmlkZSBmb3Igc29tZSBzbWFsbCBsZWV3YXksIHVzdWFsbHkgbm8gbW9yZSB0aGFuIGEgZmV3IG1pbnV0ZXMsIHRvIGFjY291bnQgZm9yIGNsb2NrIHNrZXcuXHJcbiAgICAvLyBJdHMgdmFsdWUgaXMgYSBKU09OIFtSRkM3MTU5XSBudW1iZXIgcmVwcmVzZW50aW5nIHRoZSBudW1iZXIgb2Ygc2Vjb25kcyBmcm9tIDE5NzAtIDAxIC0gMDFUMDA6IDAwOjAwWiBhcyBtZWFzdXJlZCBpbiBVVEMgdW50aWwgdGhlIGRhdGUvIHRpbWUuXHJcbiAgICAvLyBTZWUgUkZDIDMzMzkgW1JGQzMzMzldIGZvciBkZXRhaWxzIHJlZ2FyZGluZyBkYXRlLyB0aW1lcyBpbiBnZW5lcmFsIGFuZCBVVEMgaW4gcGFydGljdWxhci5cclxuICAgIC8vXHJcbiAgICAvLyBpYXRcclxuICAgIC8vIFJFUVVJUkVELiBUaW1lIGF0IHdoaWNoIHRoZSBKV1Qgd2FzIGlzc3VlZC4gSXRzIHZhbHVlIGlzIGEgSlNPTiBudW1iZXIgcmVwcmVzZW50aW5nIHRoZSBudW1iZXIgb2Ygc2Vjb25kcyBmcm9tIDE5NzAtIDAxIC0gMDFUMDA6IDAwOjAwWiBhcyBtZWFzdXJlZFxyXG4gICAgLy8gaW4gVVRDIHVudGlsIHRoZSBkYXRlLyB0aW1lLlxyXG4gICAgdmFsaWRhdGVfcmVxdWlyZWRfaWRfdG9rZW4oZGF0YUlkVG9rZW46IGFueSk6IGJvb2xlYW4ge1xyXG4gICAgICAgIGxldCB2YWxpZGF0ZWQgPSB0cnVlO1xyXG4gICAgICAgIGlmICghZGF0YUlkVG9rZW4uaGFzT3duUHJvcGVydHkoJ2lzcycpKSB7XHJcbiAgICAgICAgICAgIHZhbGlkYXRlZCA9IGZhbHNlO1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnaXNzIGlzIG1pc3NpbmcsIHRoaXMgaXMgcmVxdWlyZWQgaW4gdGhlIGlkX3Rva2VuJyk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoIWRhdGFJZFRva2VuLmhhc093blByb3BlcnR5KCdzdWInKSkge1xyXG4gICAgICAgICAgICB2YWxpZGF0ZWQgPSBmYWxzZTtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ3N1YiBpcyBtaXNzaW5nLCB0aGlzIGlzIHJlcXVpcmVkIGluIHRoZSBpZF90b2tlbicpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKCFkYXRhSWRUb2tlbi5oYXNPd25Qcm9wZXJ0eSgnYXVkJykpIHtcclxuICAgICAgICAgICAgdmFsaWRhdGVkID0gZmFsc2U7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdhdWQgaXMgbWlzc2luZywgdGhpcyBpcyByZXF1aXJlZCBpbiB0aGUgaWRfdG9rZW4nKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmICghZGF0YUlkVG9rZW4uaGFzT3duUHJvcGVydHkoJ2V4cCcpKSB7XHJcbiAgICAgICAgICAgIHZhbGlkYXRlZCA9IGZhbHNlO1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnZXhwIGlzIG1pc3NpbmcsIHRoaXMgaXMgcmVxdWlyZWQgaW4gdGhlIGlkX3Rva2VuJyk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoIWRhdGFJZFRva2VuLmhhc093blByb3BlcnR5KCdpYXQnKSkge1xyXG4gICAgICAgICAgICB2YWxpZGF0ZWQgPSBmYWxzZTtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2lhdCBpcyBtaXNzaW5nLCB0aGlzIGlzIHJlcXVpcmVkIGluIHRoZSBpZF90b2tlbicpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHZhbGlkYXRlZDtcclxuICAgIH1cclxuXHJcbiAgICAvLyBpZF90b2tlbiBDODogVGhlIGlhdCBDbGFpbSBjYW4gYmUgdXNlZCB0byByZWplY3QgdG9rZW5zIHRoYXQgd2VyZSBpc3N1ZWQgdG9vIGZhciBhd2F5IGZyb20gdGhlIGN1cnJlbnQgdGltZSxcclxuICAgIC8vIGxpbWl0aW5nIHRoZSBhbW91bnQgb2YgdGltZSB0aGF0IG5vbmNlcyBuZWVkIHRvIGJlIHN0b3JlZCB0byBwcmV2ZW50IGF0dGFja3MuVGhlIGFjY2VwdGFibGUgcmFuZ2UgaXMgQ2xpZW50IHNwZWNpZmljLlxyXG4gICAgdmFsaWRhdGVfaWRfdG9rZW5faWF0X21heF9vZmZzZXQoZGF0YUlkVG9rZW46IGFueSxcclxuICAgICAgICBtYXhfb2Zmc2V0X2FsbG93ZWRfaW5fc2Vjb25kczogbnVtYmVyLFxyXG4gICAgICAgIGRpc2FibGVfaWF0X29mZnNldF92YWxpZGF0aW9uOiBib29sZWFuKTogYm9vbGVhbiB7XHJcblxyXG4gICAgICAgIGlmIChkaXNhYmxlX2lhdF9vZmZzZXRfdmFsaWRhdGlvbikge1xyXG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmICghZGF0YUlkVG9rZW4uaGFzT3duUHJvcGVydHkoJ2lhdCcpKSB7XHJcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IGRhdGVUaW1lX2lhdF9pZF90b2tlbiA9IG5ldyBEYXRlKDApOyAvLyBUaGUgMCBoZXJlIGlzIHRoZSBrZXksIHdoaWNoIHNldHMgdGhlIGRhdGUgdG8gdGhlIGVwb2NoXHJcbiAgICAgICAgZGF0ZVRpbWVfaWF0X2lkX3Rva2VuLnNldFVUQ1NlY29uZHMoZGF0YUlkVG9rZW4uaWF0KTtcclxuXHJcbiAgICAgICAgbWF4X29mZnNldF9hbGxvd2VkX2luX3NlY29uZHMgPSBtYXhfb2Zmc2V0X2FsbG93ZWRfaW5fc2Vjb25kcyB8fCAwO1xyXG5cclxuICAgICAgICBpZiAoZGF0ZVRpbWVfaWF0X2lkX3Rva2VuID09IG51bGwpIHtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKFxyXG4gICAgICAgICAgICAndmFsaWRhdGVfaWRfdG9rZW5faWF0X21heF9vZmZzZXQ6ICcgK1xyXG4gICAgICAgICAgICAgICAgKG5ldyBEYXRlKCkudmFsdWVPZigpIC0gZGF0ZVRpbWVfaWF0X2lkX3Rva2VuLnZhbHVlT2YoKSkgK1xyXG4gICAgICAgICAgICAgICAgJyA8ICcgK1xyXG4gICAgICAgICAgICAgICAgbWF4X29mZnNldF9hbGxvd2VkX2luX3NlY29uZHMgKiAxMDAwXHJcbiAgICAgICAgKTtcclxuICAgICAgICByZXR1cm4gbmV3IERhdGUoKS52YWx1ZU9mKCkgLSBkYXRlVGltZV9pYXRfaWRfdG9rZW4udmFsdWVPZigpIDwgbWF4X29mZnNldF9hbGxvd2VkX2luX3NlY29uZHMgKiAxMDAwO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIGlkX3Rva2VuIEM5OiBUaGUgdmFsdWUgb2YgdGhlIG5vbmNlIENsYWltIE1VU1QgYmUgY2hlY2tlZCB0byB2ZXJpZnkgdGhhdCBpdCBpcyB0aGUgc2FtZSB2YWx1ZSBhcyB0aGUgb25lXHJcbiAgICAvLyB0aGF0IHdhcyBzZW50IGluIHRoZSBBdXRoZW50aWNhdGlvbiBSZXF1ZXN0LlRoZSBDbGllbnQgU0hPVUxEIGNoZWNrIHRoZSBub25jZSB2YWx1ZSBmb3IgcmVwbGF5IGF0dGFja3MuXHJcbiAgICAvLyBUaGUgcHJlY2lzZSBtZXRob2QgZm9yIGRldGVjdGluZyByZXBsYXkgYXR0YWNrcyBpcyBDbGllbnQgc3BlY2lmaWMuXHJcbiAgICB2YWxpZGF0ZV9pZF90b2tlbl9ub25jZShkYXRhSWRUb2tlbjogYW55LCBsb2NhbF9ub25jZTogYW55KTogYm9vbGVhbiB7XHJcbiAgICAgICAgaWYgKGRhdGFJZFRva2VuLm5vbmNlICE9PSBsb2NhbF9ub25jZSkge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ1ZhbGlkYXRlX2lkX3Rva2VuX25vbmNlIGZhaWxlZCwgZGF0YUlkVG9rZW4ubm9uY2U6ICcgKyBkYXRhSWRUb2tlbi5ub25jZSArICcgbG9jYWxfbm9uY2U6JyArIGxvY2FsX25vbmNlKTtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gaWRfdG9rZW4gQzE6IFRoZSBJc3N1ZXIgSWRlbnRpZmllciBmb3IgdGhlIE9wZW5JRCBQcm92aWRlciAod2hpY2ggaXMgdHlwaWNhbGx5IG9idGFpbmVkIGR1cmluZyBEaXNjb3ZlcnkpXHJcbiAgICAvLyBNVVNUIGV4YWN0bHkgbWF0Y2ggdGhlIHZhbHVlIG9mIHRoZSBpc3MgKGlzc3VlcikgQ2xhaW0uXHJcbiAgICB2YWxpZGF0ZV9pZF90b2tlbl9pc3MoZGF0YUlkVG9rZW46IGFueSwgYXV0aFdlbGxLbm93bkVuZHBvaW50c19pc3N1ZXI6IGFueSk6IGJvb2xlYW4ge1xyXG4gICAgICAgIGlmICgoZGF0YUlkVG9rZW4uaXNzIGFzIHN0cmluZykgIT09IChhdXRoV2VsbEtub3duRW5kcG9pbnRzX2lzc3VlciBhcyBzdHJpbmcpKSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZyhcclxuICAgICAgICAgICAgICAgICdWYWxpZGF0ZV9pZF90b2tlbl9pc3MgZmFpbGVkLCBkYXRhSWRUb2tlbi5pc3M6ICcgK1xyXG4gICAgICAgICAgICAgICAgICAgIGRhdGFJZFRva2VuLmlzcyArXHJcbiAgICAgICAgICAgICAgICAgICAgJyBhdXRoV2VsbEtub3duRW5kcG9pbnRzIGlzc3VlcjonICtcclxuICAgICAgICAgICAgICAgICAgICBhdXRoV2VsbEtub3duRW5kcG9pbnRzX2lzc3VlclxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuXHJcbiAgICAvLyBpZF90b2tlbiBDMjogVGhlIENsaWVudCBNVVNUIHZhbGlkYXRlIHRoYXQgdGhlIGF1ZCAoYXVkaWVuY2UpIENsYWltIGNvbnRhaW5zIGl0cyBjbGllbnRfaWQgdmFsdWUgcmVnaXN0ZXJlZCBhdCB0aGUgSXNzdWVyIGlkZW50aWZpZWRcclxuICAgIC8vIGJ5IHRoZSBpc3MgKGlzc3VlcikgQ2xhaW0gYXMgYW4gYXVkaWVuY2UuXHJcbiAgICAvLyBUaGUgSUQgVG9rZW4gTVVTVCBiZSByZWplY3RlZCBpZiB0aGUgSUQgVG9rZW4gZG9lcyBub3QgbGlzdCB0aGUgQ2xpZW50IGFzIGEgdmFsaWQgYXVkaWVuY2UsIG9yIGlmIGl0IGNvbnRhaW5zIGFkZGl0aW9uYWwgYXVkaWVuY2VzXHJcbiAgICAvLyBub3QgdHJ1c3RlZCBieSB0aGUgQ2xpZW50LlxyXG4gICAgdmFsaWRhdGVfaWRfdG9rZW5fYXVkKGRhdGFJZFRva2VuOiBhbnksIGF1ZDogYW55KTogYm9vbGVhbiB7XHJcbiAgICAgICAgaWYgKGRhdGFJZFRva2VuLmF1ZCBpbnN0YW5jZW9mIEFycmF5KSB7XHJcbiAgICAgICAgICAgIGNvbnN0IHJlc3VsdCA9IHRoaXMuYXJyYXlIZWxwZXJTZXJ2aWNlLmFyZUVxdWFsKGRhdGFJZFRva2VuLmF1ZCwgYXVkKTtcclxuXHJcbiAgICAgICAgICAgIGlmICghcmVzdWx0KSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ1ZhbGlkYXRlX2lkX3Rva2VuX2F1ZCAgYXJyYXkgZmFpbGVkLCBkYXRhSWRUb2tlbi5hdWQ6ICcgKyBkYXRhSWRUb2tlbi5hdWQgKyAnIGNsaWVudF9pZDonICsgYXVkKTtcclxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgfSBlbHNlIGlmIChkYXRhSWRUb2tlbi5hdWQgIT09IGF1ZCkge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ1ZhbGlkYXRlX2lkX3Rva2VuX2F1ZCBmYWlsZWQsIGRhdGFJZFRva2VuLmF1ZDogJyArIGRhdGFJZFRva2VuLmF1ZCArICcgY2xpZW50X2lkOicgKyBhdWQpO1xyXG5cclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgdmFsaWRhdGVTdGF0ZUZyb21IYXNoQ2FsbGJhY2soc3RhdGU6IGFueSwgbG9jYWxfc3RhdGU6IGFueSk6IGJvb2xlYW4ge1xyXG4gICAgICAgIGlmICgoc3RhdGUgYXMgc3RyaW5nKSAhPT0gKGxvY2FsX3N0YXRlIGFzIHN0cmluZykpIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdWYWxpZGF0ZVN0YXRlRnJvbUhhc2hDYWxsYmFjayBmYWlsZWQsIHN0YXRlOiAnICsgc3RhdGUgKyAnIGxvY2FsX3N0YXRlOicgKyBsb2NhbF9zdGF0ZSk7XHJcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIHZhbGlkYXRlX3VzZXJkYXRhX3N1Yl9pZF90b2tlbihpZF90b2tlbl9zdWI6IGFueSwgdXNlcmRhdGFfc3ViOiBhbnkpOiBib29sZWFuIHtcclxuICAgICAgICBpZiAoKGlkX3Rva2VuX3N1YiBhcyBzdHJpbmcpICE9PSAodXNlcmRhdGFfc3ViIGFzIHN0cmluZykpIHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCd2YWxpZGF0ZV91c2VyZGF0YV9zdWJfaWRfdG9rZW4gZmFpbGVkLCBpZF90b2tlbl9zdWI6ICcgKyBpZF90b2tlbl9zdWIgKyAnIHVzZXJkYXRhX3N1YjonICsgdXNlcmRhdGFfc3ViKTtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gaWRfdG9rZW4gQzU6IFRoZSBDbGllbnQgTVVTVCB2YWxpZGF0ZSB0aGUgc2lnbmF0dXJlIG9mIHRoZSBJRCBUb2tlbiBhY2NvcmRpbmcgdG8gSldTIFtKV1NdIHVzaW5nIHRoZSBhbGdvcml0aG0gc3BlY2lmaWVkIGluIHRoZSBhbGdcclxuICAgIC8vIEhlYWRlciBQYXJhbWV0ZXIgb2YgdGhlIEpPU0UgSGVhZGVyLlRoZSBDbGllbnQgTVVTVCB1c2UgdGhlIGtleXMgcHJvdmlkZWQgYnkgdGhlIElzc3Vlci5cclxuICAgIC8vIGlkX3Rva2VuIEM2OiBUaGUgYWxnIHZhbHVlIFNIT1VMRCBiZSBSUzI1Ni4gVmFsaWRhdGlvbiBvZiB0b2tlbnMgdXNpbmcgb3RoZXIgc2lnbmluZyBhbGdvcml0aG1zIGlzIGRlc2NyaWJlZCBpbiB0aGVcclxuICAgIC8vIE9wZW5JRCBDb25uZWN0IENvcmUgMS4wIFtPcGVuSUQuQ29yZV0gc3BlY2lmaWNhdGlvbi5cclxuICAgIHZhbGlkYXRlX3NpZ25hdHVyZV9pZF90b2tlbihpZF90b2tlbjogYW55LCBqd3RrZXlzOiBhbnkpOiBib29sZWFuIHtcclxuICAgICAgICBpZiAoIWp3dGtleXMgfHwgIWp3dGtleXMua2V5cykge1xyXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBoZWFkZXJfZGF0YSA9IHRoaXMudG9rZW5IZWxwZXJTZXJ2aWNlLmdldEhlYWRlckZyb21Ub2tlbihpZF90b2tlbiwgZmFsc2UpO1xyXG5cclxuICAgICAgICBpZiAoT2JqZWN0LmtleXMoaGVhZGVyX2RhdGEpLmxlbmd0aCA9PT0gMCAmJiBoZWFkZXJfZGF0YS5jb25zdHJ1Y3RvciA9PT0gT2JqZWN0KSB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdpZCB0b2tlbiBoYXMgbm8gaGVhZGVyIGRhdGEnKTtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY29uc3Qga2lkID0gaGVhZGVyX2RhdGEua2lkO1xyXG4gICAgICAgIGNvbnN0IGFsZyA9IGhlYWRlcl9kYXRhLmFsZztcclxuXHJcbiAgICAgICAgaWYgKCdSUzI1NicgIT09IChhbGcgYXMgc3RyaW5nKSkge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnT25seSBSUzI1NiBzdXBwb3J0ZWQnKTtcclxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgbGV0IGlzVmFsaWQgPSBmYWxzZTtcclxuXHJcbiAgICAgICAgaWYgKCFoZWFkZXJfZGF0YS5oYXNPd25Qcm9wZXJ0eSgna2lkJykpIHtcclxuICAgICAgICAgICAgLy8gZXhhY3RseSAxIGtleSBpbiB0aGUgand0a2V5cyBhbmQgbm8ga2lkIGluIHRoZSBKb3NlIGhlYWRlclxyXG4gICAgICAgICAgICAvLyBrdHlcdFwiUlNBXCIgdXNlIFwic2lnXCJcclxuICAgICAgICAgICAgbGV0IGFtb3VudE9mTWF0Y2hpbmdLZXlzID0gMDtcclxuICAgICAgICAgICAgZm9yIChjb25zdCBrZXkgb2Ygand0a2V5cy5rZXlzKSB7XHJcbiAgICAgICAgICAgICAgICBpZiAoKGtleS5rdHkgYXMgc3RyaW5nKSA9PT0gJ1JTQScgJiYgKGtleS51c2UgYXMgc3RyaW5nKSA9PT0gJ3NpZycpIHtcclxuICAgICAgICAgICAgICAgICAgICBhbW91bnRPZk1hdGNoaW5nS2V5cyA9IGFtb3VudE9mTWF0Y2hpbmdLZXlzICsgMTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgaWYgKGFtb3VudE9mTWF0Y2hpbmdLZXlzID09PSAwKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnbm8ga2V5cyBmb3VuZCwgaW5jb3JyZWN0IFNpZ25hdHVyZSwgdmFsaWRhdGlvbiBmYWlsZWQgZm9yIGlkX3Rva2VuJyk7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgIH0gZWxzZSBpZiAoYW1vdW50T2ZNYXRjaGluZ0tleXMgPiAxKSB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnbm8gSUQgVG9rZW4ga2lkIGNsYWltIGluIEpPU0UgaGVhZGVyIGFuZCBtdWx0aXBsZSBzdXBwbGllZCBpbiBqd2tzX3VyaScpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgICAgZm9yIChjb25zdCBrZXkgb2Ygand0a2V5cy5rZXlzKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKChrZXkua3R5IGFzIHN0cmluZykgPT09ICdSU0EnICYmIChrZXkudXNlIGFzIHN0cmluZykgPT09ICdzaWcnKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHB1YmxpY2tleSA9IEtFWVVUSUwuZ2V0S2V5KGtleSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlzVmFsaWQgPSBLSlVSLmp3cy5KV1MudmVyaWZ5KGlkX3Rva2VuLCBwdWJsaWNrZXksIFsnUlMyNTYnXSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghaXNWYWxpZCkge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ1dhcm5pbmcoJ2luY29ycmVjdCBTaWduYXR1cmUsIHZhbGlkYXRpb24gZmFpbGVkIGZvciBpZF90b2tlbicpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBpc1ZhbGlkO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgIC8vIGtpZCBpbiB0aGUgSm9zZSBoZWFkZXIgb2YgaWRfdG9rZW5cclxuICAgICAgICAgICAgZm9yIChjb25zdCBrZXkgb2Ygand0a2V5cy5rZXlzKSB7XHJcbiAgICAgICAgICAgICAgICBpZiAoKGtleS5raWQgYXMgc3RyaW5nKSA9PT0gKGtpZCBhcyBzdHJpbmcpKSB7XHJcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgcHVibGlja2V5ID0gS0VZVVRJTC5nZXRLZXkoa2V5KTtcclxuICAgICAgICAgICAgICAgICAgICBpc1ZhbGlkID0gS0pVUi5qd3MuSldTLnZlcmlmeShpZF90b2tlbiwgcHVibGlja2V5LCBbJ1JTMjU2J10pO1xyXG4gICAgICAgICAgICAgICAgICAgIGlmICghaXNWYWxpZCkge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nV2FybmluZygnaW5jb3JyZWN0IFNpZ25hdHVyZSwgdmFsaWRhdGlvbiBmYWlsZWQgZm9yIGlkX3Rva2VuJyk7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBpc1ZhbGlkO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICByZXR1cm4gaXNWYWxpZDtcclxuICAgIH1cclxuXHJcbiAgICBjb25maWdfdmFsaWRhdGVfcmVzcG9uc2VfdHlwZShyZXNwb25zZV90eXBlOiBzdHJpbmcpOiBib29sZWFuIHtcclxuICAgICAgICBpZiAocmVzcG9uc2VfdHlwZSA9PT0gJ2lkX3Rva2VuIHRva2VuJyB8fCByZXNwb25zZV90eXBlID09PSAnaWRfdG9rZW4nKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKHJlc3BvbnNlX3R5cGUgPT09ICdjb2RlJykge1xyXG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dXYXJuaW5nKCdtb2R1bGUgY29uZmlndXJlIGluY29ycmVjdCwgaW52YWxpZCByZXNwb25zZV90eXBlOicgKyByZXNwb25zZV90eXBlKTtcclxuICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gQWNjZXB0cyBJRCBUb2tlbiB3aXRob3V0ICdraWQnIGNsYWltIGluIEpPU0UgaGVhZGVyIGlmIG9ubHkgb25lIEpXSyBzdXBwbGllZCBpbiAnandrc191cmwnXHJcbiAgICAvLy8vIHByaXZhdGUgdmFsaWRhdGVfbm9fa2lkX2luX2hlYWRlcl9vbmx5X29uZV9hbGxvd2VkX2luX2p3dGtleXMoaGVhZGVyX2RhdGE6IGFueSwgand0a2V5czogYW55KTogYm9vbGVhbiB7XHJcbiAgICAvLy8vICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmxvZ0RlYnVnKCdhbW91bnQgb2Ygand0a2V5cy5rZXlzOiAnICsgand0a2V5cy5rZXlzLmxlbmd0aCk7XHJcbiAgICAvLy8vICAgIGlmICghaGVhZGVyX2RhdGEuaGFzT3duUHJvcGVydHkoJ2tpZCcpKSB7XHJcbiAgICAvLy8vICAgICAgICAvLyBubyBraWQgZGVmaW5lZCBpbiBKb3NlIGhlYWRlclxyXG4gICAgLy8vLyAgICAgICAgaWYgKGp3dGtleXMua2V5cy5sZW5ndGggIT0gMSkge1xyXG4gICAgLy8vLyAgICAgICAgICAgIHRoaXMub2lkY1NlY3VyaXR5Q29tbW9uLmxvZ0RlYnVnKCdqd3RrZXlzLmtleXMubGVuZ3RoICE9IDEgYW5kIG5vIGtpZCBpbiBoZWFkZXInKTtcclxuICAgIC8vLy8gICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAvLy8vICAgICAgICB9XHJcbiAgICAvLy8vICAgIH1cclxuXHJcbiAgICAvLy8vICAgIHJldHVybiB0cnVlO1xyXG4gICAgLy8vLyB9XHJcblxyXG4gICAgLy8gQWNjZXNzIFRva2VuIFZhbGlkYXRpb25cclxuICAgIC8vIGFjY2Vzc190b2tlbiBDMTogSGFzaCB0aGUgb2N0ZXRzIG9mIHRoZSBBU0NJSSByZXByZXNlbnRhdGlvbiBvZiB0aGUgYWNjZXNzX3Rva2VuIHdpdGggdGhlIGhhc2ggYWxnb3JpdGhtIHNwZWNpZmllZCBpbiBKV0FbSldBXVxyXG4gICAgLy8gZm9yIHRoZSBhbGcgSGVhZGVyIFBhcmFtZXRlciBvZiB0aGUgSUQgVG9rZW4ncyBKT1NFIEhlYWRlci4gRm9yIGluc3RhbmNlLCBpZiB0aGUgYWxnIGlzIFJTMjU2LCB0aGUgaGFzaCBhbGdvcml0aG0gdXNlZCBpcyBTSEEtMjU2LlxyXG4gICAgLy8gYWNjZXNzX3Rva2VuIEMyOiBUYWtlIHRoZSBsZWZ0LSBtb3N0IGhhbGYgb2YgdGhlIGhhc2ggYW5kIGJhc2U2NHVybC0gZW5jb2RlIGl0LlxyXG4gICAgLy8gYWNjZXNzX3Rva2VuIEMzOiBUaGUgdmFsdWUgb2YgYXRfaGFzaCBpbiB0aGUgSUQgVG9rZW4gTVVTVCBtYXRjaCB0aGUgdmFsdWUgcHJvZHVjZWQgaW4gdGhlIHByZXZpb3VzIHN0ZXAgaWYgYXRfaGFzaFxyXG4gICAgLy8gaXMgcHJlc2VudCBpbiB0aGUgSUQgVG9rZW4uXHJcbiAgICB2YWxpZGF0ZV9pZF90b2tlbl9hdF9oYXNoKGFjY2Vzc190b2tlbjogYW55LCBhdF9oYXNoOiBhbnksIGlzQ29kZUZsb3c6IGJvb2xlYW4pOiBib29sZWFuIHtcclxuICAgICAgICB0aGlzLmxvZ2dlclNlcnZpY2UubG9nRGVidWcoJ2F0X2hhc2ggZnJvbSB0aGUgc2VydmVyOicgKyBhdF9oYXNoKTtcclxuXHJcbiAgICAgICAgLy8gVGhlIGF0X2hhc2ggaXMgb3B0aW9uYWwgZm9yIHRoZSBjb2RlIGZsb3dcclxuICAgICAgICBpZiAoaXNDb2RlRmxvdykge1xyXG4gICAgICAgICAgICBpZiAoIShhdF9oYXNoIGFzIHN0cmluZykpIHtcclxuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyU2VydmljZS5sb2dEZWJ1ZygnQ29kZSBGbG93IGFjdGl2ZSwgYW5kIG5vIGF0X2hhc2ggaW4gdGhlIGlkX3Rva2VuLCBza2lwcGluZyBjaGVjayEnKTtcclxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCB0ZXN0ZGF0YSA9IHRoaXMuZ2VuZXJhdGVfYXRfaGFzaCgnJyArIGFjY2Vzc190b2tlbik7XHJcbiAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCdhdF9oYXNoIGNsaWVudCB2YWxpZGF0aW9uIG5vdCBkZWNvZGVkOicgKyB0ZXN0ZGF0YSk7XHJcbiAgICAgICAgaWYgKHRlc3RkYXRhID09PSAoYXRfaGFzaCBhcyBzdHJpbmcpKSB7XHJcbiAgICAgICAgICAgIHJldHVybiB0cnVlOyAvLyBpc1ZhbGlkO1xyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgIGNvbnN0IHRlc3RWYWx1ZSA9IHRoaXMuZ2VuZXJhdGVfYXRfaGFzaCgnJyArIGRlY29kZVVSSUNvbXBvbmVudChhY2Nlc3NfdG9rZW4pKTtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXJTZXJ2aWNlLmxvZ0RlYnVnKCctZ2VuIGFjY2Vzcy0tJyArIHRlc3RWYWx1ZSk7XHJcbiAgICAgICAgICAgIGlmICh0ZXN0VmFsdWUgPT09IChhdF9oYXNoIGFzIHN0cmluZykpIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlOyAvLyBpc1ZhbGlkXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuXHJcbiAgICBwcml2YXRlIGdlbmVyYXRlX2F0X2hhc2goYWNjZXNzX3Rva2VuOiBhbnkpOiBzdHJpbmcge1xyXG4gICAgICAgIGNvbnN0IGhhc2ggPSBLSlVSLmNyeXB0by5VdGlsLmhhc2hTdHJpbmcoYWNjZXNzX3Rva2VuLCAnc2hhMjU2Jyk7XHJcbiAgICAgICAgY29uc3QgZmlyc3QxMjhiaXRzID0gaGFzaC5zdWJzdHIoMCwgaGFzaC5sZW5ndGggLyAyKTtcclxuICAgICAgICBjb25zdCB0ZXN0ZGF0YSA9IGhleHRvYjY0dShmaXJzdDEyOGJpdHMpO1xyXG5cclxuICAgICAgICByZXR1cm4gdGVzdGRhdGE7XHJcbiAgICB9XHJcblxyXG4gICAgZ2VuZXJhdGVfY29kZV92ZXJpZmllcihjb2RlX2NoYWxsZW5nZTogYW55KTogc3RyaW5nIHtcclxuICAgICAgICBjb25zdCBoYXNoID0gS0pVUi5jcnlwdG8uVXRpbC5oYXNoU3RyaW5nKGNvZGVfY2hhbGxlbmdlLCAnc2hhMjU2Jyk7XHJcbiAgICAgICAgY29uc3QgdGVzdGRhdGEgPSBoZXh0b2I2NHUoaGFzaCk7XHJcblxyXG4gICAgICAgIHJldHVybiB0ZXN0ZGF0YTtcclxuICAgIH1cclxufVxyXG4iXX0=