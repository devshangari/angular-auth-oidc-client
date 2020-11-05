/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
export class AuthWellKnownEndpoints {
    constructor() {
        this.issuer = '';
        this.jwks_uri = '';
        this.authorization_endpoint = '';
        this.token_endpoint = '';
        this.userinfo_endpoint = '';
        this.end_session_endpoint = '';
        this.check_session_iframe = '';
        this.revocation_endpoint = '';
        this.introspection_endpoint = '';
    }
    /**
     * @param {?} data
     * @return {?}
     */
    setWellKnownEndpoints(data) {
        this.issuer = data.issuer;
        this.jwks_uri = data.jwks_uri;
        this.authorization_endpoint = data.authorization_endpoint;
        this.token_endpoint = data.token_endpoint;
        this.userinfo_endpoint = data.userinfo_endpoint;
        if (data.end_session_endpoint) {
            this.end_session_endpoint = data.end_session_endpoint;
        }
        if (data.check_session_iframe) {
            this.check_session_iframe = data.check_session_iframe;
        }
        if (data.revocation_endpoint) {
            this.revocation_endpoint = data.revocation_endpoint;
        }
        if (data.introspection_endpoint) {
            this.introspection_endpoint = data.introspection_endpoint;
        }
    }
}
if (false) {
    /** @type {?} */
    AuthWellKnownEndpoints.prototype.issuer;
    /** @type {?} */
    AuthWellKnownEndpoints.prototype.jwks_uri;
    /** @type {?} */
    AuthWellKnownEndpoints.prototype.authorization_endpoint;
    /** @type {?} */
    AuthWellKnownEndpoints.prototype.token_endpoint;
    /** @type {?} */
    AuthWellKnownEndpoints.prototype.userinfo_endpoint;
    /** @type {?} */
    AuthWellKnownEndpoints.prototype.end_session_endpoint;
    /** @type {?} */
    AuthWellKnownEndpoints.prototype.check_session_iframe;
    /** @type {?} */
    AuthWellKnownEndpoints.prototype.revocation_endpoint;
    /** @type {?} */
    AuthWellKnownEndpoints.prototype.introspection_endpoint;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC53ZWxsLWtub3duLWVuZHBvaW50cy5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItYXV0aC1vaWRjLWNsaWVudC8iLCJzb3VyY2VzIjpbImxpYi9tb2RlbHMvYXV0aC53ZWxsLWtub3duLWVuZHBvaW50cy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsTUFBTSxPQUFPLHNCQUFzQjtJQUFuQztRQUNJLFdBQU0sR0FBRyxFQUFFLENBQUM7UUFDWixhQUFRLEdBQUcsRUFBRSxDQUFDO1FBQ2QsMkJBQXNCLEdBQUcsRUFBRSxDQUFDO1FBQzVCLG1CQUFjLEdBQUcsRUFBRSxDQUFDO1FBQ3BCLHNCQUFpQixHQUFHLEVBQUUsQ0FBQztRQUN2Qix5QkFBb0IsR0FBRyxFQUFFLENBQUM7UUFDMUIseUJBQW9CLEdBQUcsRUFBRSxDQUFDO1FBQzFCLHdCQUFtQixHQUFHLEVBQUUsQ0FBQztRQUN6QiwyQkFBc0IsR0FBRyxFQUFFLENBQUM7SUF5QmhDLENBQUM7Ozs7O0lBdkJVLHFCQUFxQixDQUFDLElBQVM7UUFDbEMsSUFBSSxDQUFDLE1BQU0sR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDO1FBQzFCLElBQUksQ0FBQyxRQUFRLEdBQUcsSUFBSSxDQUFDLFFBQVEsQ0FBQztRQUM5QixJQUFJLENBQUMsc0JBQXNCLEdBQUcsSUFBSSxDQUFDLHNCQUFzQixDQUFDO1FBQzFELElBQUksQ0FBQyxjQUFjLEdBQUcsSUFBSSxDQUFDLGNBQWMsQ0FBQztRQUMxQyxJQUFJLENBQUMsaUJBQWlCLEdBQUcsSUFBSSxDQUFDLGlCQUFpQixDQUFDO1FBRWhELElBQUksSUFBSSxDQUFDLG9CQUFvQixFQUFFO1lBQzNCLElBQUksQ0FBQyxvQkFBb0IsR0FBRyxJQUFJLENBQUMsb0JBQW9CLENBQUM7U0FDekQ7UUFFRCxJQUFJLElBQUksQ0FBQyxvQkFBb0IsRUFBRTtZQUMzQixJQUFJLENBQUMsb0JBQW9CLEdBQUcsSUFBSSxDQUFDLG9CQUFvQixDQUFDO1NBQ3pEO1FBRUQsSUFBSSxJQUFJLENBQUMsbUJBQW1CLEVBQUU7WUFDMUIsSUFBSSxDQUFDLG1CQUFtQixHQUFHLElBQUksQ0FBQyxtQkFBbUIsQ0FBQztTQUN2RDtRQUVELElBQUksSUFBSSxDQUFDLHNCQUFzQixFQUFFO1lBQzdCLElBQUksQ0FBQyxzQkFBc0IsR0FBRyxJQUFJLENBQUMsc0JBQXNCLENBQUM7U0FDN0Q7SUFDTCxDQUFDO0NBQ0o7OztJQWpDRyx3Q0FBWTs7SUFDWiwwQ0FBYzs7SUFDZCx3REFBNEI7O0lBQzVCLGdEQUFvQjs7SUFDcEIsbURBQXVCOztJQUN2QixzREFBMEI7O0lBQzFCLHNEQUEwQjs7SUFDMUIscURBQXlCOztJQUN6Qix3REFBNEIiLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgY2xhc3MgQXV0aFdlbGxLbm93bkVuZHBvaW50cyB7XHJcbiAgICBpc3N1ZXIgPSAnJztcclxuICAgIGp3a3NfdXJpID0gJyc7XHJcbiAgICBhdXRob3JpemF0aW9uX2VuZHBvaW50ID0gJyc7XHJcbiAgICB0b2tlbl9lbmRwb2ludCA9ICcnO1xyXG4gICAgdXNlcmluZm9fZW5kcG9pbnQgPSAnJztcclxuICAgIGVuZF9zZXNzaW9uX2VuZHBvaW50ID0gJyc7XHJcbiAgICBjaGVja19zZXNzaW9uX2lmcmFtZSA9ICcnO1xyXG4gICAgcmV2b2NhdGlvbl9lbmRwb2ludCA9ICcnO1xyXG4gICAgaW50cm9zcGVjdGlvbl9lbmRwb2ludCA9ICcnO1xyXG5cclxuICAgIHB1YmxpYyBzZXRXZWxsS25vd25FbmRwb2ludHMoZGF0YTogYW55KSB7XHJcbiAgICAgICAgdGhpcy5pc3N1ZXIgPSBkYXRhLmlzc3VlcjtcclxuICAgICAgICB0aGlzLmp3a3NfdXJpID0gZGF0YS5qd2tzX3VyaTtcclxuICAgICAgICB0aGlzLmF1dGhvcml6YXRpb25fZW5kcG9pbnQgPSBkYXRhLmF1dGhvcml6YXRpb25fZW5kcG9pbnQ7XHJcbiAgICAgICAgdGhpcy50b2tlbl9lbmRwb2ludCA9IGRhdGEudG9rZW5fZW5kcG9pbnQ7XHJcbiAgICAgICAgdGhpcy51c2VyaW5mb19lbmRwb2ludCA9IGRhdGEudXNlcmluZm9fZW5kcG9pbnQ7XHJcblxyXG4gICAgICAgIGlmIChkYXRhLmVuZF9zZXNzaW9uX2VuZHBvaW50KSB7XHJcbiAgICAgICAgICAgIHRoaXMuZW5kX3Nlc3Npb25fZW5kcG9pbnQgPSBkYXRhLmVuZF9zZXNzaW9uX2VuZHBvaW50O1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgaWYgKGRhdGEuY2hlY2tfc2Vzc2lvbl9pZnJhbWUpIHtcclxuICAgICAgICAgICAgdGhpcy5jaGVja19zZXNzaW9uX2lmcmFtZSA9IGRhdGEuY2hlY2tfc2Vzc2lvbl9pZnJhbWU7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBpZiAoZGF0YS5yZXZvY2F0aW9uX2VuZHBvaW50KSB7XHJcbiAgICAgICAgICAgIHRoaXMucmV2b2NhdGlvbl9lbmRwb2ludCA9IGRhdGEucmV2b2NhdGlvbl9lbmRwb2ludDtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGlmIChkYXRhLmludHJvc3BlY3Rpb25fZW5kcG9pbnQpIHtcclxuICAgICAgICAgICAgdGhpcy5pbnRyb3NwZWN0aW9uX2VuZHBvaW50ID0gZGF0YS5pbnRyb3NwZWN0aW9uX2VuZHBvaW50O1xyXG4gICAgICAgIH1cclxuICAgIH1cclxufVxyXG4iXX0=