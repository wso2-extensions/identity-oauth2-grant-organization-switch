/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 */
package org.wso2.carbon.identity.oauth2.grant.regionalswitch.exception;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

/**
 * Base exception class for region switch grant.
 */
public class RegionalSwitchGrantException extends IdentityOAuth2Exception {

    private String errorCode;
    private String description;

    private String errorMessage;

    public RegionalSwitchGrantException(String message, String description, String errorCode) {

        super(errorCode, message);
        this.errorCode = errorCode;
        this.description = description;
    }

    public RegionalSwitchGrantException(String message, String errorCode, Throwable cause) {

        super(errorCode, message, cause);
        this.errorCode = errorCode;
    }

    public RegionalSwitchGrantException(String message, String description, String errorCode, Throwable cause) {

        super(errorCode, message, cause);
        this.errorCode = errorCode;
        this.description = description;
    }

    public RegionalSwitchGrantException(String message, Throwable cause) {

        super(message, cause);
        this.errorMessage = message;
    }

    public String getErrorCode() {

        return errorCode;
    }

    public String getDescription() {

        return description;
    }

    public String getErrorMessage() {

        return errorMessage;
    }
}
