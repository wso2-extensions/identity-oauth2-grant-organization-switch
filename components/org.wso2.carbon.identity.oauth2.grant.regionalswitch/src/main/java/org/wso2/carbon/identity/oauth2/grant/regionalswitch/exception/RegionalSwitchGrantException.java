package org.wso2.carbon.identity.oauth2.grant.regionalswitch.exception;

/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


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

    public RegionalSwitchGrantException(String message,Throwable cause) {

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
