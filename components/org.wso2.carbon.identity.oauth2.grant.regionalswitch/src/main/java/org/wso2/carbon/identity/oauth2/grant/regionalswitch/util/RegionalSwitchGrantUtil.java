/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 */
package org.wso2.carbon.identity.oauth2.grant.regionalswitch.util;

import org.wso2.carbon.identity.oauth2.grant.regionalswitch.exception.RegionalSwitchGrantServerException;

/**
 * This class provides utility functions for the Region Switch grant.
 */
public class RegionalSwitchGrantUtil {

    public static RegionalSwitchGrantServerException handleServerException(String errorMessage, Throwable e) {

        return new RegionalSwitchGrantServerException(errorMessage, e);
    }
}
