/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 */
package org.wso2.carbon.identity.oauth2.grant.regionalswitch;

import org.apache.oltu.oauth2.common.validators.AbstractValidator;
import org.wso2.carbon.identity.oauth2.grant.regionalswitch.util.RegionalSwitchGrantConstants;

import javax.servlet.http.HttpServletRequest;

/**
 * This validates the regional switch grant request.
 */
public class RegionalSwitchGrantValidator extends AbstractValidator<HttpServletRequest> {

    public RegionalSwitchGrantValidator() {

        requiredParams.add(RegionalSwitchGrantConstants.Params.TOKEN_PARAM);
        requiredParams.add(RegionalSwitchGrantConstants.Params.ENVIRONMENT_PARAM);
    }
}
