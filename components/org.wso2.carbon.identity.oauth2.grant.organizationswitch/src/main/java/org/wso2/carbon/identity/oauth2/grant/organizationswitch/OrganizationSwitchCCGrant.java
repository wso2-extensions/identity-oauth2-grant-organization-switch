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

package org.wso2.carbon.identity.oauth2.grant.organizationswitch;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

public class OrganizationSwitchCCGrant extends OrganizationSwitchGrant {

    private static final Log LOG = LogFactory.getLog(OrganizationSwitchCCGrant.class);

    @Override
    protected void validateGrantType(AccessTokenDO accessTokenDO) throws IdentityOAuth2Exception {

        if (!OAuthConstants.GrantTypes.CLIENT_CREDENTIALS.equals(accessTokenDO.getGrantType())
        && !OAuthConstants.GrantTypes.ORGANIZATION_SWITCH_CC.equals(accessTokenDO.getGrantType())) {
            LOG.debug("Access token validation failed.");

            throw new IdentityOAuth2Exception("Invalid grant received.");
        }
    }

    @Override
    public boolean isOfTypeApplicationUser() throws IdentityOAuth2Exception {

        return false;
    }
}
