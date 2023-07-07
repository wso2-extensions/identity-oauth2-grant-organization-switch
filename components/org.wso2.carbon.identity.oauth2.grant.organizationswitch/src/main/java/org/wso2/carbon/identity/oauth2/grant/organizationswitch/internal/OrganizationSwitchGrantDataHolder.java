/*
 * Copyright (c) 2022-2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.grant.organizationswitch.internal;

import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationUserResidentResolverService;

/**
 * Organization switch grant data holder.
 */
public class OrganizationSwitchGrantDataHolder {

    private static OrganizationSwitchGrantDataHolder instance = new OrganizationSwitchGrantDataHolder();

    private OAuth2TokenValidationService oAuth2TokenValidationService;
    private OrganizationUserResidentResolverService organizationUserResidentResolverService;
    private OrganizationManager organizationManager;

    public static OrganizationSwitchGrantDataHolder getInstance() {

        return instance;
    }

    /**
     * Get {@link OAuth2TokenValidationService}.
     *
     * @return OAuth2 token validation service instance {@link OAuth2TokenValidationService}.
     */
    public OAuth2TokenValidationService getOAuth2TokenValidationService() {

        return oAuth2TokenValidationService;
    }

    /**
     * Set {@link OAuth2TokenValidationService}.
     *
     * @param oAuth2TokenValidationService Instance of {@link OAuth2TokenValidationService}.
     */
    public void setOAuth2TokenValidationService(OAuth2TokenValidationService oAuth2TokenValidationService) {

        this.oAuth2TokenValidationService = oAuth2TokenValidationService;
    }

    public OrganizationUserResidentResolverService getOrganizationUserResidentResolverService() {

        return organizationUserResidentResolverService;
    }

    public void setOrganizationUserResidentResolverService
            (OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        this.organizationUserResidentResolverService = organizationUserResidentResolverService;
    }

    /**
     * Get {@link OrganizationManager}.
     *
     * @return organization manager instance {@link OrganizationManager}.
     */
    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    /**
     * Set {@link OrganizationManager}.
     *
     * @param organizationManager Instance of {@link OrganizationManager}.
     */
    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }
}
