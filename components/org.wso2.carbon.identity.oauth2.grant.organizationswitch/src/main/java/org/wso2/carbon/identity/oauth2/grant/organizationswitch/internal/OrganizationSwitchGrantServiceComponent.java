/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.organization.management.application.OrgApplicationManager;
import org.wso2.carbon.identity.organization.management.application.internal.OrgApplicationMgtDataHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationUserResidentResolverService;

/**
 * This class contains the service component of the organization switching grant type.
 */
@Component(
        name = "identity.oauth2.grant.organizationswitch.component",
        immediate = true
)
public class OrganizationSwitchGrantServiceComponent {

    private static final Log LOG = LogFactory.getLog(OrganizationSwitchGrantServiceComponent.class);

    /**
     * Set OAuth2 token validation service.
     *
     * @param oAuth2TokenValidationService OAuth2TokenValidationService
     */
    @Reference(name = "identity.oauth2.token.validation.service.component",
            service = OAuth2TokenValidationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOAuth2TokenValidationService")
    protected void setOAuth2TokenValidationService(OAuth2TokenValidationService oAuth2TokenValidationService) {

        LOG.debug("OAuth2 Token Validation Service is set.");
        OrganizationSwitchGrantDataHolder.getInstance().setOAuth2TokenValidationService(oAuth2TokenValidationService);
    }

    /**
     * Unset OAuth2 token validation service.
     *
     * @param oAuth2TokenValidationService OAuth2TokenValidationService
     */
    protected void unsetOAuth2TokenValidationService(OAuth2TokenValidationService oAuth2TokenValidationService) {

        LOG.debug("OAuth2 Token Validation Service is unset.");
        OrganizationSwitchGrantDataHolder.getInstance().setOAuth2TokenValidationService(null);
    }

    @Reference(name = "identity.organization.management.user.resident.resolver.service.component",
            service = OrganizationUserResidentResolverService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationUserResidentResolverService")
    protected void setOrganizationUserResidentResolverService(OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        LOG.debug("Organization user resident resolver service is set.");
        OrganizationSwitchGrantDataHolder.getInstance()
                .setOrganizationUserResidentResolverService(organizationUserResidentResolverService);
    }

    protected void unsetOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        LOG.debug("Organization user resident resolver service is unset.");
        OrganizationSwitchGrantDataHolder.getInstance().setOrganizationUserResidentResolverService(null);
    }

    /**
     * Set organization management service implementation.
     *
     * @param organizationManager OrganizationManager
     */
    @Reference(name = "identity.organization.management.component",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        OrganizationSwitchGrantDataHolder.getInstance().setOrganizationManager(organizationManager);
    }

    /**
     * Unset organization management service implementation.
     *
     * @param organizationManager OrganizationManager
     */
    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        OrganizationSwitchGrantDataHolder.getInstance().setOrganizationManager(null);
    }

    /**
     * Set organization application management service implementation.
     *
     * @param orgApplicationManager OrganizationManager.
     */
    @Reference(name = "identity.organization.application.management.component",
            service = OrgApplicationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrgApplicationManager")
    protected void setOrgApplicationManager(OrgApplicationManager orgApplicationManager) {

        OrganizationSwitchGrantDataHolder.getInstance().setOrgApplicationManager(orgApplicationManager);
        LOG.debug("Organization Application Manager is set in the Authenticator");
    }

    /**
     * Unset organization application management service implementation.
     *
     * @param orgApplicationManager OrganizationManager.
     */
    protected void unsetOrgApplicationManager(OrgApplicationManager orgApplicationManager) {

        OrganizationSwitchGrantDataHolder.getInstance().setOrgApplicationManager(null);
        LOG.debug("Organization Application Manager is unset in the Authenticator");
    }

    /**
     * Set application management service implementation.
     *
     * @param applicationManagementService ApplicationManagementService.
     */
    @Reference(name = "identity.application.management.component",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService")
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        OrganizationSwitchGrantDataHolder.getInstance().setApplicationManagementService(applicationManagementService);
    }

    /**
     * Unset application management service implementation.
     *
     * @param applicationManagementService ApplicationManagementService.
     */
    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        OrganizationSwitchGrantDataHolder.getInstance().setApplicationManagementService(null);
    }

    @Reference(
            name = "organization.user.sharing.service",
            service = OrganizationUserSharingService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationUserAssociationService")
    protected void setOrganizationUserSharingService(OrganizationUserSharingService organizationUserSharingService) {

        OrganizationSwitchGrantDataHolder.getInstance().setOrganizationUserSharingService(organizationUserSharingService);
        LOG.debug("Set organization user association service.");
    }

    protected void unsetOrganizationUserAssociationService(
            OrganizationUserSharingService organizationUserSharingService) {

        OrganizationSwitchGrantDataHolder.getInstance().setOrganizationUserSharingService(null);
        LOG.debug("Unset organization user association Service.");
    }
}
