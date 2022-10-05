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

    protected void unsetOrganizationUserResidentResolverService(OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        LOG.debug("Organization user resident resolver service is unset.");
        OrganizationSwitchGrantDataHolder.getInstance().setOrganizationUserResidentResolverService(null);
    }
}
