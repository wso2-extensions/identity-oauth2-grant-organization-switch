package org.wso2.carbon.identity.oauth2.grant.regionalswitch.internal;

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


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * This class contains the service component of the region switching grant type.
 */
@Component(
        name = "identity.oauth2.grant.regionalswitch.component",
        immediate = true
)
public class RegionalSwitchGrantServiceComponent {

    private static final Log LOG = LogFactory.getLog(RegionalSwitchGrantServiceComponent.class);

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting the Realm Service");
        }
        RegionalSwitchGrantDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsetting the Realm Service");
        }
        RegionalSwitchGrantDataHolder.getInstance().setRealmService(null);
    }
}
