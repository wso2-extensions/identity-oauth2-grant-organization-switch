/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 */
package org.wso2.carbon.identity.oauth2.grant.regionalswitch.internal;

import org.wso2.carbon.user.core.service.RealmService;

/**
 * Regional switch grant data holder.
 */
public class RegionalSwitchGrantDataHolder {

    private static RegionalSwitchGrantDataHolder instance = new RegionalSwitchGrantDataHolder();

    private RealmService realmService;

    public static RegionalSwitchGrantDataHolder getInstance() {

        return instance;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }
}
