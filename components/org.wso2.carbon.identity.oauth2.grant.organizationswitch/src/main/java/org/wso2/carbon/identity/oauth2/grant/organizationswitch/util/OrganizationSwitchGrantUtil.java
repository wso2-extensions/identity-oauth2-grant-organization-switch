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

package org.wso2.carbon.identity.oauth2.grant.organizationswitch.util;

import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.exception.OrganizationSwitchGrantClientException;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.exception.OrganizationSwitchGrantServerException;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;

/**
 * This class provides utility functions for the Organization Switch grant.
 */
public class OrganizationSwitchGrantUtil {

    /**
     * Throw an OrganizationSwitchGrantServerException upon server side error in organization switch grant.
     *
     * @param error The error enum.
     * @param e     The error.
     * @return OrganizationSwitchGrantServerException
     */
    public static OrganizationSwitchGrantServerException handleServerException(
            OrganizationManagementConstants.ErrorMessages error, Throwable e) {

        return new OrganizationSwitchGrantServerException(error.getMessage(), error.getCode(), e);
    }

    /**
     * Throw an OrganizationSwitchGrantClientException upon client side error in organization switch grant.
     *
     * @param error The error enum.
     * @param data  The error message data.
     * @return OrganizationSwitchGrantClientException
     */
    public static OrganizationSwitchGrantClientException handleClientException(
            OrganizationManagementConstants.ErrorMessages error, String... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }
        return new OrganizationSwitchGrantClientException(error.getMessage(), description, error.getCode());
    }
}
