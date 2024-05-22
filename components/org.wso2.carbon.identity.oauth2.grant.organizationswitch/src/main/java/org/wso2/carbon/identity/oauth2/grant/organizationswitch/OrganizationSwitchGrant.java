/*
 * Copyright (c) 2022-2024, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.exception.OrganizationSwitchGrantException;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.internal.OrganizationSwitchGrantDataHolder;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantConstants;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantUtil;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.application.OrgApplicationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.util.Arrays;

import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RESOLVING_TENANT_DOMAIN_FROM_ORGANIZATION_DOMAIN;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_NOT_FOUND_FOR_TENANT;

import static java.util.Objects.nonNull;

/**
 * Implements the AuthorizationGrantHandler for the OrganizationSwitch grant type.
 */
public class OrganizationSwitchGrant extends AbstractAuthorizationGrantHandler {

    private static final Log LOG = LogFactory.getLog(OrganizationSwitchGrant.class);
    private static final String TOKEN_BINDING_REFERENCE = "tokenBindingReference";
    private static final String OAUTH_APP_PROPERTY = "OAuthAppDO";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);

        String token = extractParameter(OrganizationSwitchGrantConstants.Params.TOKEN_PARAM, tokReqMsgCtx);
        String accessingOrgId = extractParameter(OrganizationSwitchGrantConstants.Params.ORG_PARAM, tokReqMsgCtx);
        boolean isActiveOrg = isActiveOrganization(accessingOrgId);
        if (!isActiveOrg) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "The switching organization is in deactivated state.");
        }
        OAuth2TokenValidationResponseDTO validationResponseDTO = validateToken(token);
        if (!validationResponseDTO.isValid()) {
            LOG.debug("Access token validation failed.");

            throw new IdentityOAuth2Exception("Invalid token received.");
        }

        LOG.debug("Access token validation success.");

        AccessTokenDO tokenDO = OAuth2Util.findAccessToken(token, false);
        AuthenticatedUser authorizedUser = nonNull(tokenDO) ? tokenDO.getAuthzUser() :
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                        validationResponseDTO.getAuthorizedUser());

        String appResideOrgId = getOrganizationIdFromTenantDomain(authorizedUser.getTenantDomain());
        OAuthAppDO oAuthAppDO = (OAuthAppDO) tokReqMsgCtx.getProperty(OAUTH_APP_PROPERTY);
        String appName = oAuthAppDO.getApplicationName();
        try {
            // Check whether the organization is allowed to switch.
            if (isInSameBranch(appResideOrgId, accessingOrgId)) {
                isAppShared(appName, authorizedUser.getTenantDomain(), appResideOrgId, accessingOrgId);
            }
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2ServerException("Error while checking organizations allowed to switch.", e);
        }
        AuthenticatedUser authenticatedUser = new AuthenticatedUser(authorizedUser);
        // When accessing the root org, the accessing org is set to null.
        if (StringUtils.equals(appResideOrgId, accessingOrgId)) {
            authenticatedUser.setAccessingOrganization(null);
        } else {
            // Update the accessing organization.
            authenticatedUser.setAccessingOrganization(accessingOrgId);
        }

        // Update the user resident organization if not set already.
        if (StringUtils.isEmpty(authenticatedUser.getUserResidentOrganization())) {
            authenticatedUser.setUserResidentOrganization(appResideOrgId);
        }

        /* Remove user organization from the authenticated user when switching to the app reside organization in order
        to preserve the associative nature of the authenticated user object */
        if (appResideOrgId.equals(accessingOrgId) &&
                appResideOrgId.equals(authenticatedUser.getUserResidentOrganization())) {
            authenticatedUser.setUserResidentOrganization(null);
        }
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);

        String[] allowedScopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();
        if (OAuthConstants.UserType.APPLICATION.equals(tokenDO.getTokenType())) {
            allowedScopes = (String[]) ArrayUtils.removeElement(allowedScopes, OAuthConstants.Scope.OPENID);
        }
        tokReqMsgCtx.setScope(allowedScopes);
        if (tokenDO.getTokenBinding() != null) {
            tokReqMsgCtx.addProperty(TOKEN_BINDING_REFERENCE, tokenDO.getTokenBinding());
        }

        tokReqMsgCtx.addProperty(OAuthConstants.UserType.USER_TYPE, tokenDO.getTokenType());
        if (LOG.isDebugEnabled()) {
            LOG.debug("Issuing an access token for user: " + authenticatedUser + " with scopes: " +
                    Arrays.toString(tokReqMsgCtx.getScope()));
        }
        return true;
    }

    @Override
    public boolean issueRefreshToken(String tokenType) throws IdentityOAuth2Exception {

        return super.issueRefreshToken() && OAuthConstants.UserType.APPLICATION_USER.equals(tokenType);
    }

    @Override
    public boolean isOfTypeApplicationUser(OAuthTokenReqMessageContext tokReqMsgCtx) {

        return OAuthConstants.UserType.APPLICATION_USER
                .equals(tokReqMsgCtx.getProperty(OAuthConstants.UserType.USER_TYPE));
    }

    private boolean isActiveOrganization(String organizationId) throws IdentityOAuth2Exception {

        try {
            boolean organizationExistById = OrganizationSwitchGrantDataHolder.getInstance().getOrganizationManager()
                    .isOrganizationExistById(organizationId);
            if (!organizationExistById) {
                throw new IdentityOAuth2Exception(OAuth2ErrorCodes.INVALID_REQUEST,
                        "Invalid organization id: " + organizationId);
            }
            String tenantDomain = getTenantDomainFromOrgId(organizationId);
            TenantManager tenantManager =
                    OrganizationSwitchGrantDataHolder.getInstance().getRealmService().getTenantManager();
            return tenantManager.isTenantActive(IdentityTenantUtil.getTenantId(tenantDomain));
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while checking organization exist with ID: " + organizationId , e);
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception("Error while validating whether the organization is active.", e);
        }
    }

    private boolean isInSameBranch(String currentOrgId, String switchOrgId) throws IdentityOAuth2ClientException,
            OrganizationManagementServerException {

        if (StringUtils.equals(currentOrgId, switchOrgId)) {
            return false;
        }
        if (getOrganizationManager()
                .getRelativeDepthBetweenOrganizationsInSameBranch(currentOrgId, switchOrgId) < 0) {
            throw new IdentityOAuth2ClientException("Organization switch is only allowed for the organizations " +
                    "in the same branch.");
        }
        return true;
    }

    private void isAppShared(String appName, String tenantDomain, String currentOrgId, String switchOrgId)
            throws IdentityOAuth2Exception, OrganizationManagementException {

        if (!CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME) {
            String appID = getAppID(appName, tenantDomain);
            // Organization switching is allowed only for the organizations that have shared the application.
            if (!OrganizationSwitchGrantConstants.CONSOLE_APP_NAME.equals(appName) &&
                    !getOrgApplicationManager().isApplicationSharedWithGivenOrganization(appID, currentOrgId,
                            switchOrgId)) {
                throw new IdentityOAuth2ClientException("Organization switching is not allowed for organizations " +
                        "that have not shared the application");
            }
        }
    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if (tokReqMsgCtx.getProperty(TOKEN_BINDING_REFERENCE) != null) {
            tokReqMsgCtx.setTokenBinding((TokenBinding) tokReqMsgCtx.getProperty(TOKEN_BINDING_REFERENCE));
        }
        return super.issue(tokReqMsgCtx);
    }

    private String extractParameter(String param, OAuthTokenReqMessageContext tokReqMsgCtx) {

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        if (parameters != null) {
            for (RequestParameter parameter : parameters) {
                if (param.equals(parameter.getKey())) {
                    if (ArrayUtils.isNotEmpty(parameter.getValue())) {
                        return parameter.getValue()[0];
                    }
                }
            }
        }

        return null;
    }

    /**
     * Validate access token.
     *
     * @param accessToken
     * @return OAuth2TokenValidationResponseDTO of the validated token
     */
    private OAuth2TokenValidationResponseDTO validateToken(String accessToken) {

        OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();

        token.setIdentifier(accessToken);
        token.setTokenType("bearer");
        requestDTO.setAccessToken(token);

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                TokenValidationContextParam();

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams = {contextParam};
        requestDTO.setContext(contextParams);

        OAuth2ClientApplicationDTO clientApplicationDTO = OrganizationSwitchGrantDataHolder.getInstance()
                .getOAuth2TokenValidationService().findOAuthConsumerIfTokenIsValid(requestDTO);
        return clientApplicationDTO.getAccessTokenValidationResponse();
    }

    private String getOrganizationIdFromTenantDomain(String tenantDomain) throws OrganizationSwitchGrantException {

        try {
            return OrganizationSwitchGrantDataHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
        } catch (OrganizationManagementException e) {
            throw OrganizationSwitchGrantUtil.handleServerException(ERROR_CODE_ORGANIZATION_NOT_FOUND_FOR_TENANT, e);
        }
    }

    private String getTenantDomainFromOrgId(String organizationId) throws OrganizationSwitchGrantException {

        try {
            return OrganizationSwitchGrantDataHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(organizationId);
        } catch (OrganizationManagementException e) {
            throw OrganizationSwitchGrantUtil.handleServerException(
                    ERROR_CODE_ERROR_RESOLVING_TENANT_DOMAIN_FROM_ORGANIZATION_DOMAIN, e);
        }
    }

    private OrganizationManager getOrganizationManager() {

        return OrganizationSwitchGrantDataHolder.getInstance().getOrganizationManager();
    }

    private OrgApplicationManager getOrgApplicationManager() {

        return OrganizationSwitchGrantDataHolder.getInstance().getOrgApplicationManager();
    }

    private ApplicationManagementService getApplicationManagementService() {

        return OrganizationSwitchGrantDataHolder.getInstance().getApplicationManagementService();
    }

    private String getAppID(String appName, String tenantDomain) throws IdentityOAuth2Exception {

        try {
            ApplicationBasicInfo applicationBasicInfo = getApplicationManagementService().
                    getApplicationBasicInfoByName(appName, tenantDomain);
            if (applicationBasicInfo.getApplicationResourceId() != null) {
                return applicationBasicInfo.getApplicationResourceId();
            } else {
                throw new IdentityOAuth2Exception("Application not found for the name: " + appName);
            }
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while getting application basic info.", e);
        }
    }
}
