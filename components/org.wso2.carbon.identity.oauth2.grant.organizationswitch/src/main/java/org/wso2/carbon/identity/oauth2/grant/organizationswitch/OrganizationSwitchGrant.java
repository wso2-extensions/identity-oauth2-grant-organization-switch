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

package org.wso2.carbon.identity.oauth2.grant.organizationswitch;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.exception.OrganizationSwitchGrantException;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.exception.OrganizationSwitchGrantServerException;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.internal.OrganizationSwitchGrantDataHolder;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantConstants;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantUtil;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManagerImpl;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.Arrays;
import java.util.Optional;

import static java.util.Objects.nonNull;
import static java.util.Optional.ofNullable;

import static org.apache.commons.lang.StringUtils.equalsIgnoreCase;
import static org.apache.commons.lang.StringUtils.isBlank;
import static org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantConstants.ORGANIZATION_AUTHENTICATOR;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RESOLVING_TENANT_DOMAIN_FROM_ORGANIZATION_DOMAIN;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RETRIEVING_AUTHENTICATED_USER;
import static org.wso2.carbon.user.core.UserCoreConstants.TENANT_DOMAIN_COMBINER;

/**
 * Implements the AuthorizationGrantHandler for the OrganizationSwitch grant type.
 */
public class OrganizationSwitchGrant extends AbstractAuthorizationGrantHandler {

    private static final Log LOG = LogFactory.getLog(OrganizationSwitchGrant.class);
    private static final String TOKEN_BINDING_REFERENCE = "tokenBindingReference";
    public OrganizationManager organizationManager = new OrganizationManagerImpl();

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);

        String token = extractParameter(OrganizationSwitchGrantConstants.Params.TOKEN_PARAM, tokReqMsgCtx);
        String organizationId = extractParameter(OrganizationSwitchGrantConstants.Params.ORG_PARAM, tokReqMsgCtx);
        String tokenRequestedTenantDomain = getTenantDomainFromOrganizationId(organizationId);
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
        if (StringUtils.equals(tokenRequestedTenantDomain, authorizedUser.getTenantDomain())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Provided token was already issued for the requested tenant domain: " +
                        tokenRequestedTenantDomain);
            }
            throw new IdentityOAuth2Exception("Provided token was already issued for the requested tenant domain.");
        }
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(authorizedUser.getUserName());
        authenticatedUser.setUserStoreDomain(authorizedUser.getUserStoreDomain());
        authenticatedUser.setTenantDomain(tokenRequestedTenantDomain);

        String userId = null;
        if (authorizedUser.isFederatedUser()) {
            IdentityProvider idp = OAuth2Util.getIdentityProvider(authorizedUser.getFederatedIdPName(),
                    authorizedUser.getTenantDomain());
            if (equalsIgnoreCase(ORGANIZATION_AUTHENTICATOR,
                    ofNullable(idp.getDefaultAuthenticatorConfig()).map(FederatedAuthenticatorConfig::getName)
                            .orElse(null))) {
                // If the user bound to the token is a federated user and the user is authenticated via
                // OrganizationLogin Authenticator accessing the organization_switch grant, the user ID is populated
                // as the username.
                userId = authorizedUser.getUserName();
            } else {
                Optional<org.wso2.carbon.user.core.common.User> optionalUser =
                        getFederatedUserFromResidentOrganization(authorizedUser.getUserName(), organizationId);
                if (optionalUser.isPresent()) {
                    userId = optionalUser.get().getUserID();
                    authenticatedUser.setUserStoreDomain(optionalUser.get().getUserStoreDomain());
                    authenticatedUser.setAuthenticatedSubjectIdentifier(optionalUser.get().getUsername() +
                            TENANT_DOMAIN_COMBINER + authenticatedUser.getTenantDomain());
                }
            }
        }

        if (isBlank(userId)) {
            userId = getUserIdFromAuthorizedUser(authorizedUser);
        }

        authenticatedUser.setUserId(userId);

        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);

        String[] allowedScopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();
        tokReqMsgCtx.setScope(allowedScopes);
        if (tokenDO.getTokenBinding() != null) {
            tokReqMsgCtx.addProperty(TOKEN_BINDING_REFERENCE, tokenDO.getTokenBinding());
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Issuing an access token for user: " + authenticatedUser + " with scopes: " +
                    Arrays.toString(tokReqMsgCtx.getScope()));
        }

        return true;
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

        OAuth2TokenValidationService oAuth2TokenValidationService = new OAuth2TokenValidationService();
        OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();

        token.setIdentifier(accessToken);
        token.setTokenType("bearer");
        requestDTO.setAccessToken(token);

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                TokenValidationContextParam();

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams = {contextParam};
        requestDTO.setContext(contextParams);

        OAuth2ClientApplicationDTO clientApplicationDTO = oAuth2TokenValidationService
                .findOAuthConsumerIfTokenIsValid
                        (requestDTO);
        return clientApplicationDTO.getAccessTokenValidationResponse();
    }

    private String getUserIdFromAuthorizedUser(User authorizedUser) throws OrganizationSwitchGrantException {

        try {
            return new AuthenticatedUser(authorizedUser).getUserId();
        } catch (UserIdNotFoundException e) {
            throw OrganizationSwitchGrantUtil.handleServerException(ERROR_CODE_ERROR_RETRIEVING_AUTHENTICATED_USER, e);
        }
    }

    private String getTenantDomainFromOrganizationId(String organizationId) throws OrganizationSwitchGrantException {

        try {
            return organizationManager.resolveTenantDomain(organizationId);
        } catch (OrganizationManagementException e) {
            throw OrganizationSwitchGrantUtil.handleServerException(
                    ERROR_CODE_ERROR_RESOLVING_TENANT_DOMAIN_FROM_ORGANIZATION_DOMAIN, e);
        }
    }

    private Optional<org.wso2.carbon.user.core.common.User> getFederatedUserFromResidentOrganization(String username,
                                                                                                     String organizationId)
            throws OrganizationSwitchGrantServerException {

        try {
            return OrganizationSwitchGrantDataHolder.getInstance().getOrganizationUserResidentResolverService()
                    .resolveUserFromResidentOrganization(username, null, organizationId);
        } catch (OrganizationManagementException e) {
            throw OrganizationSwitchGrantUtil.handleServerException(ERROR_CODE_ERROR_RETRIEVING_AUTHENTICATED_USER, e);
        }
    }
}
