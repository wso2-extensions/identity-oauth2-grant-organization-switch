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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.internal.OrganizationSwitchGrantDataHolder;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantConstants;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.application.OrgApplicationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;
import org.wso2.carbon.identity.organization.management.service.util.Utils;

import java.util.ArrayList;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantConstants.TOKEN_BINDING_REFERENCE;

@WithCarbonHome
public class OrganizationSwitchGrantTest {

    private static final String TOKEN_ISSUED_ORG_ID = "90184a8d-113f-5211-a0d5-efe36b082233";
    private static final String TOKEN_ISSUED_TENANT_DOMAIN = "EasyMeet";
    private static final  String SWITCHING_ORG_ID = "70184a8d-113f-5211-ac0d5-efe39b082214";
    private static final String SWITCHING_ORG_TENANT_DOMAIN = "Medverse";
    private static final String MOCK_TOKEN_BINDING_REFERENCE = "mockTokenBindingReference";
    private static final String APPLICATION_NAME = "B2B-APP";
    private static final String APPLICATION_ID = "123456";
    private static final String ACCESS_TOKEN = "a8fb49be-5a28-30bd-98ea-dad7b87d5d86";
    private OAuth2TokenValidationService mockOAuth2TokenValidationService;
    private OrganizationManager mockOrganizationManager;
    private OrgApplicationManager mockOrgApplicationManager;
    private ApplicationManagementService mockApplicationManagementService;
    private OAuth2ClientApplicationDTO mockOAuth2ClientApplicationDTO;
    private OAuthAppDO mockOAuthAppDO;
    private ApplicationBasicInfo mockApplicationBasicInfo;
    private OAuthTokenReqMessageContext oAuthTokenReqMessageContext;
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;
    private OAuth2TokenValidationResponseDTO mockOAuth2TokenValidationResponseDTO;
    private OrganizationSwitchGrant organizationSwitchGrant;
    private AccessTokenDO mockAccessTokenDO;
    private AuthenticatedUser mockAuthenticatedUser;
    private MockedStatic<OAuth2Util> mockedOAuth2Util;
    private MockedStatic<Utils> mockOrgUtil;

    @BeforeClass
    public void setup() throws IdentityApplicationManagementException {

        mockAccessTokenDO = mock(AccessTokenDO.class);
        mockAuthenticatedUser = mock(AuthenticatedUser.class);
        mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
        mockOrgUtil = Mockito.mockStatic(Utils.class);
        mockedOAuth2Util.when(() -> OAuth2Util.findAccessToken(nullable(String.class), anyBoolean())).thenReturn(mockAccessTokenDO);
        mockOrgUtil.when(Utils::getSubOrgStartLevel).thenReturn(2);

        mockOAuth2TokenValidationService = mock(OAuth2TokenValidationService.class);
        mockOAuth2ClientApplicationDTO = mock(OAuth2ClientApplicationDTO.class);
        mockOAuthAppDO = mock(OAuthAppDO.class);
        mockOAuth2TokenValidationResponseDTO = mock(OAuth2TokenValidationResponseDTO.class);
        OrganizationSwitchGrantDataHolder.getInstance().setOAuth2TokenValidationService(mockOAuth2TokenValidationService);
        when(mockOAuth2TokenValidationService.findOAuthConsumerIfTokenIsValid(any())).thenReturn(mockOAuth2ClientApplicationDTO);
        when(mockOAuth2ClientApplicationDTO.getAccessTokenValidationResponse()).thenReturn(mockOAuth2TokenValidationResponseDTO);

        mockOrganizationManager = mock(OrganizationManager.class);
        OrganizationSwitchGrantDataHolder.getInstance().setOrganizationManager(mockOrganizationManager);
        mockOrgApplicationManager = mock(OrgApplicationManager.class);
        OrganizationSwitchGrantDataHolder.getInstance().setOrgApplicationManager(mockOrgApplicationManager);
        mockApplicationManagementService = mock(ApplicationManagementService.class);
        OrganizationSwitchGrantDataHolder.getInstance().setApplicationManagementService(mockApplicationManagementService);

        mockApplicationBasicInfo = mock(ApplicationBasicInfo.class);
        when(mockOAuthAppDO.getApplicationName()).thenReturn(APPLICATION_NAME);
        when(mockApplicationManagementService.getApplicationBasicInfoByName(anyString(),anyString())).thenReturn(mockApplicationBasicInfo);
        when(mockApplicationBasicInfo.getApplicationResourceId()).thenReturn(APPLICATION_ID);
    }

    @BeforeMethod
    public void init() {

        oAuth2AccessTokenReqDTO = mock(OAuth2AccessTokenReqDTO.class);
        oAuthTokenReqMessageContext = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        oAuthTokenReqMessageContext.addProperty("OAuthAppDO", mockOAuthAppDO);
        organizationSwitchGrant = new OrganizationSwitchGrant();
        RequestParameter[] requestParameters = new RequestParameter[2];
        requestParameters[0] = new RequestParameter(OrganizationSwitchGrantConstants.Params.ORG_PARAM, SWITCHING_ORG_ID);
        requestParameters[1] = new RequestParameter(OrganizationSwitchGrantConstants.Params.TOKEN_PARAM, ACCESS_TOKEN);
        when(oAuth2AccessTokenReqDTO.getRequestParameters()).thenReturn(requestParameters);
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = false;
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testWhenTokenIsInvalid() throws IdentityOAuth2Exception {

        organizationSwitchGrant.validateGrant(oAuthTokenReqMessageContext);
    }

    @Test(expectedExceptions = IdentityOAuth2ClientException.class)
    public void testWhenSwitchingOrgIsInvalid() throws IdentityOAuth2Exception, OrganizationManagementException {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(TOKEN_ISSUED_TENANT_DOMAIN)).thenReturn(TOKEN_ISSUED_ORG_ID);
        when(mockOrganizationManager.getRelativeDepthBetweenOrganizationsInSameBranch(TOKEN_ISSUED_ORG_ID, SWITCHING_ORG_ID)).thenReturn(-1);
        organizationSwitchGrant.validateGrant(oAuthTokenReqMessageContext);
    }

    @Test
    public void testSwitchSubOrgInSameTree()
            throws IdentityOAuth2Exception, OrganizationManagementException, UserIdNotFoundException {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(TOKEN_ISSUED_TENANT_DOMAIN)).thenReturn(TOKEN_ISSUED_ORG_ID);
        when(mockOrganizationManager.getRelativeDepthBetweenOrganizationsInSameBranch(TOKEN_ISSUED_ORG_ID, SWITCHING_ORG_ID)).thenReturn(1);
        when(mockAuthenticatedUser.getUserId()).thenReturn("12345");
        when(mockOrgApplicationManager.isApplicationSharedWithGivenOrganization(anyString(),anyString(),anyString())).
                thenReturn(true);
        organizationSwitchGrant.validateGrant(oAuthTokenReqMessageContext);
    }

    @Test
    public void testSwitchSameOrganization() throws IdentityOAuth2Exception, OrganizationManagementException {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(SWITCHING_ORG_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(anyString())).thenReturn(SWITCHING_ORG_ID);
        organizationSwitchGrant.validateGrant(oAuthTokenReqMessageContext);
    }

    @Test(expectedExceptions = IdentityOAuth2ClientException.class)
    public void testSwitchSubOrgInDifferentTree()
            throws OrganizationManagementException, IdentityOAuth2Exception {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(TOKEN_ISSUED_TENANT_DOMAIN)).thenReturn(TOKEN_ISSUED_ORG_ID);
        when(mockOrganizationManager.getRelativeDepthBetweenOrganizationsInSameBranch(TOKEN_ISSUED_ORG_ID, SWITCHING_ORG_ID)).thenReturn(-1);
        organizationSwitchGrant.validateGrant(oAuthTokenReqMessageContext);
    }

    @Test(expectedExceptions = IdentityOAuth2ClientException.class)
    public void testSwitchOrgWhereAppNotShared()
            throws OrganizationManagementException, IdentityOAuth2Exception {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(TOKEN_ISSUED_TENANT_DOMAIN)).thenReturn(TOKEN_ISSUED_ORG_ID);
        when(mockOrganizationManager.getRelativeDepthBetweenOrganizationsInSameBranch(TOKEN_ISSUED_ORG_ID, SWITCHING_ORG_ID)).thenReturn(1);
        when(mockOrgApplicationManager.isApplicationSharedWithGivenOrganization(anyString(),anyString(),anyString())).
                thenReturn(false);
        organizationSwitchGrant.validateGrant(oAuthTokenReqMessageContext);
    }

    @Test
    public void testSameBindingSetForSwitchedToken()
            throws OrganizationManagementException, UserIdNotFoundException, IdentityOAuth2Exception {

        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingReference(MOCK_TOKEN_BINDING_REFERENCE);
        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(TOKEN_ISSUED_TENANT_DOMAIN)).thenReturn(TOKEN_ISSUED_ORG_ID);
        when(mockOrganizationManager.getRelativeDepthBetweenOrganizationsInSameBranch(TOKEN_ISSUED_ORG_ID, SWITCHING_ORG_ID)).thenReturn(2);
        when(mockAuthenticatedUser.getUserId()).thenReturn("12345");
        when(mockAccessTokenDO.getTokenBinding()).thenReturn(tokenBinding);
        when(mockOrgApplicationManager.isApplicationSharedWithGivenOrganization(anyString(),anyString(),anyString())).
                thenReturn(true);
        organizationSwitchGrant.validateGrant(oAuthTokenReqMessageContext);
        assert MOCK_TOKEN_BINDING_REFERENCE.equals(
                ((TokenBinding) oAuthTokenReqMessageContext.getProperty(
                        TOKEN_BINDING_REFERENCE)).getBindingReference());
    }
}
