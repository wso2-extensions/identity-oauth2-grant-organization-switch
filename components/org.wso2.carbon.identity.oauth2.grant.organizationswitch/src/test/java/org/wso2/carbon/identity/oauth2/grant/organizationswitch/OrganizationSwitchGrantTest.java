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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
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
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantConstants.IMPERSONATED_SUBJECT;
import static org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantConstants.IMPERSONATING_ACTOR;
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
    private static final String IMPERSONATOR_ID = "8122e3de-0f3b-4b0e-a43a-d0c237451b7a";
    private static final String IMPERSONATED_SUBJECT_ID ="d9982d93-4e73-4565-b7ac-3605e8d05f80";

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
    private TenantManager mockTenantManager;
    private RealmService mockRealmService;
    private MockedStatic<OAuth2Util> mockedOAuth2Util;
    private MockedStatic<Utils> mockOrgUtil;
    private MockedStatic<IdentityTenantUtil> mockIdentityTenantUtil;
    private MockedStatic<OAuthServerConfiguration> mockOAuthServerConfig;

    @BeforeClass
    public void setup() throws Exception {

        mockAccessTokenDO = mock(AccessTokenDO.class);
        mockAuthenticatedUser = mock(AuthenticatedUser.class);
        mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
        mockOrgUtil = Mockito.mockStatic(Utils.class);
        mockIdentityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
        mockedOAuth2Util.when(() -> OAuth2Util.findAccessToken(nullable(String.class), anyBoolean()))
                .thenReturn(mockAccessTokenDO);
        mockOrgUtil.when(Utils::getSubOrgStartLevel).thenReturn(2);
        mockIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(nullable(String.class))).thenReturn(1);

        mockOAuth2TokenValidationService = mock(OAuth2TokenValidationService.class);
        mockOAuth2ClientApplicationDTO = mock(OAuth2ClientApplicationDTO.class);
        mockOAuthAppDO = mock(OAuthAppDO.class);
        mockOAuth2TokenValidationResponseDTO = mock(OAuth2TokenValidationResponseDTO.class);
        OrganizationSwitchGrantDataHolder.getInstance()
                .setOAuth2TokenValidationService(mockOAuth2TokenValidationService);
        when(mockOAuth2TokenValidationService.findOAuthConsumerIfTokenIsValid(any())).thenReturn(
                mockOAuth2ClientApplicationDTO);
        when(mockOAuth2ClientApplicationDTO.getAccessTokenValidationResponse()).thenReturn(
                mockOAuth2TokenValidationResponseDTO);

        mockOrganizationManager = mock(OrganizationManager.class);
        OrganizationSwitchGrantDataHolder.getInstance().setOrganizationManager(mockOrganizationManager);
        when(mockOrganizationManager.isOrganizationExistById(anyString())).thenReturn(true);

        mockOrgApplicationManager = mock(OrgApplicationManager.class);
        OrganizationSwitchGrantDataHolder.getInstance().setOrgApplicationManager(mockOrgApplicationManager);
        mockApplicationManagementService = mock(ApplicationManagementService.class);
        OrganizationSwitchGrantDataHolder.getInstance()
                .setApplicationManagementService(mockApplicationManagementService);

        mockApplicationBasicInfo = mock(ApplicationBasicInfo.class);
        when(mockOAuthAppDO.getApplicationName()).thenReturn(APPLICATION_NAME);
        when(mockApplicationManagementService.getApplicationBasicInfoByName(anyString(), anyString())).thenReturn(
                mockApplicationBasicInfo);
        when(mockApplicationBasicInfo.getApplicationResourceId()).thenReturn(APPLICATION_ID);

        mockRealmService = mock(RealmService.class);
        mockTenantManager = mock(TenantManager.class);
        OrganizationSwitchGrantDataHolder.getInstance().setRealmService(mockRealmService);
        when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
        when(mockTenantManager.isTenantActive(anyInt())).thenReturn(true);
        when(mockAccessTokenDO.getTokenType()).thenReturn("APPLICATION_USER");

    }

    @BeforeMethod
    public void init() {

        oAuth2AccessTokenReqDTO = mock(OAuth2AccessTokenReqDTO.class);
        oAuthTokenReqMessageContext = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        oAuthTokenReqMessageContext.addProperty("OAuthAppDO", mockOAuthAppDO);
        organizationSwitchGrant = new OrganizationSwitchGrant();
        mockOAuthServerConfig = Mockito.mockStatic(OAuthServerConfiguration.class);
        RequestParameter[] requestParameters = new RequestParameter[2];
        requestParameters[0] = new RequestParameter(OrganizationSwitchGrantConstants.Params.ORG_PARAM, SWITCHING_ORG_ID);
        requestParameters[1] = new RequestParameter(OrganizationSwitchGrantConstants.Params.TOKEN_PARAM, ACCESS_TOKEN);
        when(oAuth2AccessTokenReqDTO.getRequestParameters()).thenReturn(requestParameters);
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = false;
    }

    @AfterMethod
    public void tearDown() {

        if (mockOAuthServerConfig != null) {
            mockOAuthServerConfig.close();
        }
    }

    @DataProvider
    public Object[][] provideTokenTypes() {

        return new Object[][]{
                {OAuthConstants.UserType.APPLICATION_USER, true},
                {OAuthConstants.UserType.APPLICATION, false}
        };
    }

    @DataProvider
    public Object[][] provideRefreshTokenAllowedPropertyValues() {

        return new Object[][]{
                {true},
                {false}
        };
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
        when(mockOrganizationManager.resolveOrganizationId(SWITCHING_ORG_ID)).thenReturn(SWITCHING_ORG_TENANT_DOMAIN);
        when(mockOrganizationManager.getRelativeDepthBetweenOrganizationsInSameBranch(TOKEN_ISSUED_ORG_ID,
                SWITCHING_ORG_ID)).thenReturn(-1);
        organizationSwitchGrant.validateGrant(oAuthTokenReqMessageContext);
    }

    @Test(expectedExceptions = IdentityOAuth2ClientException.class)
    public void testWhenSwitchingOrgIsInactive()
            throws OrganizationManagementException, IdentityOAuth2Exception, UserStoreException {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(TOKEN_ISSUED_TENANT_DOMAIN)).thenReturn(TOKEN_ISSUED_ORG_ID);
        when(mockOrganizationManager.resolveOrganizationId(SWITCHING_ORG_ID)).thenReturn(SWITCHING_ORG_TENANT_DOMAIN);
        when(mockTenantManager.isTenantActive(anyInt())).thenReturn(false);
        organizationSwitchGrant.validateGrant(oAuthTokenReqMessageContext);
    }

    @Test
    public void testSwitchSubOrgInSameTree()
            throws IdentityOAuth2Exception, OrganizationManagementException, UserIdNotFoundException {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(TOKEN_ISSUED_TENANT_DOMAIN)).thenReturn(TOKEN_ISSUED_ORG_ID);
        when(mockOrganizationManager.resolveOrganizationId(SWITCHING_ORG_ID)).thenReturn(SWITCHING_ORG_TENANT_DOMAIN);
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
        when(mockOrganizationManager.resolveOrganizationId(SWITCHING_ORG_ID)).thenReturn(SWITCHING_ORG_TENANT_DOMAIN);
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
        when(mockOrganizationManager.resolveOrganizationId(SWITCHING_ORG_ID)).thenReturn(SWITCHING_ORG_TENANT_DOMAIN);
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
        when(mockOrganizationManager.resolveOrganizationId(SWITCHING_ORG_ID)).thenReturn(SWITCHING_ORG_TENANT_DOMAIN);
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

    @Test
    public void testImpersonationAccessTokenSwitch() throws IdentityOAuth2Exception, OrganizationManagementException,
            NoSuchAlgorithmException, JOSEException {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(TOKEN_ISSUED_TENANT_DOMAIN)).thenReturn(TOKEN_ISSUED_ORG_ID);
        when(mockOrganizationManager.getRelativeDepthBetweenOrganizationsInSameBranch(TOKEN_ISSUED_ORG_ID, SWITCHING_ORG_ID)).thenReturn(1);
        when(mockOrgApplicationManager.isApplicationSharedWithGivenOrganization(anyString(),anyString(),anyString())).
                thenReturn(true);
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn("carbon.super");
        mockedOAuth2Util.when(() -> OAuth2Util.getIdTokenIssuer("carbon.super"))
                .thenReturn("https://localhost:9443/oauth2/token");


        RequestParameter[] requestParameters = new RequestParameter[2];
        requestParameters[0] = new RequestParameter(OrganizationSwitchGrantConstants.Params.ORG_PARAM, SWITCHING_ORG_ID);
        requestParameters[1] = new RequestParameter(OrganizationSwitchGrantConstants.Params.TOKEN_PARAM,
                getImpersonatedAccessToken().serialize());
        when(oAuth2AccessTokenReqDTO.getRequestParameters()).thenReturn(requestParameters);
        Assert.assertTrue(organizationSwitchGrant.validateGrant(oAuthTokenReqMessageContext));
        Assert.assertNotNull(oAuthTokenReqMessageContext.getProperty(IMPERSONATING_ACTOR), IMPERSONATOR_ID);
        Assert.assertNotNull(oAuthTokenReqMessageContext.getProperty(IMPERSONATED_SUBJECT), IMPERSONATED_SUBJECT_ID);
    }

    @Test(dataProvider = "provideTokenTypes")
    void testIssueRefreshTokenWithBlankPropertyInConfigs(String tokenType, boolean expectedValue) throws Exception {

        OAuthServerConfiguration config = mock(OAuthServerConfiguration.class);
        mockOAuthServerConfig.when(OAuthServerConfiguration::getInstance).thenReturn(config);
        when(config.getValueForIsRefreshTokenAllowed(anyString(), any())).thenReturn("");

        boolean result = organizationSwitchGrant.issueRefreshToken(tokenType);
        Assert.assertEquals(result, expectedValue);
    }

    @Test(dataProvider = "provideRefreshTokenAllowedPropertyValues")
    void testIssueRefreshTokenWithPropertyInConfigs(boolean propertyValue) throws Exception {

        OAuthServerConfiguration config = mock(OAuthServerConfiguration.class);
        mockOAuthServerConfig.when(OAuthServerConfiguration::getInstance).thenReturn(config);
        when(config.getValueForIsRefreshTokenAllowed(anyString(), any())).thenReturn(String.valueOf(propertyValue));

        boolean result = organizationSwitchGrant.issueRefreshToken("any");
        Assert.assertEquals(result, propertyValue);
    }

    private SignedJWT getImpersonatedAccessToken() throws NoSuchAlgorithmException, JOSEException {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGenerator.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("KID").build();
        Instant currentTime = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("7N7vQHZbJtPnzegtGXJvvwDL4wca")
                .issuer("https://localhost:9443/oauth2/token")
                .subject(IMPERSONATED_SUBJECT_ID)
                .issueTime(Date.from(currentTime))
                .expirationTime(Date.from(Instant.ofEpochSecond(currentTime.getEpochSecond() + 36000)))
                .claim("scope", "default")
                .claim("aut", "APPLICATION_USER")
                .claim("azp", "7N7vQHZbJtPnzegtGXJvvwDL4wca")
                .claim("act", Collections.singletonMap("sub", IMPERSONATOR_ID))
                .notBeforeTime(Date.from(currentTime))
                .build();
        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJwt = new SignedJWT(jwsHeader, claims);
        signedJwt.sign(signer);
        return signedJwt;
    }
}
