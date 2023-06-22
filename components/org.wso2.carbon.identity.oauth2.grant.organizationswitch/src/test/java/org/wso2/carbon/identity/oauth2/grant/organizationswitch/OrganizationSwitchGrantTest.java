package org.wso2.carbon.identity.oauth2.grant.organizationswitch;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
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
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;

import java.util.ArrayList;
import java.util.Arrays;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithCarbonHome
public class OrganizationSwitchGrantTest {

    private static final String TOKEN_ISSUED_ORG_ID = "90184a8d-113f-5211-a0d5-efe36b082233";
    private static final  String SWITCHING_ORG_ID = "70184a8d-113f-5211-ac0d5-efe39b082214";
    private static final String TOKEN_ISSUED_TENANT_DOMAIN = "EasyMeet";
    private static final String ACCESS_TOKEN = "a8fb49be-5a28-30bd-98ea-dad7b87d5d86";
    private OAuth2TokenValidationService mockOAuth2TokenValidationService;
    private OrganizationManager mockOrganizationManager;
    private OAuth2ClientApplicationDTO mockOAuth2ClientApplicationDTO;
    private OAuthTokenReqMessageContext mockOAuthTokenReqMessageContext;
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;
    private OAuth2TokenValidationResponseDTO mockOAuth2TokenValidationResponseDTO;
    private OrganizationSwitchGrant organizationSwitchGrant;
    private AccessTokenDO mockAccessTokenDO;
    private AuthenticatedUser mockAuthenticatedUser;
    private MockedStatic<OAuth2Util> mockedOAuth2Util;

    @BeforeClass
    public void setup() throws OrganizationManagementException {

        mockAccessTokenDO = mock(AccessTokenDO.class);
        mockAuthenticatedUser = mock(AuthenticatedUser.class);
        mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
        mockedOAuth2Util.when(() -> OAuth2Util.findAccessToken(nullable(String.class), anyBoolean())).thenReturn(mockAccessTokenDO);

        mockOAuth2TokenValidationService = mock(OAuth2TokenValidationService.class);
        mockOAuth2ClientApplicationDTO = mock(OAuth2ClientApplicationDTO.class);
        mockOAuth2TokenValidationResponseDTO = mock(OAuth2TokenValidationResponseDTO.class);
        OrganizationSwitchGrantDataHolder.getInstance().setOAuth2TokenValidationService(mockOAuth2TokenValidationService);
        when(mockOAuth2TokenValidationService.findOAuthConsumerIfTokenIsValid(any())).thenReturn(mockOAuth2ClientApplicationDTO);
        when(mockOAuth2ClientApplicationDTO.getAccessTokenValidationResponse()).thenReturn(mockOAuth2TokenValidationResponseDTO);

        mockOrganizationManager = mock(OrganizationManager.class);
        OrganizationSwitchGrantDataHolder.getInstance().setOrganizationManager(mockOrganizationManager);
    }

    @BeforeMethod
    public void init() {

        mockOAuthTokenReqMessageContext = mock(OAuthTokenReqMessageContext.class);
        oAuth2AccessTokenReqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(mockOAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        organizationSwitchGrant = new OrganizationSwitchGrant();

        RequestParameter[] requestParameters = new RequestParameter[2];
        requestParameters[0] = new RequestParameter(OrganizationSwitchGrantConstants.Params.ORG_PARAM,
                TOKEN_ISSUED_ORG_ID);
        requestParameters[1] = new RequestParameter(OrganizationSwitchGrantConstants.Params.TOKEN_PARAM, ACCESS_TOKEN);
        when(oAuth2AccessTokenReqDTO.getRequestParameters()).thenReturn(requestParameters);

    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testWhenTokenIsInvalid() throws IdentityOAuth2Exception {

        organizationSwitchGrant.validateGrant(mockOAuthTokenReqMessageContext);
    }

    @Test(expectedExceptions = IdentityOAuth2ClientException.class)
    public void testWhenSwitchingOrgIsInvalid() throws IdentityOAuth2Exception, OrganizationManagementServerException {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.getAncestorOrganizationIds(nullable(String.class))).thenReturn(new ArrayList<>());
        organizationSwitchGrant.validateGrant(mockOAuthTokenReqMessageContext);
    }

    @Test(expectedExceptions = IdentityOAuth2ClientException.class)
    public void testSwitchDifferentSubTree() throws IdentityOAuth2Exception, OrganizationManagementException {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(anyString())).thenReturn(TOKEN_ISSUED_ORG_ID);
        when(mockOrganizationManager.getAncestorOrganizationIds(nullable(String.class))).thenReturn(
                Arrays.asList("123", "456"));
        organizationSwitchGrant.validateGrant(mockOAuthTokenReqMessageContext);
    }

    @Test(expectedExceptions = IdentityOAuth2ClientException.class)
    public void testSwitchSameOrganization() throws IdentityOAuth2Exception, OrganizationManagementException {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(anyString())).thenReturn(TOKEN_ISSUED_ORG_ID);
        organizationSwitchGrant.validateGrant(mockOAuthTokenReqMessageContext);
    }

    @Test
    public void testSuccessfullySwitchToken()
            throws OrganizationManagementException, IdentityOAuth2Exception, UserIdNotFoundException {

        when(mockOAuth2TokenValidationResponseDTO.isValid()).thenReturn(true);
        when(mockAccessTokenDO.getAuthzUser()).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TOKEN_ISSUED_TENANT_DOMAIN);
        when(mockOrganizationManager.resolveOrganizationId(anyString())).thenReturn(SWITCHING_ORG_ID);
        when(mockOrganizationManager.getAncestorOrganizationIds(nullable(String.class))).thenReturn(
                Arrays.asList("12345", SWITCHING_ORG_ID));
        when(mockAuthenticatedUser.getUserId()).thenReturn("12345");
        organizationSwitchGrant.validateGrant(mockOAuthTokenReqMessageContext);
    }
}
