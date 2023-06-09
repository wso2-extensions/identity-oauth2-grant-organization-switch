package org.wso2.carbon.identity.oauth2.grant.regionalswitch;

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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.grant.regionalswitch.exception.RegionalSwitchGrantServerException;
import org.wso2.carbon.identity.oauth2.grant.regionalswitch.internal.RegionalSwitchGrantDataHolder;
import org.wso2.carbon.identity.oauth2.grant.regionalswitch.util.RegionalSwitchGrantConstants;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import org.json.JSONObject;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import java.security.Signature;

import static org.wso2.carbon.identity.role.mgt.core.RoleConstants.Error.UNEXPECTED_SERVER_ERROR;

/**
 * Implements the AuthorizationGrantHandler for the RegionalSwitch grant type.
 */
public class RegionalSwitchGrant extends AbstractAuthorizationGrantHandler {

    private static final Log LOG = LogFactory.getLog(RegionalSwitchGrant.class);

    String publicKeyString = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzVUjynJaMmZtRFI170uA\n" +
            "ZknTiRbwg5/ery06gCXj/UD1F+98U76HPiVQ0np03PCWQViZaoIRbvTALk9jNzr0\n" +
            "YgBk9Z31/koUOX+ogaa3UQnfM0w5eUv+PuNRts+7K/3czPGMGxB8NpUEZDwluV5c\n" +
            "8slDWlSZvNqVySycYXlwViRzVY6QZoibtvrdLcnK4JbKP8j+sT/mWSxKW9hAugJ1\n" +
            "SIYznEWPeg5kS61KlH5UsKVAkaPy56K0WImC2WGe3o/0noJAsJm1DE6Bjnz3Y3fz\n" +
            "8nArrRosh6DEr2Iq50XBBFJFvbs8/wEnRvixaztnrvgfNfyyF0uqYn2QJjAhExxh\n" +
            "KQIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);

        String token = extractParameter(RegionalSwitchGrantConstants.Params.TOKEN_PARAM, tokReqMsgCtx);
        String environmentName = extractParameter(RegionalSwitchGrantConstants.Params.ENVIRONMENT_PARAM, tokReqMsgCtx);
        String username = "";
        String userId = null;
        // Parse the JWT token
        if (StringUtils.isNotEmpty(token)) {
            String[] jwtTokenPayload = token.split("\\.");
            String jwtTokenHeaderPayload = new String(Base64.getUrlDecoder().decode(jwtTokenPayload[0]), StandardCharsets.UTF_8);
            String jwtTokenPayloadJson = new String(Base64.getUrlDecoder().decode(jwtTokenPayload[1]), StandardCharsets.UTF_8);

//            verifyJWTSignature(jwtTokenPayload);

            JSONObject payload = new JSONObject(jwtTokenPayloadJson);
            String tenantedUsername = payload.getString("sub");
            System.out.println("Tenanted Username: " + tenantedUsername);
            username = payload.getString("username");
            System.out.println("The username: " + username);
            System.out.println("The username: " + username);

            JSONArray regionalUserAssociations = payload.getJSONArray("regional_user_associations");

            for (int i = 0; i < regionalUserAssociations.length(); i++) {
                JSONObject regionalUserAssociation = regionalUserAssociations.getJSONObject(i);
                JSONArray environments = regionalUserAssociation.getJSONArray("environments");

                for (int j = 0; j < environments.length(); j++) {
                    JSONObject environmentObject = environments.getJSONObject(j);
                    if (StringUtils.isNotEmpty(environmentName)
                            && environmentName.equalsIgnoreCase(environmentObject.getString("envName"))
                            && StringUtils.isNotEmpty(username)) {
                        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                        authenticatedUser.setUserName(username);
                        authenticatedUser.setUserStoreDomain("PRIMARY");
                        authenticatedUser.setTenantDomain(environmentObject.getString("envName"));
                        RealmService realmService = RegionalSwitchGrantDataHolder.getInstance().getRealmService();
                        int tenantId = 0;
                        AbstractUserStoreManager userStoreManager;
                        try {
                            tenantId = realmService.getTenantManager().getTenantId(authenticatedUser.getTenantDomain());
                            userStoreManager
                                    = (AbstractUserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
                            userId = userStoreManager.getUserIDFromUserName(authenticatedUser.getUserName());
                        } catch (UserStoreException e) {
                            String errorMessage = "Error while validating receiving userid of the user:" + username;
                            throw new RegionalSwitchGrantServerException(UNEXPECTED_SERVER_ERROR.getCode(),
                                    String.format(errorMessage), e);
                        }

                        authenticatedUser.setUserId(userId);

                        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);

                        String[] allowedScopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();
                        tokReqMsgCtx.setScope(allowedScopes);

                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Issuing an access token for user: " + authenticatedUser + " with scopes: " +
                                    Arrays.toString(tokReqMsgCtx.getScope()));
                        }
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private void verifyJWTSignature(String[] parts) throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        // Obtain the public key from the X.509 certificate in PEM format
        byte[] publicKeyBytes = publicKeyString.getBytes(StandardCharsets.UTF_8);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory
                .generateCertificate(new ByteArrayInputStream(publicKeyBytes));
        PublicKey publicKey = certificate.getPublicKey();

        Signature verifier = Signature.getInstance("SHA256withRSA");
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        verifier.initVerify(publicKey);
        verifier.update((parts[0] + "." + parts[1]).getBytes());
        boolean verified = verifier.verify(signature);
        if (verified) {
            System.out.println("Signature Verified");
        } else {
            System.out.println("Signature is not Verified");
        }
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
}
