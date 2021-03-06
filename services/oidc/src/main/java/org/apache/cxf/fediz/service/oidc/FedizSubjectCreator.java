/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cxf.fediz.service.oidc;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MultivaluedMap;

import org.w3c.dom.Element;

import org.apache.cxf.common.util.Base64UrlUtility;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FedizConstants;
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.provider.SubjectCreator;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.cxf.rs.security.oidc.idp.OidcUserSubject;
import org.apache.cxf.rt.security.crypto.CryptoUtils;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;


public class FedizSubjectCreator implements SubjectCreator {

    private String issuer;
    private long defaultTimeToLive = 3600L;
    private Map<String, String> supportedClaims = Collections.emptyMap();
    
    @Override
    public UserSubject createUserSubject(MessageContext mc, 
                                         MultivaluedMap<String, String> params) throws OAuthServiceException {
        Principal principal = mc.getSecurityContext().getUserPrincipal();
        
        if (!(principal instanceof FedizPrincipal)) {
            throw new OAuthServiceException("Unsupported Principal");
        }
        FedizPrincipal fedizPrincipal = (FedizPrincipal)principal; 
        
        // In the future FedizPrincipal will likely have JWT claims already prepared,
        // with IdToken being initialized here from those claims 
        OidcUserSubject oidcSub = new OidcUserSubject();
        oidcSub.setLogin(fedizPrincipal.getName());
     
        // Subject ID - a locally unique and never reassigned identifier allocated to the end user
        // REVISIT: 
        // Can it be allocated on per-session basis or is it something that is supposed to be created
        // by the authentication system (IDP/STS) once and reported every time a given user signs in ?
        oidcSub.setId(Base64UrlUtility.encode(CryptoUtils.generateSecureRandomBytes(16)));
        
        IdToken idToken = convertToIdToken(fedizPrincipal.getLoginToken(),
                                           oidcSub.getLogin(),
                                           oidcSub.getId(),
                                           fedizPrincipal.getClaims(),
                                           fedizPrincipal.getRoleClaims(),
                                           params.getFirst("claims"));
        oidcSub.setIdToken(idToken);
        // UserInfo can be populated and set on OidcUserSubject too.
        // UserInfoService will create it otherwise.
        
        return oidcSub;
    }
    
    private IdToken convertToIdToken(Element samlToken, 
            String subjectName,
            String subjectId,
            ClaimCollection claims,
            List<String> roles,
            String requestedClaims) {
        // The current SAML Assertion represents an authentication record.
        // It has to be translated into IdToken (JWT) so that it can be returned 
        // to client applications participating in various OIDC flows.
        
        IdToken idToken = new IdToken();
        
        //TODO: make the mapping between the subject name and IdToken claim configurable
        idToken.setPreferredUserName(subjectName);
        idToken.setSubject(subjectId);
        
        Assertion saml2Assertion = getSaml2Assertion(samlToken);
        if (saml2Assertion != null) {
            // issueInstant
            DateTime issueInstant = saml2Assertion.getIssueInstant();
            if (issueInstant != null) {
                idToken.setIssuedAt(issueInstant.getMillis() / 1000);
            }
        
            // expiryTime
            if (saml2Assertion.getConditions() != null) {
                DateTime expires = saml2Assertion.getConditions().getNotOnOrAfter();
                if (expires != null) {
                    idToken.setExpiryTime(expires.getMillis() / 1000);
                }
            }
        
            // authInstant
            if (!saml2Assertion.getAuthnStatements().isEmpty()) {
                DateTime authInstant = 
                saml2Assertion.getAuthnStatements().get(0).getAuthnInstant();
                idToken.setAuthenticationTime(authInstant.getMillis() / 1000L);
            }
        }
        // Check if default issuer, issuedAt and expiryTime values have to be set 
        if (issuer != null) {
            idToken.setIssuer(issuer);
        } else if (saml2Assertion != null) {
            Issuer assertionIssuer = saml2Assertion.getIssuer();
            if (assertionIssuer != null) {
                idToken.setIssuer(assertionIssuer.getValue());
            }
        }
        
        long currentTimeInSecs = System.currentTimeMillis() / 1000;
        if (idToken.getIssuedAt() == null) {
            idToken.setIssuedAt(currentTimeInSecs);
        }
        if (idToken.getExpiryTime() == null) {
            idToken.setExpiryTime(currentTimeInSecs + defaultTimeToLive);
        }
        
        // Additional claims requested
        List<String> requestedClaimsList = Collections.emptyList();
        if (requestedClaims != null && !supportedClaims.isEmpty()) {
            requestedClaimsList = Arrays.asList(requestedClaims.trim().split(" "));
        }
        
        // Map claims
        if (claims != null) {
            String firstName = null;
            String lastName = null;
            for (Claim c : claims) {
                if (!(c.getValue() instanceof String)) {
                    continue;
                }
                if (ClaimTypes.FIRSTNAME.equals(c.getClaimType())) {
                    idToken.setGivenName((String)c.getValue());
                    firstName = (String)c.getValue();
                } else if (ClaimTypes.LASTNAME.equals(c.getClaimType())) {
                    idToken.setFamilyName((String)c.getValue());
                    lastName = (String)c.getValue();
                } else if (ClaimTypes.EMAILADDRESS.equals(c.getClaimType())) {
                    idToken.setEmail((String)c.getValue());
                } else if (ClaimTypes.DATEOFBIRTH.equals(c.getClaimType())) {
                    idToken.setBirthDate((String)c.getValue());
                } else if (ClaimTypes.HOMEPHONE.equals(c.getClaimType())) {
                    idToken.setPhoneNumber((String)c.getValue());
                } else if (ClaimTypes.GENDER.equals(c.getClaimType())) {
                    idToken.setGender((String)c.getValue());
                } else if (ClaimTypes.WEB_PAGE.equals(c.getClaimType())) {
                    idToken.setWebsite((String)c.getValue());
                } else if (supportedClaims.containsKey(c.getClaimType().toString())
                    && requestedClaimsList.contains(supportedClaims.get(c.getClaimType().toString()))) {
                    idToken.setClaim(supportedClaims.get(c.getClaimType().toString()), (String)c.getValue());
                }
            
            }
            if (firstName != null && lastName != null) {
                idToken.setName(firstName + " " + lastName);
            }
        }
        
        if (roles != null && !roles.isEmpty() 
            && supportedClaims.containsKey(FedizConstants.DEFAULT_ROLE_URI.toString())
            && requestedClaimsList.contains(supportedClaims.get(FedizConstants.DEFAULT_ROLE_URI.toString()))) {
            if (roles.size() == 1) {
                idToken.setClaim(supportedClaims.get(FedizConstants.DEFAULT_ROLE_URI.toString()), roles.get(0));
            } else {
                idToken.setClaim(supportedClaims.get(FedizConstants.DEFAULT_ROLE_URI.toString()), roles);
            }
        }
    
        return idToken;
    }


    private Assertion getSaml2Assertion(Element samlToken) {
        // Should a null assertion lead to the exception ?
        try {
            SamlAssertionWrapper wrapper = new SamlAssertionWrapper(samlToken);
            return wrapper.getSaml2();
        } catch (WSSecurityException ex) {
            throw new OAuthServiceException("Error converting SAML token", ex);
        }
    
    }


    public void setIdTokenIssuer(String idTokenIssuer) {
        this.issuer = idTokenIssuer;
    }
    
    
    public void setIdTokenTimeToLive(long idTokenTimeToLive) {
        this.defaultTimeToLive = idTokenTimeToLive;
    }

    /**
     * Set a map of supported claims. The map is from a SAML ClaimType URI String to a claim value that is
     * sent in the claims parameter. So for example:
     * http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role -> role
     * If the token contains a the former, and the OpenId claims contains the latter, then the claim value
     * will be encoded in the IdToken using the latter key.
     */
    public void setSupportedClaims(Map<String, String> supportedClaims) {
        this.supportedClaims = supportedClaims;
    }

}
