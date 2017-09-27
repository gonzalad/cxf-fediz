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
package org.apache.cxf.fediz.service.idp.service.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.fediz.service.idp.domain.Entitlement;
import org.apache.cxf.fediz.service.idp.domain.Role;
import org.apache.cxf.fediz.service.idp.service.RoleDAO;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class GrantedAuthorityEntitlementsTest {

    private static final String ROLE_PREFIX = "ROLE_";
    private GrantedAuthorityEntitlements grantedAuthorityEntitlements;
    private RoleDAO roleDAOMock;
    private HttpServletRequest requestMock;
    private HttpServletResponse responseMock;
    private FilterChain filterChainMock;

    @Before
    public void setUp() {
        this.requestMock = mock(HttpServletRequest.class);
        this.responseMock = mock(HttpServletResponse.class);
        this.filterChainMock = mock(FilterChain.class);
        this.roleDAOMock = mock(RoleDAO.class);
        this.grantedAuthorityEntitlements = new GrantedAuthorityEntitlements();
        this.grantedAuthorityEntitlements.setRoleDAO(roleDAOMock);
        SecurityContextHolder.clearContext();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testPrincipal() throws IOException, ServletException {
        String claimListRoleName = "CLAIM_LIST";
        String claimEditRoleName = "CLAIM_EDIT";
        List<GrantedAuthority> grantedAuthorities = Arrays
            .<GrantedAuthority> asList(new SimpleGrantedAuthority(ROLE_PREFIX + claimListRoleName),
                                       new SimpleGrantedAuthority(ROLE_PREFIX + claimEditRoleName));
        setPrincipalInContext(new UsernamePasswordAuthenticationToken("user", "N/A", grantedAuthorities));

        when(roleDAOMock.getRole(eq(claimListRoleName), ArgumentMatchers.<String> anyList()))
            .thenReturn(claimCreateRole());
        when(roleDAOMock.getRole(eq(claimEditRoleName), ArgumentMatchers.<String> anyList()))
            .thenReturn(claimListRole());

        grantedAuthorityEntitlements.doFilter(requestMock, responseMock, filterChainMock);
        verify(roleDAOMock, times(2)).getRole(anyString(), ArgumentMatchers.<String> anyList());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        List<String> expectedAuthorityNames = new ArrayList<>();
        for (GrantedAuthority grantedAuthority : grantedAuthorities) {
            expectedAuthorityNames.add(grantedAuthority.getAuthority());
        }
        for (Role role : createRoles()) {
            for (Entitlement entl : role.getEntitlements()) {
                expectedAuthorityNames.add(entl.getName());
            }
        }
        Collections.sort(expectedAuthorityNames);
        List<String> actualAuthorityNames = new ArrayList<>();
        for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
            actualAuthorityNames.add(grantedAuthority.getAuthority());
        }
        Collections.sort(actualAuthorityNames);
        assertEquals(expectedAuthorityNames.size(), actualAuthorityNames.size());
    }

    @Test
    public void testNoPrincipal() throws IOException, ServletException {
        grantedAuthorityEntitlements.doFilter(requestMock, responseMock, filterChainMock);
        verify(roleDAOMock, times(0)).getRole(anyString(), ArgumentMatchers.<String> anyList());
    }

    @Test
    public void testAnonymousPrincipal() throws IOException, ServletException {
        setPrincipalInContext(new AnonymousAuthenticationToken("anonymousUser", "N/A", Collections
            .singletonList(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))));
        grantedAuthorityEntitlements.doFilter(requestMock, responseMock, filterChainMock);
        verify(roleDAOMock, times(0)).getRole(anyString(), ArgumentMatchers.<String> anyList());
    }

    private void setPrincipalInContext(Authentication authentication) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    private List<Role> createRoles() {
        return Arrays.asList(claimCreateRole(), claimListRole());
    }

    private Role claimCreateRole() {
        Role claimCreateRole = new Role();
        Entitlement entitlement = new Entitlement();
        entitlement.setName("claimCreateEntl1");
        claimCreateRole.getEntitlements().add(entitlement);
        entitlement = new Entitlement();
        entitlement.setName("claimCreateEntl2");
        claimCreateRole.getEntitlements().add(entitlement);
        return claimCreateRole;
    }

    private Role claimListRole() {
        Role claimListRole = new Role();
        Entitlement entitlement = new Entitlement();
        entitlement.setName("claimListEntl1");
        claimListRole.getEntitlements().add(entitlement);
        entitlement = new Entitlement();
        entitlement.setName("claimListEntl2");
        claimListRole.getEntitlements().add(entitlement);
        return claimListRole;
    }
}
