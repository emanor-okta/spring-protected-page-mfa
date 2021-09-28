package com.okta.example;

import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerificationException;
import com.okta.jwt.JwtVerifiers;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.*;

@SpringBootApplication
public class ProtectedPageMFAApplication {

    public static void main(String[] args) {
        SpringApplication.run(ProtectedPageMFAApplication.class, args);
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    static class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                // allow anonymous access to the root page
                .antMatchers("/").permitAll()

                // all other requests
                .anyRequest().authenticated()
                // After we logout, redirect to root page, by default Spring will send you to /login?logout
                .and().logout().logoutSuccessUrl("/")

                // enable OAuth2/OIDC
                .and().oauth2Login(oauth2 -> oauth2

                // setup custom authorities mapper to add 'groups' claims into Granted Authorities
                .userInfoEndpoint(userInfo -> userInfo
                        .userAuthoritiesMapper(this.userAuthoritiesMapper()))).oauth2Login();

            http.csrf().disable();
        }


        private GrantedAuthoritiesMapper userAuthoritiesMapper() {
            return (authorities) -> {
                Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

                authorities.forEach(authority -> {
                    if (OidcUserAuthority.class.isInstance(authority)) {
                        OidcUserAuthority oidcUserAuthority = (OidcUserAuthority)authority;
                        OidcIdToken idToken = oidcUserAuthority.getIdToken();
                        OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

                        // add 'groups' claim into Granted Authorities
                        for (String key : idToken.getClaims().keySet()) {
                            if (key.equalsIgnoreCase("groups")) {
                                for (String v : ((List<String>)idToken.getClaims().get(key))) {
                                    mappedAuthorities.add(new SimpleGrantedAuthority(v));
                                }
                            }
                        }
                        for (String key : userInfo.getClaims().keySet()) {
                            if (key.equalsIgnoreCase("groups")) {
                                for (String v : ((List<String>)userInfo.getClaims().get(key))) {
                                    mappedAuthorities.add(new SimpleGrantedAuthority(v));
                                }
                            }
                        }
                    } else if (OAuth2UserAuthority.class.isInstance(authority)) {
                        OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority)authority;
                        Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();
                        // Map the attributes found in userAttributes
                        // to one or more GrantedAuthority's and add it to mappedAuthorities
                        // No-Op
                    } else {
                        // add existing
                        mappedAuthorities.add(authority);
                    }
                });

                return mappedAuthorities;
            };
        }
    }



    @Controller
    static class SimpleController {
        private AccessTokenVerifier jwtVerifier;

        @Value("${spring.security.oauth2.client.provider.oktamfa.issuer-uri}")
        private String mfaIssuer;
        @Value("${spring.security.oauth2.client.provider.oktamfa.audience}")
        private String mfaAudience;
        @Value("${spring.security.oauth2.client.registration.oktamfa.client-id}")
        private String clientId;


        @ExceptionHandler(AccessDeniedException.class)
        public void handleAccessDeniedException(AccessDeniedException ex, HttpServletRequest req, HttpServletResponse resp) throws Exception {
            if (req.getRequestURI().equalsIgnoreCase("/admin")) {
                setRedirectCookie(resp);
                resp.sendRedirect("./oauth2/authorization/oktamfa");
            } else if (req.getRequestURI().equalsIgnoreCase("/admin2")) {
                resp.sendRedirect(mfaIssuer + "/v1/authorize?client_id=" + clientId +
                        "&response_type=token&response_mode=form_post&scope=openid%20admin&" +
                        "redirect_uri=" + req.getScheme()+"://"+req.getLocalName()+":"+req.getLocalPort() +
                        "/admin-callback&state=MyState&nonce=" + System.currentTimeMillis());
            } else {
                resp.sendRedirect(ex.getLocalizedMessage());
            }
        }


        @GetMapping("/")
        public String home(HttpServletRequest req, HttpServletResponse resp) {
            if (checkRedirectCookie(req, resp)) {
                return "admin"   ;
            } else{
                return "home";
            }
        }


        @GetMapping("/profile")
        public ModelAndView userDetails(OAuth2AuthenticationToken authentication) {
            return new ModelAndView("profile" , Collections.singletonMap("details", authentication.getPrincipal().getAttributes()));
        }


        @PreAuthorize("hasAuthority('SCOPE_admin')")
        @GetMapping(value={"/admin", "/admin2"})
        public String admin() { //HttpServletResponse resp, OAuth2AuthenticationToken authentication) {
            return "admin";
        }


        @PreAuthorize("hasAuthority('admin')")
        @PostMapping("/admin-callback")
        public void adminCallback(HttpServletRequest req, HttpServletResponse resp,
                                  @RequestParam("access_token") String token) throws  IOException {
            System.out.println(token);

            try {
                Jwt jwt = jwtVerifier.decode(token);
                if (!((List<String>)jwt.getClaims().get("scp")).contains("admin")) {
                    resp.sendRedirect("/");
                    return;
                }
            } catch (JwtVerificationException e) {
                e.printStackTrace();
                resp.sendRedirect("/");
                return;
            }


            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Set<GrantedAuthority> authorities = new HashSet<>();
            for (Object o : authentication.getAuthorities().toArray()) {
                authorities.add((GrantedAuthority) o);
            }
            authorities.add(new SimpleGrantedAuthority("SCOPE_admin"));
            OAuth2AuthenticationToken newAuth = new OAuth2AuthenticationToken((OAuth2User) authentication.getPrincipal(),
                    authorities,"okta");
            SecurityContextHolder.getContext().setAuthentication(newAuth);
            resp.sendRedirect("/admin");
        }

        @GetMapping("/login2")
        public void login(HttpServletResponse resp) throws IOException {
            resp.sendRedirect("/oauth2/authorization/okta");
        }

        // hidden route to debug authorities
        @GetMapping("/id")
        public String id(@AuthenticationPrincipal OidcUser user) {
            System.out.println(user);//.getUserInfo().getFullName());
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            System.out.println(authentication);
            System.out.println(authentication.getClass().getName());
            for (Object o : authentication.getAuthorities().toArray()) {
                System.out.println("    " + o);
            }
            return "home";
        }

        @PostConstruct
        public void init() {
            jwtVerifier = JwtVerifiers.accessTokenVerifierBuilder()
                    .setIssuer(mfaIssuer)
                    .setAudience(mfaAudience)           // defaults to 'api://default'
                    .setConnectionTimeout(Duration.ofSeconds(1))    // defaults to 1s
                    .setRetryMaxAttempts(2)                     // defaults to 2
                    .setRetryMaxElapsed(Duration.ofSeconds(10)) // defaults to 10s
                    .build();

        }

        private void setRedirectCookie(HttpServletResponse resp) {
            Cookie c = new Cookie("okta_context", "admin");
            c.setHttpOnly(true);
            c.setPath("/");
            resp.addCookie(c);
        }

        private boolean checkRedirectCookie(HttpServletRequest req, HttpServletResponse resp) {
            if (req.getCookies() != null) {
                for (Cookie c : req.getCookies()) {
                    if (c.getName().equalsIgnoreCase("okta_context") && c.getValue().equalsIgnoreCase("admin")) {
                        c.setMaxAge(0);
                        resp.addCookie(c);
                        return true;
                    }
                }
            }
            return false;
        }
    }
}