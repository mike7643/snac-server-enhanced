package com.ureca.snac.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ureca.snac.auth.filter.CustomLogoutFilter;
import com.ureca.snac.auth.filter.JWTFilter;
import com.ureca.snac.auth.filter.LoginFilter;
import com.ureca.snac.auth.oauth2.CustomAuthorizationRequestResolver;
import com.ureca.snac.auth.oauth2.CustomOAuth2FailHandler;
import com.ureca.snac.auth.oauth2.CustomOAuth2SuccessHandler;
import com.ureca.snac.auth.repository.RefreshRepository;
import com.ureca.snac.auth.service.AuthCookieService;
import com.ureca.snac.auth.service.CustomOAuth2UserService;
import com.ureca.snac.auth.service.TokenIssuer;
import com.ureca.snac.auth.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfigurationSource;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({AuthCookieProperties.class, OAuthRedirectProperties.class})
@RequiredArgsConstructor
public class SecurityConfig {

    private final JWTUtil jwtUtil;
    private final ObjectMapper objectMapper;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOAuth2SuccessHandler customOAuth2SuccessHandler;
    private final CustomOAuth2FailHandler customOAuth2FailHandler;
    private final CustomAuthorizationRequestResolver customAuthorizationRequestResolver;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configure and build the application's SecurityFilterChain using stateless sessions, CORS, OAuth2 login, and custom authentication/logout filters.
     *
     * @param refreshRepository        repository used to manage stored refresh tokens for logout handling
     * @param corsConfigurationSource  source for CORS configuration applied to the security chain
     * @param authenticationManager    authentication manager used by the login filter
     * @param tokenIssuer              service responsible for issuing authentication tokens during login
     * @param authCookieService        service for creating and clearing authentication cookies used by login and logout filters
     * @return                         the configured SecurityFilterChain
     * @throws Exception               if an error occurs while configuring or building the HttpSecurity
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           RefreshRepository refreshRepository,
                                           CorsConfigurationSource corsConfigurationSource,
                                           AuthenticationManager authenticationManager,
                                           TokenIssuer tokenIssuer,
                                           AuthCookieService authCookieService) throws Exception {

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .csrf((auth) -> auth.disable())
                .formLogin((auth) -> auth.disable())
                .httpBasic((auth) -> auth.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(customOAuth2SuccessHandler)
                        .failureHandler(customOAuth2FailHandler)
                        .userInfoEndpoint(userinfo -> userinfo
                                .userService(customOAuth2UserService))
                        .authorizationEndpoint(endpoint -> endpoint
                                .authorizationRequestResolver(customAuthorizationRequestResolver))
                )
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll());

        http
                .addFilterBefore(jwtFilter(), OAuth2AuthorizationRequestRedirectFilter.class)
                .addFilterAt(loginFilter(authenticationManager, tokenIssuer, authCookieService), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshRepository, authCookieService, objectMapper), LogoutFilter.class);

        return http.build();

    }

    /**
     * Create a JWT filter used to validate and parse JWTs from incoming requests.
     *
     * @return a JWTFilter that validates and parses JWTs from HTTP requests
     */
    private JWTFilter jwtFilter() {
        return new JWTFilter(objectMapper, jwtUtil);
    }

    /**
     * Creates a LoginFilter configured with the given AuthenticationManager, TokenIssuer, AuthCookieService, and the class's ObjectMapper.
     *
     * @param authenticationManager the AuthenticationManager used to authenticate login attempts
     * @param tokenIssuer the TokenIssuer used to issue tokens on successful authentication
     * @param authCookieService the AuthCookieService used to manage authentication cookies
     * @return a LoginFilter instance wired with the provided dependencies
     */
    private LoginFilter loginFilter(AuthenticationManager authenticationManager,
                                    TokenIssuer tokenIssuer,
                                    AuthCookieService authCookieService) {
        return new LoginFilter(authenticationManager, tokenIssuer, authCookieService, objectMapper);
    }
}
