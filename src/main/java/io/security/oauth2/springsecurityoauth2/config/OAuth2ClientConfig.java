package io.security.oauth2.springsecurityoauth2.config;

import io.security.oauth2.springsecurityoauth2.filter.CustomOAuth2AuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.Filter;

@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2ClientConfig {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final DefaultOAuth2AuthorizedClientManager defaultOAuth2AuthorizedClientManager;
    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authRequest -> authRequest.antMatchers("/", "/oauth2Login", "/client").permitAll()
                .anyRequest().authenticated());
//        http.oauth2Login(authLogin -> authLogin.authorizationEndpoint(
//                authEndpoint -> authEndpoint.authorizationRequestResolver(customOAuth2AuthorizationRequestResolver())
//        ));
        http.oauth2Client(Customizer.withDefaults());
        http.addFilterBefore(customOAuth2AuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    private Filter customOAuth2AuthenticationFilter() {
        CustomOAuth2AuthenticationFilter filter = new CustomOAuth2AuthenticationFilter(defaultOAuth2AuthorizedClientManager, oAuth2AuthorizedClientRepository);
        filter.setAuthenticationSuccessHandler((request, response, authentication) -> response.sendRedirect("/home"));
        return filter;
    }

    private OAuth2AuthorizationRequestResolver customOAuth2AuthorizationRequestResolver() {
        return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
    }

}
