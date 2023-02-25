package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated();
//        http.formLogin();
//        http.httpBasic();
        http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> System.out.println("custom entryPoint"));
        return http.build();
    }

}
