package com.amigoJWT.config;


import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
      http
              .csrf()
              .disable()
              .authorizeHttpRequests()
              //whitelist this
              .requestMatchers("/api/v1/auth/**")
              .permitAll()
              // this must be authenticated
              .anyRequest()
              .authenticated()
              .and()
              /*session management - (when we implement the filter we want a once per request filter means every request should be authenticated
              this means we should not store authentication state or session state (session must be state less - this will ensure that
              each request should be authenticated */
              .sessionManagement()
              .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
              .and()
              .authenticationProvider(authenticationProvider)
              .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
              //logout
              .logout()
              .logoutUrl("/api/vi/auth/logout")
              .addLogoutHandler(logoutHandler)
              .logoutSuccessHandler(
                      (request, response, authentication) ->
                      SecurityContextHolder.clearContext())
      ;

        return http.build();
    }

}
