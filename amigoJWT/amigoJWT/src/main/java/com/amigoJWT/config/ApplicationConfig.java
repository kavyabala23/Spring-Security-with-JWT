package com.amigoJWT.config;

import com.amigoJWT.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor //in case we have to inject something
public class ApplicationConfig {
     private final  UserRepository repository;
   @Bean
    public UserDetailsService userDetailsService() {

       return username -> repository.findByEmail(username)
               .orElseThrow(() -> new UsernameNotFoundException("User not found"));
   }
   //authenticationProvider is the data access object which is responsible to fetch the user details and also encode password etc

   @Bean
    public AuthenticationProvider authenticationProvider(){
       DaoAuthenticationProvider authProvider  = new DaoAuthenticationProvider();
       authProvider.setUserDetailsService(userDetailsService());
       authProvider.setPasswordEncoder(passwordEncoder());
       return authProvider;

   }
   @Bean
   public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{
       return config.getAuthenticationManager();

   }
    @Bean
    public PasswordEncoder passwordEncoder() {
       return new BCryptPasswordEncoder();
    }
}
