package com.amigoJWT.config;

import com.amigoJWT.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.beans.Transient;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.lang.NonNull;

import java.io.IOException;

@Component
@RequiredArgsConstructor

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request, response);
            return;
        }
       /*when we make a call need to pass the  Jwt authentication token within the header so it should be within a header called
        authorization so what we need to do here is try to extract this header,The authentication header is part of our request */
              final String authHeader = request.getHeader("Authorization");
              final String jwt;
              final String userEmail;
              //if token is not correct then further process is stoped
              if(authHeader == null || !authHeader.startsWith("Bearer ")){
                  filterChain.doFilter(request,response);
                  return;
              }
              //extract the token from my authentication header
              jwt = authHeader.substring(7);
              //extract the userEmail from JWT
              userEmail = jwtService.extractUsername(jwt);
               /* here when our user email and the user is not authenticated,we get the user details from the database
                and then whether user is valid or not if the user and token is valid so we create an object of type a Usernamepasswordauthentication token we pass user details credentials
                and authorities as parameter and then we extend or reinforce this authentiction token with the details
                of our request and then we update the authentication token */
              //if user token is validate then check in the database
              if(userEmail != null && SecurityContextHolder.getContext().getAuthentication()== null){
                  UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                  //to check whether the token is expried or not
                  var isTokenValid =tokenRepository.findByToken(jwt)
                          .map(t-> !t.isExpired() && !t.isRevoked())
                          .orElse(false);
                  if(jwtService.isTokenValid(jwt,userDetails) && isTokenValid){
                      //this object is needed by spring and by security context on order to update our security context
                      UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                              userDetails,
                              null,
                              userDetails.getAuthorities()
                      );
                      authToken.setDetails(
                              new WebAuthenticationDetailsSource().buildDetails(request)
                      );
                      //to update in securtity context holder
                      SecurityContextHolder.getContext().setAuthentication(authToken);
                  }
              }
              filterChain.doFilter(request,response);
    }

}
