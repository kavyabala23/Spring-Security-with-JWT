package com.amigoJWT.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${application.security.jwt.secret-key}")
    private  String secretKey;
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;


    public String extractUsername(String token) {

        return extractClaim(token,Claims::getSubject);
    }
    //extracting single claim
    public<T> T extractClaim(String token, Function<Claims ,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public  String generateToken(UserDetails userDetails) {

        return generateToken(new HashMap<>(),userDetails);
    }

    //to generate token
    public String generateToken(
            Map<String,Object> extraClaims,
            UserDetails userDetails
    ){
        return buildToken(extraClaims,userDetails,jwtExpiration);
    }
       //so to store additional information within my token
       public String generateRefreshToken(
               UserDetails userDetails
       ){
           return buildToken(new HashMap<>(), userDetails, refreshExpiration);
       }

    private String buildToken(
            Map<String,Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+ expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    //that validate the token,we userdetails to validate whether that user valid or not
    public boolean isTokenValid(String token,UserDetails userDetails){
        final String username =extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
   //to get expiration date for token
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) //to generate or decode a token we need a signing key
                .build()
                //after building we need to get the claims
                .parseClaimsJws(token)
                //then we have to get the body
                .getBody();

    }
    private Key getSignInKey(){
        byte[] keyBytes= Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
