package com.example.demo.service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtTokenService {

    private String secretKey;

    private String getSecretKey(){
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGenerator.generateKey();
            System.out.println("Secret KeyYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY : " + secretKey.toString());
            System.out.println("Secret KeyYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY : " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating secret key", e);
        }
    }

    public JwtTokenService(){
        secretKey = getSecretKey();
    }

    private SecretKey getKey(){
        byte[] bas64Decoded = Base64.getDecoder().decode(secretKey);
        return Keys.hmacShaKeyFor(bas64Decoded);
    }
    public String generateJwtToken(String username, Collection<? extends GrantedAuthority> authorities) {
        String jwt = Jwts
                    .builder()
                    .issuer(username)
                    .subject(username)
                    .claim("username", username)
                    .claim("authorities", authorities.stream().map(auth -> auth.getAuthority()).collect(Collectors.joining(",")))
                    .issuedAt(new Date())
                    .expiration(new Date(new Date().getTime()+30*60*1000))
                    .signWith(getKey())
                    .compact();
        System.out.println("JWT TOKENNNNNNNNNN GENERATEEEEDDDDDDDDDDD IIIIIIIIISSSSSSSS ====== "+jwt);
        return jwt;
    }

    public String extractUsername(String jwtToken) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'extractUsername'");
    }

    public boolean validateToken(String jwtToken, UserDetails userDetails) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'validateToken'");
    }
    
}
