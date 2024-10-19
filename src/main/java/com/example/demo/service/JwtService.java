package com.example.demo.service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import io.jsonwebtoken.InvalidClaimException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtService {

    private String secret;

    private String generateSecret() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGenerator.generateKey();
            System.out.println("Secret KeyYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY : " + secretKey.toString());
            System.out.println("Secret KeyYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY : "
                    + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating secret key", e);
        }
    }

    public JwtService() {
        secret = generateSecret();
    }

    private SecretKey getSecretKey() {
        byte[] bas64Decoded =  Base64.getDecoder().decode(secret);
        return Keys.hmacShaKeyFor(bas64Decoded);
    }

    public String generateJwtToken(String username, Collection<? extends GrantedAuthority> authorities) {

        String jwt = Jwts
                .builder()
                .issuer(username)
                .subject(username)
                .claim("username", username)
                .claim("authorities",
                        authorities.stream().map(auth -> auth.getAuthority()).collect(Collectors.joining(",")))
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + 90 * 60 * 1000))
                .signWith(getSecretKey())
                .compact();

        return jwt;
    }

    public String extractUsername(String jwtToken) {

        String username = extractClaim(jwtToken, Claims::getSubject);

        return username;
    }

    public boolean validateToken(String jwtToken, UserDetails userDetails) {

        if (userDetails.getUsername().equals(extractUsername(jwtToken)) && isTokenValid(jwtToken)) {

            return true;
        }
        return false;
    }

    private boolean isTokenValid(String jwtToken) {
        return extractExpiration(jwtToken).after(new Date());
    }

    private Date extractExpiration(String jwtToken) {

        return extractClaim(jwtToken, Claims::getExpiration);
    }

    private <T> T extractClaim(String jwtToken, Function<Claims, T> claimResolver) {

        Claims claims = extractAllClaims(jwtToken);

        return claimResolver.apply(claims);
    }

    public Claims extractAllClaims(String jwtToken) throws InvalidClaimException {

        Claims claims =  Jwts
                        .parser()
                        .verifyWith(getSecretKey())
                        .build()
                        .parseSignedClaims(jwtToken)
                        .getPayload();

        return claims;
    }

}