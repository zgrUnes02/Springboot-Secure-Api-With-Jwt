package com.secure.securejwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private final static String SECRET_KEY = "054b0fed47c5b09f762c1108b5296cb0c695e505ecd8b0d43d01870228e628a8";

    // Function to extract the user email
    public String extractUserEmail(String token) {
        return extractClaim(token , Claims::getSubject) ;
    }

    // Extract single claim
    public <T> T extractClaim(String token , Function<Claims , T> claimsResolver) {
        final Claims claims = extractAllClaims(token) ;
        return claimsResolver.apply(claims) ;
    }

    // Generate token without claims
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>() , userDetails) ;
    }

    // Generate the token with claims
    public String generateToken(Map<String , Object> extractClaims , UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey() , SignatureAlgorithm.ES256)
                .compact() ;
    }

    // Extract all claims
    public Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJwt(token)
                .getBody() ;
    }

    // Get the sign in key
    public Key getSignInKey() {
        byte[] keyByte = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyByte);
    }
}
