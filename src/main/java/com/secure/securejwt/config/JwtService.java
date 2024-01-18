package com.secure.securejwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

@Service
public class JwtService {

    private final static String SECRET_KEY = "054b0fed47c5b09f762c1108b5296cb0c695e505ecd8b0d43d01870228e628a8";

    // Function to extract the user email
    public String extractUserEmail(String token) {
        return extractClaim(token , Claims::getSubject) ;
    }

    public <T> T extractClaim(String token , Function<Claims , T> claimsResolver) {
        final Claims claims = extractAllClaims(token) ;
        return claimsResolver.apply(claims) ;
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJwt(token)
                .getBody() ;
    }

    private Key getSignInKey() {
        byte[] keyByte = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyByte);
    }
}
