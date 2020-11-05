package com.example.wallet.serrvices;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.Date;

public class AuthenticationService {
    static final long EXPIRATIONTIME = 864_000_00;
    static final String SINGINGKEY ="signingKey";
    static final String BEARER_PREFIX = "Bearer";

    static public void addJWTToken(HttpServletResponse response, String userName) {
        String JwtToken = Jwts.builder().setSubject(userName)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                .signWith(SignatureAlgorithm.ES512, SINGINGKEY)
                .compact();
        response.addHeader("Authorization", BEARER_PREFIX + " " + JwtToken);
        response.addHeader("Access-Control-Expose-Headers", "Authorization");
    }

    static public Authentication getAuthentication(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if (token != null) {
            String user = Jwts.parser()
                    .setSigningKey(SINGINGKEY)
                    .parseClaimsJws(token.replace(BEARER_PREFIX, ""))
                    .getBody()
                    .getSubject();

            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList());
            } else {
                throw new RuntimeException("Authentication failed");
            }
        }
        return null;
    }
}
