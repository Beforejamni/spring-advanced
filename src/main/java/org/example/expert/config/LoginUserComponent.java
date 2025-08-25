package org.example.expert.config;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.example.expert.domain.auth.exception.AuthException;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Locale;

@RequiredArgsConstructor
@Component
public class LoginUserComponent {

    private final static String BEARER_TOKEN = "Bearer ";
    private final JwtUtil jwtUtil;

    public Long getUserId(HttpServletRequest request) {

        Claims claims = getClaims(request);

        return Long.valueOf(claims.getSubject());
    }



    public String getRole(HttpServletRequest request) {

        Claims claims = getClaims(request);

        Object ob = claims.get("userRole");

        if(ob == null){
            throw new AuthException("권한 정보가 없습니다.");
        }

        return hasRole(ob.toString());

    }



    private Claims getClaims(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(header == null || !header.startsWith(BEARER_TOKEN)) {
            throw new AuthException("인증된 토큰이 없습니다.");
        }

        String token = header.substring(BEARER_TOKEN.length());

        try{
            return  jwtUtil.extractClaims(token);

        } catch (JwtException e) {
            throw new AuthException("유효하지 않은 토큰입니다.");
        }
    }

    private String hasRole(String role) {

        String upperCase = role.toUpperCase();

        return upperCase.startsWith("ROLE_") ? upperCase : "ROLE_" + upperCase;
    }
}
