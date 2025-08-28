package org.example.expert.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.auth.exception.AuthException;
import org.example.expert.domain.common.dto.AuthUser;
import org.example.expert.domain.common.exception.ServerException;
import org.example.expert.domain.user.enums.UserRole;
import org.example.expert.security.UserDetailServiceImpl;
import org.example.expert.security.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;

import java.util.Base64;
import java.util.Collection;
import java.util.Date;

@Slf4j(topic = "JwtUtil")
@Component
public class JwtUtil {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final long TOKEN_TIME = 60 * 60 * 1000L; // 60분

    @Value("${jwt.secret.key}")
    private String secretKey;
    private Key key;
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @PostConstruct
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        log.info("JWT key decoded length={}", bytes.length);
        key = Keys.hmacShaKeyFor(bytes);
    }

    public String createToken(Long userId, String email, UserRole userRole) {
        Date date = new Date();

        return BEARER_PREFIX +
                Jwts.builder()
                        .setSubject(String.valueOf(userId))
                        .claim("email", email)
                        .claim("userRole", userRole)
                        .setExpiration(new Date(date.getTime() + TOKEN_TIME))
                        .setIssuedAt(date) // 발급일
                        .signWith(key, signatureAlgorithm) // 암호화 알고리즘
                        .compact();
    }

    public String substringToken(String tokenValue) {
        if (StringUtils.hasText(tokenValue) && tokenValue.startsWith(BEARER_PREFIX)) {
            return tokenValue.substring(7);
        }
        throw new ServerException("Not Found Token");
    }




    public Claims extractClaims(String token) {

       try {
           return Jwts.parserBuilder()
                   .setSigningKey(key)
                   .build()
                   .parseClaimsJws(token)
                   .getBody();
       }catch (JwtException e) {
           throw new AuthException("유효하지 않은 토큰입니다.");
       }
    }

    public Authentication getAuthentication(String token, UserDetailServiceImpl userDetailService) {

        Claims claims = extractClaims(token);

        Long userId = Long.valueOf(claims.getSubject());
        String email = claims.get("email", String.class);

        UserDetailsImpl userDetailsImpl = userDetailService.loadUserByUsername(email);

        UserRole role = extractUserRoleFromUserAuthorities(userDetailsImpl.getAuthorities());

        AuthUser authUser = new AuthUser( userId, email, role);

        return new UsernamePasswordAuthenticationToken(authUser, null, userDetailsImpl.getAuthorities());

    }

    private UserRole extractUserRoleFromUserAuthorities(Collection<? extends GrantedAuthority> authorities) {


        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a-> a.startsWith("ROLE_"))
                .map(a -> a.substring(5))
                .map(String::toUpperCase)
                .map(UserRole::valueOf)
                .findFirst()
                .orElse(UserRole.USER);
    }
}
