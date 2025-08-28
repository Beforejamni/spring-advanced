package org.example.expert.security;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.config.JwtUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final UserDetailServiceImpl userDetailServiceImpl;
    private final JwtUtil jwtUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if("POST".equalsIgnoreCase(request.getMethod())
                && ("/auth/signup".equals(request.getRequestURI())) || "/auth/signin".equals(request.getRequestURI())) {

            filterChain.doFilter(request, response);
            return;
        }

        String bearerJwt = request.getHeader("Authorization");

        if(!StringUtils.hasText(bearerJwt) || !bearerJwt.startsWith("Bearer ")) {

            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "JWT 토큰이 필요합니다.");
            return;
        }

           try {

               String token = jwtUtil.substringToken(bearerJwt);
               Authentication authentication = jwtUtil.getAuthentication(token, userDetailServiceImpl);
               SecurityContextHolder.getContext().setAuthentication(authentication);

               filterChain.doFilter(request, response);

           } catch (SecurityException | MalformedJwtException e) {
               log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.", e);
               response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "유효하지 않는 JWT 서명입니다.");

           } catch (ExpiredJwtException e) {
               log.error("Expired JWT token, 만료된 JWT token 입니다.", e);
               response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "만료된 JWT 토큰입니다.");

           } catch (UnsupportedJwtException e) {
               log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.", e);
               response.sendError(HttpServletResponse.SC_BAD_REQUEST, "지원되지 않는 JWT 토큰입니다.");

           } catch (Exception e) {
               log.error("Invalid JWT token, 유효하지 않는 JWT 토큰 입니다.", e);
               response.sendError(HttpServletResponse.SC_BAD_REQUEST, "유효하지 않는 JWT 토큰입니다.");
           }

       }




}
