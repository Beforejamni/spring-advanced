package org.example.expert.config;



import lombok.RequiredArgsConstructor;
import org.example.expert.domain.auth.exception.AuthException;
import org.example.expert.domain.common.dto.AuthUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Locale;

@RequiredArgsConstructor
@Component
public class LoginUserComponent {

    private Authentication getAuth() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication == null || !authentication.isAuthenticated()) {

            throw  new AuthException("인증 정보가 없습니다.");
        }
        return  authentication;
    }

    public Long getUserId() {

        Authentication authentication = getAuth();

        Object principal = authentication.getPrincipal();

        if(principal instanceof AuthUser authUser) {
            return authUser.getId();
        }

        throw new AuthException("유효한 사용자가 아닙니다.");
    }


    public String getEmail() {

        Authentication authentication = getAuth();

        Object principal = authentication.getPrincipal();

        if(principal instanceof  AuthUser authUser) {

            return  authUser.getEmail();
        }

        throw new AuthException("유효한 사용자가 아닙니다.");
    }


    public String getRole() {

        Authentication authentication =getAuth();

        Object principal = authentication.getPrincipal();

        if(principal instanceof AuthUser authUser) {

            String role = authUser.getUserRole().name();

            return  role.startsWith("ROLE_") ? role : "ROLE_" + role;
        }

        throw  new AuthException("권한 정보가 없습니다.");
    }
}
