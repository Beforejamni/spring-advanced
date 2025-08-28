package org.example.expert.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.common.annotation.Admin;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;


@Slf4j
@Component
@RequiredArgsConstructor
public class AdminInterceptor implements HandlerInterceptor {


    private final LoginUserComponent loginUser;


    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        if(!(handler instanceof HandlerMethod handlerMethod)){
            return true;
        }


        Admin admin = AnnotatedElementUtils.findMergedAnnotation(handlerMethod.getMethod(), Admin.class);

        if(admin == null){

            admin = AnnotatedElementUtils.findMergedAnnotation(handlerMethod.getBeanType(), Admin.class);
        }

        if(admin == null) {
            return true;
        }

            Long userId = loginUser.getUserId();

            String role =  loginUser.getRole();

            if(role.equals("ROLE_ADMIN")) {
                return true;
            }

            log.warn("FORBIDDEN: path= {}, userId= {}, role = {}", request.getRequestURI(), userId, role);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "관리자만 접근이 가능합니다.");
            return false;

    }

}
