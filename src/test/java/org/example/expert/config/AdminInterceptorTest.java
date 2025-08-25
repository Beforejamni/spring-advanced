package org.example.expert.config;


import jakarta.servlet.http.HttpServletRequest;
import org.example.expert.domain.comment.controller.CommentAdminController;
import org.example.expert.domain.comment.service.CommentAdminService;
import org.example.expert.domain.user.controller.UserAdminController;
import org.example.expert.domain.user.dto.request.UserRoleChangeRequest;
import org.example.expert.domain.user.service.UserAdminService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;


import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class AdminInterceptorTest {

    private MockMvc mockMvc;

    @Mock
    private LoginUserComponent loginUserComponent;

    @Mock
    private UserAdminService userAdminService;

    @Mock
    private CommentAdminService commentAdminService;


    @InjectMocks
    private AdminInterceptor adminInterceptor;

    @BeforeEach
    void setup() {

        UserAdminController userAdminController = new UserAdminController(userAdminService);

        CommentAdminController commentAdminController = new CommentAdminController(commentAdminService);

        this.mockMvc = MockMvcBuilders
                .standaloneSetup(userAdminController, commentAdminController)
                .addInterceptors(adminInterceptor)
                .build();

    }

    //관리자의 유저 상태 변환 기능

    @Test
    @DisplayName("ADMIN이면 200OK")
    void accessAdmin() throws Exception {


        when(loginUserComponent.getUserId(any(HttpServletRequest.class))).thenReturn(1L);

        when(loginUserComponent.getRole(any(HttpServletRequest.class))).thenReturn("ROLE_ADMIN");

        doNothing().when(userAdminService).changeUserRole(any(Long.class), any(UserRoleChangeRequest.class));

        mockMvc.perform(patch("/admin/users/{userid}", 31L)
                .header("Authorization", "Bearer dummy")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userRole\":\"ADMIN\"}"))
                .andExpect(status().isOk());

    }

    @Test
    @DisplayName("USER이면 403FOBIDDEN")
    void accessUser() throws Exception {

        when(loginUserComponent.getUserId(any(HttpServletRequest.class))).thenReturn(2L);

        when(loginUserComponent.getRole(any(HttpServletRequest.class))).thenReturn("ROLE_USER");

        mockMvc.perform(patch("/admin/users/{userid}", 31L)
                .header("Authorization","Bearer dummy")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userRole\":\"ADMIN\"}"))
                .andExpect(status().isForbidden());

    }

    //관리자 댓글 삭제 기능

    @Test
    @DisplayName("ADMIN이면 200OK")
    void accessAdminComment() throws  Exception {

        when(loginUserComponent.getUserId(any(HttpServletRequest.class))).thenReturn(1L);

        when(loginUserComponent.getRole(any(HttpServletRequest.class))).thenReturn("ROLE_ADMIN");

        doNothing().when(commentAdminService).deleteComment(anyLong());

        mockMvc.perform(delete("/admin/comments/{commentId}", 21L)
                .header("Authorization", "Bearer dummy"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("USER면 403FORBIDDEN")
    void accessUserComment() throws Exception {

        when(loginUserComponent.getUserId(any(HttpServletRequest.class))).thenReturn(2L);

        when(loginUserComponent.getRole(any(HttpServletRequest.class))).thenReturn("ROLE_USER");

        mockMvc.perform(delete("/admin/comments/{commentId}", 23L)
                        .header("Authorization", "Bearer dummy"))
                .andExpect(status().isForbidden());
    }

}
