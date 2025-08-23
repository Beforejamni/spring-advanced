package org.example.expert.domain.user.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.validation.annotation.Validated;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class UserChangePasswordRequest {

    @NotBlank
    private String oldPassword;
    @NotBlank
    @Pattern(regexp = ".*\\d.*", message = "숫자를 포함해야 합니다.")
    @Pattern(regexp = ".*[A-Z].*", message =  "대문자를 포함해야 합니다.")
    @Size(min = 8, message ="새 비밀번호는 8자 이상이어야 합니다" )
    private String newPassword;
}
