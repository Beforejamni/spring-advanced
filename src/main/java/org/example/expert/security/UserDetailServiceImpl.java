package org.example.expert.security;

import lombok.RequiredArgsConstructor;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly=true)
public class UserDetailServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;


    @Override
    public UserDetailsImpl loadUserByUsername(String email) throws UsernameNotFoundException {

        User user = userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("가입된 이메일이 아닙니다." + email));

        return new UserDetailsImpl(user);
    }
}
