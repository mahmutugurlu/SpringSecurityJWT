package com.tpe.security.service;

import com.tpe.domain.User;
import com.tpe.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    //username ile DB den userı(bizim) getirip UserDetails'e dönüştürüp
    //return yapacağız.
        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

            User user =userRepository.findByUserName(username)
                    .orElseThrow(()->new UsernameNotFoundException("User is not found by username:"+username));



            return UserDetailsImpl.build(user);
        }


    }

