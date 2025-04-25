package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AuthTokenFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;

    private final UserDetailsService userDetailsService;

    //1-requestin içerisinden tokenı alalım
    //requestin headerını kontrol edelim , Authorization başlığından
    //tokenı String olarak alalım
    private String getTokenFromRequest(HttpServletRequest request){

        String header=request.getHeader("Authorization");//Bearer eyDFGDFH.DFGKLFGh.kdjdof
        if (StringUtils.hasText(header) && header.startsWith("Bearer ") ){
            return header.substring(7);
        }
        return null;
    }



    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        //1-tokenı requestten çekelim
        String token=getTokenFromRequest(request);

        try {

            //2-JWT tokenı doğrulama
            if (token != null && jwtUtils.validateToken(token)) {
                //3-token geçerli yani user login olabilir, giriş yapabilir
                //login olan usera username ile ulaşalım ki rollerini vs kontrol edebiliriz
                //tokendan username i alalım
                String username = jwtUtils.getUsernameFromToken(token);
                //username ile userı bulalım
                UserDetails user = userDetailsService.loadUserByUsername(username);

                //4-kimliklendirilmiş userı security contexte bırakalım
                //contexte authentication obje olarak set edilmelidir
                UsernamePasswordAuthenticationToken authenticated =
                        new UsernamePasswordAuthenticationToken(user,
                                null,//password
                                user.getAuthorities()
                        );
                SecurityContextHolder.getContext().setAuthentication(authenticated);

            }
        }catch (UsernameNotFoundException e){
            e.printStackTrace();
        }

        filterChain.doFilter(request,response); //buraya kadar tüm işlemler başarılı ise request i sonraki filtreye ilet
    }


}