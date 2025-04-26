package com.tpe.security.service;

import com.tpe.domain.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsImpl implements UserDetails {

    //HATIRLATMA:daha önce SpringBootIntro uygulamasında
    //SpringSecuritynin UserDetails i implemente ederek
    //oluşturduğu User classını hazır olarak kullanmıştık
    //bu defa kendimiz implemente ettik

    //SS nin istediği UserDetails objesini
    //kendimiz implemente ederek oluşturacağız
    //amaç: kendi userımız ---> UserDetails

    private Long id;
    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    /**
     * User nesnesini UserDetailsImpl nesnesine dönüştürür
     * @param user Dönüştürülecek User nesnesi
     * @return UserDetailsImpl nesnesi
     */
    public static UserDetailsImpl build(User user){
        //amaç: kendi userımız ---> UserDetails
        //userın rolleri var ama UserDetails GrantedAuthority
        List<SimpleGrantedAuthority> authorityList=
                user.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getType().name())).collect(Collectors.toList());

        return new UserDetailsImpl(user.getId(),user.getUserName(), user.getPassword(),authorityList );

    }


    /**
     * Kullanıcının yetkilerini döndürür
     * @return Kullanıcının yetkileri koleksiyonu
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    /**
     * Kullanıcının şifresini döndürür
     * @return Kullanıcı şifresi
     */
    @Override
    public String getPassword() {
        return this.password;
    }

    /**
     * Kullanıcının kullanıcı adını döndürür
     * @return Kullanıcı adı
     */
    @Override
    public String getUsername() {
        return this.username;
    }

    /**
     * Kullanıcı hesabının süresinin dolup dolmadığını kontrol eder
     * @return Hesap süresi dolmamışsa true, dolmuşsa false
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Kullanıcı hesabının kilitli olup olmadığını kontrol eder
     * @return Hesap kilitli değilse true, kilitliyse false
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Kullanıcı kimlik bilgilerinin süresinin dolup dolmadığını kontrol eder
     * @return Kimlik bilgileri süresi dolmamışsa true, dolmuşsa false
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Kullanıcı hesabının aktif olup olmadığını kontrol eder
     * @return Hesap aktifse true, değilse false
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}