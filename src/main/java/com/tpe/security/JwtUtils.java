package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {

    //jwt üretme ve doğrulama için gerekli olan metodlar
    //i-token : header(ALG+ TYPE) +
    //          payload(asıl verinin taşındığı bölüm,userla veya tokenla ilgili) +
    //          signature(şifreleme değildir, karşılaştırma yapılır)
    //ii-Bearer eyFGHJHM.dsf45vbhghk.chftyuFTYt
    //iii-Base64 ile kodlanarak gönderilir
    //iv-şifreleme değildir, içerisinde hassas bilgi(şifre) taşınmamalıdır.
    //v-jjwt kütüphanesinden yararlanarak gerekli işlemler yapılabilir


    //amaç:
    //1-jwt tokenı generate edelim
    private String secretKey="techpro";
    private long expirationTime=86400000;//24*60*60*1000

    public String generateToken(Authentication authentication){

        //username ve password ile doğrulanan userın bilgilerini
        //taşıyan authentication objesinin içinden userı alalım

        UserDetailsImpl user = (UserDetailsImpl) authentication.getPrincipal();

        //jjwt ile tokenı üretelim
        return Jwts.builder()//jwt oluşturucu getirir
                .setSubject(user.getUsername())//payload'a data ekleme
                .setIssuedAt(new Date())//System.currentMillis
                .setExpiration(new Date(new Date().getTime()+expirationTime))//+1 gün
                .signWith(SignatureAlgorithm.HS512,secretKey)
                //şifreleme değil, ancak key ile karşılaşatırma yapılır
                .compact();

    }



    //2-jwt tokenı doğrulama(validate)
    public boolean validateToken(String token){

        try {

            Jwts.parser()//ayrıştırıcı
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);//anahtar uyumlu ise token geçerli :true,

            return true;
        }catch (ExpiredJwtException e)// aksi halde exceptions fırlatılır :false
        {
            e.printStackTrace();
        }catch (UnsupportedJwtException e){
            e.printStackTrace();
        }catch (MalformedJwtException e){
            e.printStackTrace();
        }catch (SignatureException e){
            e.printStackTrace();
        }catch (IllegalArgumentException e){
            e.printStackTrace();
        }
        return false;

    }







    //3-jwt tokenıın içerisinden username i alma->user'a ulaşabilmek için
    public String getUsernameFromToken(String token){

        return Jwts.
                parser().
                setSigningKey(secretKey)
                .parseClaimsJws(token)//header,payload,signature
                .getBody().getSubject();//username

    }





}
