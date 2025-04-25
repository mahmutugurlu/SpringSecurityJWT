package com.tpe.controller;

import com.tpe.dto.LoginUser;
import com.tpe.dto.UserDTO;
import com.tpe.security.JwtUtils;
import com.tpe.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    private final AuthenticationManager authenticationManager;

    private final JwtUtils jwtUtils;

    //userı kaydetme:register
    //request:http://localhost:8080/register + POST + Body
    /*
    { "firstName":"Ali",
      "lastName":"Can",
      "username":"alican",
      "password":"12345678"
    }
    */
    //response:save + 201 + mesaj
    @RequestMapping("/register")
    @PostMapping
    public ResponseEntity<String> registerUser(@Valid @RequestBody UserDTO userDTO){

        userService.saveUser(userDTO);

        return new ResponseEntity<>("User is registered successfully...", HttpStatus.CREATED);
    }

    //user login
    //request:http://localhost:8080/login + JSON body(username+password) + POST
    //response:authenticate(kimliklendirme)-->authentication
    //        :token üretip vereceğiz
    @RequestMapping("/login")
    @PostMapping
    public ResponseEntity<String> login(@Valid @RequestBody LoginUser loginUser){

        //username ve password ile doğrulama(kimliklendirme)
        Authentication authentication =authenticationManager.
                authenticate(new UsernamePasswordAuthenticationToken(loginUser.getUserName(),
                        loginUser.getPassword()));
        // authenticate : parametre olarak UsernamePasswordAuthenticationToken objesi alır
        //bu objenin isAuthenticated özelliği başlangıçta false'dur
        //eğer doğrulama başarılı ise metod geriye authentication return eder ve
        //isAuthenticated true olarak set edilir.

        String token= jwtUtils.generateToken(authentication);

        return new ResponseEntity<>(token,HttpStatus.CREATED);

    }


    @RequestMapping("/goodbye")
    @GetMapping
    @PreAuthorize("hasAnyRole('STUDENT','INSTRUCTOR','ADMIN')")
    public ResponseEntity<String> goodbye(){
        return ResponseEntity.ok("Goodbye Security:)");
    }
















}