package com.tpe.dto;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Getter
@Setter
public class LoginUser {

    @NotBlank
    private String userName;

    @NotBlank
    @Size(min = 8)
    private String password;
}