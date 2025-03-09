/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Builder;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonInclude;
/**
 *
 * @author minhp
 */

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDTO {
    private String citizenIdentificationNumber;
    private String name;
    private String password;
    private String bithday;
    private String email;
    private String phone;
    private String address;
    private String atm;
    private String publicKey;
    private String privateKey;
    private String token;
    private UserDTO individual;
    private List<UserDTO> listUserData;
    private Boolean success;
    private String mes;

}
