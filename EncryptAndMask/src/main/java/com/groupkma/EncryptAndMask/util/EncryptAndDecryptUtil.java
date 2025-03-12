/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.groupkma.EncryptAndMask.dto.UserDTO;
import com.groupkma.EncryptAndMask.entity.PermissionEntity;
import com.groupkma.EncryptAndMask.entity.UserEntity;
import com.groupkma.EncryptAndMask.security.AES;
import com.groupkma.EncryptAndMask.security.RSA;
/**
 *
 * @author minhp
 */

@Component
public class EncryptAndDecryptUtil {
    @Autowired
    private AES aes;

    @Autowired
    private RSA rsa;

    public boolean checkPassword(UserEntity entity, UserDTO dto) {
        String decryptPassword = aes.decrypt(entity.getPassword(), dto.getPassword());
        return decryptPassword.equals(dto.getPassword());
    }

    public UserEntity encryptAll(UserEntity entity) {
        String iv = entity.getPassword();
        entity.setName(aes.encrypt(entity.getName(), iv));
        entity.setBirthday(aes.encrypt(entity.getBirthday(), iv));
        entity.setAddress(aes.encrypt(entity.getAddress(), iv));
        entity.setEmail(aes.encrypt(entity.getEmail(), iv));
        entity.setAtm(aes.encrypt(entity.getAtm(), iv));
        entity.setPhoneNumber(aes.encrypt(entity.getPhoneNumber(), iv));
        entity.setPassword(aes.encrypt(entity.getPassword(), iv));
        return entity;
    }

    public UserDTO decryptAll(UserEntity entity, UserDTO dto) {
        String iv = dto.getPassword();
        UserDTO newDTO = new UserDTO();
        newDTO.setCitizenIdentificationNumber(entity.getCitizenIdentificationNumber());
        newDTO.setName(aes.decrypt(entity.getName(), iv));
        newDTO.setBirthday(aes.decrypt(entity.getBirthday(), iv));
        newDTO.setAddress(aes.decrypt(entity.getAddress(), iv));
        newDTO.setEmail(aes.decrypt(entity.getEmail(), iv));
        newDTO.setAtm(aes.decrypt(entity.getAtm(), iv));
        newDTO.setPhoneNumber(aes.decrypt(entity.getPhoneNumber(), iv));
        newDTO.setPassword(aes.decrypt(entity.getPassword(), iv));
        return newDTO;
    }

    public UserDTO maskingData(UserEntity entity, String id) {
        String mask = "*******";
        UserDTO maskDTO = UserDTO.builder()
                            .citizenIdentificationNumber(entity.getCitizenIdentificationNumber())
                            .email(mask)
                            .address(mask)
                            .password(mask)
                            .phoneNumber(mask)
                            .birthday(mask)
                            .atm(mask)
                            .name(mask)
                            .build();
        if(!entity.getListMain().isEmpty()) {
            String iv = "";
            for (PermissionEntity permission : entity.getListMain()) {
                if(permission.getEntityOther().getCitizenIdentificationNumber().equals(id)) {
                    if(iv.equals("")) {
                        iv = rsa.decrypt(permission.getEkey(), permission.getEntityOther().getPrivateKey());
                    }
                    switch (permission.getColumnName()) {
                        case "name":
                            maskDTO.setName(aes.decrypt(entity.getName(), iv));
                            break;
                        case "address":
                            maskDTO.setAddress(aes.decrypt(entity.getAddress(), iv));
                            break;
                        case "phoneNumber":
                            maskDTO.setPhoneNumber(aes.decrypt(entity.getPhoneNumber(), iv));
                            break;
                        case "birthday":
                            maskDTO.setBirthday(aes.decrypt(entity.getBirthday(), iv));
                            break;	
                        case "email":
                            maskDTO.setEmail(aes.decrypt(entity.getEmail(), iv));
                            break;
                        case "password":
                            maskDTO.setPassword(aes.decrypt(entity.getPassword(), iv));
                            break;	
                        case "atm":
                            maskDTO.setAtm(aes.decrypt(entity.getAtm(), iv));
                            break;	
                    }
                }
            }
        }
        return maskDTO;
    }
}
