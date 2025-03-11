/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import com.groupkma.EncryptAndMask.dto.UserDTO;

/**
 *
 * @author minhp
 */
public interface UserService extends UserDetailsService{
    UserDTO findById(UserDTO dto);
    UserDTO save(UserDTO dto);
    UserDTO findAll(UserDTO dto);
    UserDTO register(UserDTO dto);
    UserDTO login(UserDTO dto);
}
