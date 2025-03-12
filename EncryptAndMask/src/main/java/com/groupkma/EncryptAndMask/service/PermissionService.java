/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.service;

import java.util.List;
import com.groupkma.EncryptAndMask.dto.PermissionDTO;
/**
 *
 * @author minhp
 */
public interface PermissionService {
    PermissionDTO findAll();
    PermissionDTO findAllByIdMain(String idMain);
    PermissionDTO delete(PermissionDTO dto);
    PermissionDTO save(List<PermissionDTO> dataChange, String token);
    PermissionDTO update(PermissionDTO dto, String token);

}
