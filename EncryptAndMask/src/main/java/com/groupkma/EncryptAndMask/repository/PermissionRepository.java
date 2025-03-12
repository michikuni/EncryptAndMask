/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import com.groupkma.EncryptAndMask.entity.PermissionEntity;
/**
 *
 * @author minhp
 */
public interface PermissionRepository extends JpaRepository<PermissionEntity, Long>{
        
    List<PermissionEntity> findByEntityMain_citizenIdentificationNumber(String idMain);
    List<PermissionEntity> findByEntityMain_citizenIdentificationNumberAndEntityOther_citizenIdentificationNumber(String id_main, String id_other);
    void deleteByEntityMain_citizenIdentificationNumberAndEntityOther_citizenIdentificationNumber(String id_main, String id_others);

}
