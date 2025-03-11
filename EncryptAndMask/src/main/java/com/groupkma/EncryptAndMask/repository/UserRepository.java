/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */

package com.groupkma.EncryptAndMask.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.groupkma.EncryptAndMask.entity.UserEntity;

/**
 *
 * @author minhp
 */
public interface UserRepository extends JpaRepository<UserEntity, String>{
    boolean existsByCitizenIdentificationNumber(String citizenIdentificationNumber);
    boolean existsByAtm(String atm);
    boolean existsByPhoneNumber(String phone);
    boolean existsByEmail(String email);
    Optional<UserEntity> findByCitizenIdentificationNumber(String citizenIdentificationNumber); 
}
