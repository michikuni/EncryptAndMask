/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.service.Impl;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.groupkma.EncryptAndMask.dto.PermissionDTO;
import com.groupkma.EncryptAndMask.entity.PermissionEntity;
import com.groupkma.EncryptAndMask.entity.UserEntity;
import com.groupkma.EncryptAndMask.repository.PermissionRepository;
import com.groupkma.EncryptAndMask.repository.UserRepository;
import com.groupkma.EncryptAndMask.security.RSA;
import com.groupkma.EncryptAndMask.service.PermissionService;
import com.groupkma.EncryptAndMask.util.JwtUtil;

import jakarta.transaction.Transactional;

/**
 *
 * @author minhp
 */
@Service
@Transactional
public class PermissionServiceImpl implements PermissionService {
        @Autowired
        private PermissionRepository repository;

        @Autowired
        private UserRepository userRepository;

        @Autowired
        private ModelMapper mapper;

        @Autowired
        private RSA rsa;

        @Autowired
        private JwtUtil jwtUtil;

        @Override
        public PermissionDTO findAll() {
                PermissionDTO response;
                List<PermissionEntity> entities = repository.findAll();
                if (entities.isEmpty()) {
                        response = PermissionDTO.builder()
                                        .mes("Thất bại")
                                        .success(false)
                                        .build();
                } else {
                        response = PermissionDTO.builder()
                                        .mes("Thành công")
                                        .success(true)
                                        .dtos(entities.stream()
                                                        .map(entity -> mapper.map(entity, PermissionDTO.class))
                                                        .collect(Collectors.toList()))
                                        .build();
                }
                return response;
        }

        @Override
        public PermissionDTO findAllByIdMain(String idMain) {
                PermissionDTO response;
                List<PermissionEntity> entities = repository.findByEntityMain_citizenIdentificationNumber(idMain);
                if (entities.isEmpty()) {
                        response = PermissionDTO.builder()
                                        .mes("Thất bại")
                                        .success(false)
                                        .build();
                } else {
                        response = PermissionDTO.builder()
                                        .mes("Thành công")
                                        .success(true)
                                        .listDataUserAuthorizations(entities.stream()
                                                        .map(entity -> PermissionDTO.builder().id_main(entity
                                                                        .getEntityMain()
                                                                        .getCitizenIdentificationNumber())
                                                                        .id_others(entity.getEntityOther()
                                                                                        .getCitizenIdentificationNumber())
                                                                        .columnName(entity.getColumnName()).build())
                                                        .collect(Collectors.toList()))
                                        .build();
                }
                return response;
        }

        @Override
        public PermissionDTO delete(PermissionDTO dto) {
                PermissionDTO response;
                repository.deleteByEntityMain_citizenIdentificationNumberAndEntityOther_citizenIdentificationNumber(
                                dto.getId_main(), dto.getId_others());
                List<PermissionEntity> list = repository
                                .findByEntityMain_citizenIdentificationNumberAndEntityOther_citizenIdentificationNumber(
                                                dto.getId_main(), dto.getId_others());
                if (list.isEmpty()) {
                        response = PermissionDTO.builder()
                                        .mes("Thành công")
                                        .success(true)
                                        .build();
                } else {
                        response = PermissionDTO.builder()
                                        .mes("Thất bại")
                                        .success(false)
                                        .build();
                }
                return response;
        }

        @Override
        public PermissionDTO save(List<PermissionDTO> dataChange, String token) {
                PermissionDTO response;
                String id_other = "";
                String eKey = "";
                List<Long> ids = new ArrayList<>();
                for (PermissionDTO object : dataChange) {
                        if (!id_other.equals(object.getId_others())) {
                                id_other = object.getId_others();
                                Optional<UserEntity> entity = userRepository
                                                .findByCitizenIdentificationNumber(id_other);
                                eKey = rsa.encrypt(jwtUtil.extractPass(token), entity.get().getPublicKey());
                        }
                        PermissionEntity entity = PermissionEntity.builder()
                                        .entityMain(UserEntity.builder()
                                                        .citizenIdentificationNumber(object.getId_main()).build())
                                        .entityOther(UserEntity.builder()
                                                        .citizenIdentificationNumber(object.getId_others()).build())
                                        .columnName(object.getColumnName())
                                        .ekey(eKey)
                                        .build();
                        entity = repository.save(entity);
                        ids.add(entity.getId());
                }
                if (ids.size() != dataChange.size()) {
                        response = PermissionDTO.builder()
                                        .mes("Thất bại")
                                        .success(false)
                                        .build();
                } else {
                        response = PermissionDTO.builder()
                                        .mes("Thành công")
                                        .success(true)
                                        .build();
                }
                return response;
        }

        @Override
        public PermissionDTO update(PermissionDTO dto, String token) {
                PermissionDTO response;
                repository.deleteByEntityMain_citizenIdentificationNumberAndEntityOther_citizenIdentificationNumber(
                                dto.getId_main(), dto.getId_others());
                List<PermissionEntity> list = repository
                                .findByEntityMain_citizenIdentificationNumberAndEntityOther_citizenIdentificationNumber(
                                                dto.getId_main(), dto.getId_others());
                if (list.isEmpty()) {
                        String id_other = "";
                        String eKey = "";
                        List<Long> ids = new ArrayList<>();
                        for (PermissionDTO object : dto.getDataChange()) {
                                if (!id_other.equals(object.getId_others())) {
                                        id_other = object.getId_others();
                                        Optional<UserEntity> entity = userRepository
                                                        .findByCitizenIdentificationNumber(id_other);
                                        eKey = rsa.encrypt(jwtUtil.extractPass(token), entity.get().getPublicKey());
                                }
                                PermissionEntity entity = PermissionEntity.builder()
                                                .entityMain(UserEntity.builder()
                                                                .citizenIdentificationNumber(object.getId_main())
                                                                .build())
                                                .entityOther(UserEntity.builder()
                                                                .citizenIdentificationNumber(object.getId_others())
                                                                .build())
                                                .columnName(object.getColumnName())
                                                .ekey(eKey)
                                                .build();
                                entity = repository.save(entity);
                                ids.add(entity.getId());
                        }
                        if (ids.size() == dto.getDataChange().size()) {
                                response = PermissionDTO.builder()
                                                .mes("Thành công")
                                                .success(true)
                                                .build();
                        } else {
                                response = PermissionDTO.builder()
                                                .mes("Thất bại")
                                                .success(false)
                                                .build();
                        }
                } else {
                        response = PermissionDTO.builder()
                                        .mes("Thất bại")
                                        .success(false)
                                        .build();
                }

                return response;
        }

}
