/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.api;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.groupkma.EncryptAndMask.dto.PermissionDTO;
import com.groupkma.EncryptAndMask.dto.UserDTO;
import com.groupkma.EncryptAndMask.service.PermissionService;
import com.groupkma.EncryptAndMask.service.UserService;

/**
 *
 * @author minhp
 */
@RestController
@RequestMapping("/api/user")
public class api {
    @Autowired
    private UserService userService;

    @Autowired
    private PermissionService permissionService;


    @PostMapping("/register")
	public ResponseEntity<UserDTO> register(@RequestBody UserDTO userDTO) {
		UserDTO response = userService.register(userDTO);
		if(response.getSuccess()) {
			return new ResponseEntity<UserDTO>(response , HttpStatus.OK);
		}else
			return new ResponseEntity<UserDTO>(response , HttpStatus.BAD_REQUEST);
	}
	
	@PostMapping("/login")
	public ResponseEntity<UserDTO> login(@RequestBody UserDTO userDTO) {
		UserDTO response = userService.login(userDTO);
		if(response.getSuccess()) {
			return new ResponseEntity<UserDTO>(response, HttpStatus.OK);
		}else
			return new ResponseEntity<UserDTO>(response , HttpStatus.BAD_REQUEST);
	}
	@PostMapping("/addDecentralization")
	public ResponseEntity<PermissionDTO> addDecentralization(@RequestBody List<PermissionDTO> dataChange, @RequestHeader("x-auth-token") String token) {
		PermissionDTO response = permissionService.save(dataChange, token);
		if(response.getSuccess()) {
			return new ResponseEntity<PermissionDTO>(response, HttpStatus.OK);
		}else 
			return new ResponseEntity<PermissionDTO>(response, HttpStatus.BAD_REQUEST);
	}

	@GetMapping("/getDecentralization/{id}")
	public ResponseEntity<PermissionDTO> getDecentralization(@PathVariable String id) {
		PermissionDTO response = permissionService.findAllByIdMain(id);
		return new ResponseEntity<PermissionDTO>(response, HttpStatus.OK);
	}
	
	@PutMapping("/updateDecentralization")
	public ResponseEntity<PermissionDTO> updatePermission(@RequestBody PermissionDTO dto, @RequestHeader("x-auth-token") String token) {
		PermissionDTO response = permissionService.update(dto, token);
		if(response.getSuccess()) {
			return new ResponseEntity<PermissionDTO>(response, HttpStatus.OK);
		}else 
			return new ResponseEntity<PermissionDTO>(response, HttpStatus.BAD_REQUEST);
	}
	
	@PostMapping("/deleteDecentralization")
	public ResponseEntity<PermissionDTO> deleteDecentralization(@RequestBody PermissionDTO dto) {
		PermissionDTO response = permissionService.delete(dto);
		if(response.getSuccess()) {
			return new ResponseEntity<PermissionDTO>(response, HttpStatus.OK);
		}else 
			return new ResponseEntity<PermissionDTO>(response, HttpStatus.BAD_REQUEST);
	}
	
	@GetMapping("/getDataUsers/{id}")
	public ResponseEntity<UserDTO> getAllUser(@PathVariable String id, @RequestHeader("x-auth-token") String token) {
		UserDTO response = userService.findAll(UserDTO.builder().citizenIdentificationNumber(id).token(token).build());
		if(response.getSuccess()) {
			return new ResponseEntity<UserDTO>(response, HttpStatus.OK);
		}else 
			return new ResponseEntity<UserDTO>(response, HttpStatus.BAD_REQUEST);
	}
	
	@GetMapping("/getInfPersonal/{id}")
	public ResponseEntity<UserDTO> getInfPersonal(@PathVariable String id, @RequestHeader("x-auth-token") String token) {
		UserDTO response = userService.findById(UserDTO.builder().citizenIdentificationNumber(id).token(token).build());
		if(response.getSuccess()) {
			return new ResponseEntity<UserDTO>(response, HttpStatus.OK);
		}else 
			return new ResponseEntity<UserDTO>(response, HttpStatus.BAD_REQUEST);
	}

	@PutMapping("/updateInfPersonal")
	public ResponseEntity<UserDTO> updateInfPersonal(@RequestBody UserDTO userDTO, @RequestHeader("x-auth-token") String token) {
		UserDTO response = userService.update(userDTO, token);
		if(response.getSuccess()) {
			return new ResponseEntity<UserDTO>(response, HttpStatus.OK);
		}else 
			return new ResponseEntity<UserDTO>(response, HttpStatus.BAD_REQUEST);
	}
	
	@PostMapping("/logout")
	public ResponseEntity<UserDTO> logout() {
		return new ResponseEntity<UserDTO>(new UserDTO(), HttpStatus.OK);
	}
	
}
