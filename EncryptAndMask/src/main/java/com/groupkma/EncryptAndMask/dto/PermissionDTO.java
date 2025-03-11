/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.dto;


import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;    

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
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
public class PermissionDTO {
    
    private Long id;
	private UserDTO entityMain;
	private String columnName;
	private UserDTO entityOther;
	
	private String id_main;
	private String id_others;
	
	private Boolean success;
	private String mes;
	
	private List<PermissionDTO> dataChange;
	private List<PermissionDTO> dtos;
	
	private List<PermissionDTO> listDataUserAuthorizations;
        
}
