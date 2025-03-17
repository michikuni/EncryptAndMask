package com.groupkma.EncryptAndMask.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    @GetMapping("/login")
    public String showLogin() {
        return "login"; // Trả về tên file login.html trong templates/
    }

    @GetMapping("/register")
    public String showRegister() {
        return "register";
    }

    @GetMapping("/home")
    public String showHome() {
        return "home";
    }
}