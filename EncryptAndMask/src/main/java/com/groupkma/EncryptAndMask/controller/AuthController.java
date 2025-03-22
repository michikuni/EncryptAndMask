package com.groupkma.EncryptAndMask.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    @GetMapping("/signin")
    public String signin() {
        return "signin"; // Trả về tên file login.html trong templates/
    }

    @GetMapping("/signup")
    public String signup() {
        return "signup";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }
}