package com.groupkma.EncryptAndMask;

import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
//import com.groupkma.EncryptAndMask.security.AES;

@SpringBootApplication
public class EncryptAndMaskApplication {
	public static void main(String[] args) {
//            AES aes = new AES("MySecretKey12345");
//            String plainText = "This is a secret message.";
//            System.out.println(plainText);
//            String encrypted = aes.encrypt(plainText);
//            System.out.println("Encrypted: " + encrypted);
//            String decrypted = aes.decrypt(encrypted);
//            System.out.println("Decrypted: " + decrypted);
            SpringApplication.run(EncryptAndMaskApplication.class, args);
	}
    @Bean
    public ModelMapper getModelMapper() {
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);
        return modelMapper;
    }
}
