package com.example.demo.controller;

import com.example.demo.client.Client;
import com.example.demo.model.AuthenticationRequestToKDC;
import com.example.demo.model.SecondTGTPart;
import com.example.demo.model.TGT;
import com.example.demo.service.EncryptService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

@RestController
@RequestMapping("/authentication")
public class Controller {
    public EncryptService eService;
    public Client client;

    public Controller(EncryptService eService, Client client) {
        this.eService = eService;
        this.client = client;
    }

    @GetMapping("/client")
    public AuthenticationRequestToKDC startProcess() throws IllegalBlockSizeException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IOException {
        IvParameterSpec iv = new IvParameterSpec("qwertyuiopasdfgh".getBytes(StandardCharsets.UTF_8));
        byte[] hashedKey = eService.hashData("12345", "password");
        byte[] clientAuth = eService.encryptDate(System.currentTimeMillis(), Arrays.copyOfRange(hashedKey, 0, 16), iv);
        AuthenticationRequestToKDC toKDC = new AuthenticationRequestToKDC("login", "domain", clientAuth);
        TGT tgt = client.authenticateToKdc(toKDC);
        ObjectMapper objectMapper = new ObjectMapper();
        byte[] bytes = eService.decryptRequestFromKdc(tgt.getEncryptedByHashedPassword(), Arrays.copyOfRange(hashedKey, 0, 16), iv);
        SecondTGTPart secondTGTPart = objectMapper.readValue(bytes, SecondTGTPart.class);
        String sessionKey = secondTGTPart.getSessionKey();
        return toKDC;
    }
}
