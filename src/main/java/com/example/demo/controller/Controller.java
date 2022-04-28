package com.example.demo.controller;

import com.example.demo.client.Client;
import com.example.demo.model.*;
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
        byte[] sessionKeyBytes = eService.decryptRequestFromKdc(tgt.getEncryptedByHashedPassword(), Arrays.copyOfRange(hashedKey, 0, 16), iv);
        SecondTGTPart secondTGTPart = objectMapper.readValue(sessionKeyBytes, SecondTGTPart.class);
        String sessionKey = secondTGTPart.getSessionKey();

        byte[] secondPart = eService.encryptDate(System.currentTimeMillis(), sessionKey.getBytes(StandardCharsets.UTF_8), iv);
        TGSc tgSc = client.authorisationToKDC(new AuthorisationRequestToKDC(tgt, secondPart));
        byte[] tgScPartByte = eService.decryptRequestFromKdc(tgSc.getTgSc_b(), sessionKey.getBytes(StandardCharsets.UTF_8), iv);
        TGScPart tgScPart = objectMapper.readValue(tgScPartByte, TGScPart.class);
        byte[] timestamp = eService.encryptDate(System.currentTimeMillis(), tgScPart.getTGS().getK_cs().getBytes(StandardCharsets.UTF_8), iv);
        RequestToServer requestToServer = new RequestToServer(timestamp, tgScPart.getTGSs().getE_sk_TGS());
        client.authRequestToServer(requestToServer);
        return toKDC;
    }
}
