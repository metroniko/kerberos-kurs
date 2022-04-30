package com.example.demo.controller;

import com.example.demo.client.Client;
import com.example.demo.model.*;
import com.example.demo.service.EncryptService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;

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

    private String K_cs;

    private IvParameterSpec iv;

    public Controller(EncryptService eService, Client client) {
        this.eService = eService;
        this.client = client;
        iv = new IvParameterSpec("qwertyuiopasdfgh".getBytes(StandardCharsets.UTF_8));
    }

    @GetMapping("/client")
    public AuthenticationRequestToKDC startProcess() throws IllegalBlockSizeException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IOException {
        System.out.println("Клиент начинает формировать запрос на аунтетификацию к KDC");
        iv = new IvParameterSpec("qwertyuiopasdfgh".getBytes(StandardCharsets.UTF_8));
        byte[] hashedKey = eService.hashData("12345", "password");
        System.out.println("Захешированный ключ: " + Arrays.toString(hashedKey) + " с помощью которого будет шифроваться время");
        byte[] clientAuth = eService.encryptDate(System.currentTimeMillis(), Arrays.copyOfRange(hashedKey, 0, 16), iv);
        System.out.println("Зашифрованное с помощью захешированного ключа время: " + Arrays.toString(clientAuth));
        AuthenticationRequestToKDC toKDC = new AuthenticationRequestToKDC("login", "domain", clientAuth);
        System.out.println("Запрос на KDC: " + toKDC);
        TGT tgt = client.authenticateToKdc(toKDC);
        System.out.println("Ответ от KDC - TGT: " + tgt);
        ObjectMapper objectMapper = new ObjectMapper();
        byte[] sessionKeyBytes = eService.decryptRequestFromKdc(tgt.getEncryptedByHashedPassword(), Arrays.copyOfRange(hashedKey, 0, 16), iv);
        SecondTGTPart secondTGTPart = objectMapper.readValue(sessionKeyBytes, SecondTGTPart.class);
        String sessionKey = secondTGTPart.getSessionKey();
        System.out.println("Сессионный ключ от KDC, с помощью которого будет зашифрованно время: " + sessionKey);
        byte[] secondPart = eService.encryptDate(System.currentTimeMillis(), sessionKey.getBytes(StandardCharsets.UTF_8), iv);
        System.out.println("Зашифрованное время с помощью сессионного ключа: "+ Arrays.toString(secondPart));
        TGSc tgSc = client.authorisationToKDC(new AuthorisationRequestToKDC(tgt, secondPart));
        byte[] tgScPartByte = eService.decryptRequestFromKdc(tgSc.getTgSc_b(), sessionKey.getBytes(StandardCharsets.UTF_8), iv);
        TGScPart tgScPart = objectMapper.readValue(tgScPartByte, TGScPart.class);
        System.out.println("Расшифрованное с помощью сессионного ключа TGSc - :" + tgScPart);
        System.out.println("Клиент-сервер сессионный ключ, с помощью коророго будет зашифрован запрос: " + tgScPart.getTGS().getK_cs());
        K_cs = tgScPart.getTGS().getK_cs();
        byte[] timestamp = eService.encryptDate(System.currentTimeMillis(), tgScPart.getTGS().getK_cs().getBytes(StandardCharsets.UTF_8), iv);
        RequestToServer requestToServer = new RequestToServer(timestamp, tgScPart.getTGSs().getE_sk_TGS());
        System.out.println("Запрос на сервер для авторизации и формировании зашифрованного канал связи");
        client.authRequestToServer(requestToServer);
        System.out.println("Канал установлен");
        return toKDC;
    }
    @PostMapping("/message")
    public void message(@RequestBody MessageDTO requestFromClient) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] bytes = eService.encryptString(requestFromClient.getMessage().getBytes(StandardCharsets.UTF_8), K_cs.getBytes(StandardCharsets.UTF_8), iv);
        Message message = new Message(bytes);
        client.message(message);
    }
}
