package com.example.kdc.client;

import com.example.kdc.model.*;
import com.example.kdc.service.EncryptService;
import com.example.kdc.storage.ClientStorage;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
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
import java.util.Date;
import java.util.Objects;

import static com.example.kdc.service.EncryptService.*;

@RestController
public class KDCController {
    private EncryptService eService;
    private ClientStorage storage;
    private IvParameterSpec iv;

    public KDCController(EncryptService encryptService, ClientStorage storage) {
        this.eService = encryptService;
        this.storage = storage;
        this.iv = new IvParameterSpec("qwertyuiopasdfgh".getBytes(StandardCharsets.UTF_8));
    }

    @PostMapping(path = "/kdc/auth", consumes = MediaType.APPLICATION_JSON_VALUE)
    private TGT authClient(@RequestBody AuthenticationRequestToKDC requestFromClient) throws InvalidAlgorithmParameterException,
            IllegalBlockSizeException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        System.out.println("Запрос от клиента на аунтетификацию: "+ requestFromClient);
        String password = storage.getLoginPasswordMap().get(requestFromClient.getLogin());
        String key = storage.getLoginKeyMap().get(requestFromClient.getLogin());
        byte[] hashedKey = eService.hashData(key, password);
        // Нужно проверить что временной идентификатор не протух
        System.out.println("Находим по логину и домену пароль и им расшифровываем дату");
        Date date = eService.decryptDate(requestFromClient.getEncryptedKey(), Arrays.copyOfRange(hashedKey, 0, 16), iv);
        System.out.println("Проверка по дате:" + date);
        TGT tgt = eService.buildTGT(requestFromClient.getLogin(), Arrays.copyOfRange(hashedKey, 0, 16), iv);
        System.out.println("Возвращаем TGT на клиент: " + tgt);
        return tgt;
    }

    @PostMapping(path = "/kdc/author", consumes = MediaType.APPLICATION_JSON_VALUE)
    private TGSc getToken(@RequestBody AuthorisationRequestToKDC authorisationRequestToKDC) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        System.out.println("Запрос на авторизацию от клиента: " + authorisationRequestToKDC);
        byte[] firstTgtPart = eService.decryptString(authorisationRequestToKDC.getTgt().getEncryptedByMasterKeyFields(), MASTER_KEY.getBytes(StandardCharsets.UTF_8), iv);
        ObjectMapper objectMapper = new ObjectMapper();
        FirstTGTPart firstTGTPart = objectMapper.readValue(firstTgtPart, FirstTGTPart.class);
        String sessionKey = firstTGTPart.getSessionKey();
        // про
        System.out.println("Проверка сессионного ключа: " + sessionKey);
        boolean b = Objects.equals(sessionKey, SESSION_KEY);
        TGS tgs = new TGS("login", "server", System.currentTimeMillis(), System.currentTimeMillis(), CLIENT_SERVER_KEY);
        System.out.println("Сформированный TGS: " + tgs);
        //buildResponse
        byte[] tgs_b = objectMapper.writeValueAsBytes(tgs);
        byte[] encryptedTGS = eService.encryptString(SERVER_KEY_SK.getBytes(StandardCharsets.UTF_8), iv, tgs_b);
        System.out.println("TGS зашифрованное долговременным ключом сервера: " + Arrays.toString(encryptedTGS));
        TGSs tgSs = new TGSs(encryptedTGS);
        TGScPart tgScPart = new TGScPart(tgs, tgSs);
        byte[] tgScPart_b = objectMapper.writeValueAsBytes(tgScPart);
        byte[] tgSc_b = eService.encryptString(sessionKey.getBytes(StandardCharsets.UTF_8), iv, tgScPart_b);
        System.out.println("Ответ клиенту, зашифрованный сессионным ключом клиент-сервер: " + Arrays.toString(tgSc_b));
        TGSc tgSc = new TGSc(tgSc_b);
        return tgSc;
    }
}
