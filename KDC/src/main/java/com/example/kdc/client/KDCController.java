package com.example.kdc.client;

import com.example.kdc.model.AuthenticationRequestToKDC;
import com.example.kdc.model.TGT;
import com.example.kdc.service.EncryptService;
import com.example.kdc.storage.ClientStorage;
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

@RestController
public class KDCController {
    private EncryptService eService;
    private ClientStorage storage;

    public KDCController(EncryptService encryptService, ClientStorage storage) {
        this.eService = encryptService;
        this.storage = storage;
    }

    @PostMapping(path = "/kdc/auth", consumes = MediaType.APPLICATION_JSON_VALUE)
    private TGT authClient(@RequestBody AuthenticationRequestToKDC requestFromClient) throws InvalidAlgorithmParameterException,
            IllegalBlockSizeException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        IvParameterSpec iv = new IvParameterSpec("qwertyuiopasdfgh".getBytes(StandardCharsets.UTF_8));
        String password = storage.getLoginPasswordMap().get(requestFromClient.getLogin());
        String key = storage.getLoginKeyMap().get(requestFromClient.getLogin());
        byte[] hashedKey = eService.hashData(key, password);
        // Нужно проверить что временной идентификатор не протух
        Date date = eService.decryptDate(requestFromClient.getEncryptedKey(), Arrays.copyOfRange(hashedKey, 0, 16), iv);
        TGT tgt = eService.buildTGT(requestFromClient.getLogin(), Arrays.copyOfRange(hashedKey, 0, 16), iv);
        return tgt;
    }
}
