package com.example.server.client;

import com.example.server.model.RequestFromServer;
import com.example.server.model.TGS;
import com.example.server.service.EncryptService;
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
import java.util.Date;

import static com.example.server.service.EncryptService.SERVER_KEY_Ks;

@RestController
public class ServerController {

    private EncryptService eService;

    private IvParameterSpec iv;

    public ServerController(EncryptService eService) {
        this.eService = eService;
        this.iv = new IvParameterSpec("qwertyuiopasdfgh".getBytes(StandardCharsets.UTF_8));
    }

    @PostMapping(path = "/from", consumes = MediaType.APPLICATION_JSON_VALUE)
    public void fromClient(@RequestBody RequestFromServer requestFromClient) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        byte[] encryptedTGSs = requestFromClient.getEncryptedTGSs();
        byte[] TGS_b = eService.decryptString(encryptedTGSs, SERVER_KEY_Ks.getBytes(StandardCharsets.UTF_8), iv);
        ObjectMapper objectMapper = new ObjectMapper();
        TGS tgs = objectMapper.readValue(TGS_b, TGS.class);
        Date date = eService.decryptDate(requestFromClient.getEncryptedTime(), tgs.getK_cs().getBytes(StandardCharsets.UTF_8), iv);
    }
}
