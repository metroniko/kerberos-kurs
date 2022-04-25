package com.example.kdc.storage;

import lombok.Data;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Data
@Service
public class ClientStorage {
    Map<String, String> loginPasswordMap;
    Map<String, String> loginKeyMap;

    public ClientStorage() {
        this.loginPasswordMap = new HashMap<>();
        this.loginKeyMap = new HashMap<>();
        this.loginPasswordMap.put("login", "password");
        this.loginKeyMap.put("login", "12345");
    }
}
