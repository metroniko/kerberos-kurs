package com.example.kdc.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

@Data
@AllArgsConstructor
public class AuthenticationRequestToKDC implements Serializable {
    private String login;
    private String domain;
    private byte[] encryptedKey;
}

