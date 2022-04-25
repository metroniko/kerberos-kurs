package com.example.kdc.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

@Data
@AllArgsConstructor
public class FirstTGTPart implements Serializable {
    private String sessionKey;
    private String login;
    private long ttl;
}
