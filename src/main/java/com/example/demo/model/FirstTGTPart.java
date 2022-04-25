package com.example.demo.model;

import lombok.Data;

import java.io.Serializable;

@Data
public class FirstTGTPart implements Serializable {
    private String sessionKey;
    private String login;
    private String ttl;
}
