package com.example.kdc.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class FirstTGTPart implements Serializable {
    private String sessionKey;
    private String login;
    private long ttl;
}
