package com.example.server.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class TGS {
    private String login;
    private String server;
    private long t;
    private long ttl;
    private String K_cs;
}
