package com.example.kdc.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;

@Data
@AllArgsConstructor
public class SecondTGTPart implements Serializable {
    private String sessionKey;
    private long time;
}
