package com.example.demo.model;

import lombok.Data;

import java.io.Serializable;
import java.util.Date;

@Data
public class SecondTGTPart implements Serializable {
    private String sessionKey;
    private Date time;
}
