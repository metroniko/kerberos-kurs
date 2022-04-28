package com.example.demo.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class RequestToServer {
    private byte[] encryptedTime;
    private byte[] encryptedTGSs;
}
