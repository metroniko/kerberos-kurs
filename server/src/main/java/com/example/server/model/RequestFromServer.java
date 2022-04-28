package com.example.server.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class RequestFromServer {
    private byte[] encryptedTime;
    private byte[] encryptedTGSs;
}
