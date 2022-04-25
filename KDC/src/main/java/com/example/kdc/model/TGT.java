package com.example.kdc.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import javax.crypto.SealedObject;
import java.io.Serializable;

@Data
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TGT implements Serializable {
    @JsonProperty("first")
    private byte[] encryptedByMasterKeyFields;
    @JsonProperty(value = "second")
    private byte[] encryptedByHashedPassword;
}

