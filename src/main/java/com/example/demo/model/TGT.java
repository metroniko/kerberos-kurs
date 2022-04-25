package com.example.demo.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

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
