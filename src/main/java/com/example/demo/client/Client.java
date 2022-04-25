package com.example.demo.client;

import com.example.demo.model.AuthenticationRequestToKDC;
import com.example.demo.model.TGT;
import org.springframework.http.HttpEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class Client {

    private final RestTemplate restTemplate = new RestTemplate();

    public TGT authenticateToKdc(AuthenticationRequestToKDC reqBody) {
        HttpEntity<AuthenticationRequestToKDC> request = new HttpEntity<>(reqBody);
        String fooResourceUrl = "http://localhost:8081/kdc/auth";
        TGT tgt = restTemplate.postForObject(fooResourceUrl, request, TGT.class);
        return tgt;
    }
}
