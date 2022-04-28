package com.example.demo.client;

import com.example.demo.model.*;
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

    public TGSc authorisationToKDC(AuthorisationRequestToKDC req) {
        HttpEntity<AuthorisationRequestToKDC> request = new HttpEntity<>(req);
        String fooResourceUrl = "http://localhost:8081/kdc/author";
        TGSc TGSc = restTemplate.postForObject(fooResourceUrl, request, TGSc.class);
        return TGSc;
    }

    public void authRequestToServer(RequestToServer req) {
        HttpEntity<RequestToServer> request = new HttpEntity<>(req);
        String fooResourceUrl = "http://localhost:8083/from";
        restTemplate.postForObject(fooResourceUrl, request, Object.class);
    }
}
