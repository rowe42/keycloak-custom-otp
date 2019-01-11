/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.muenchen.keycloak.custom;

/**
 *
 * @author roland
 */
public class TOTPResponse {
    private String secret;
    private String secretQrcode;

    public String getSecretQrcode() {
        return secretQrcode;
    }

    public void setSecretQrcode(String secretQrcode) {
        this.secretQrcode = secretQrcode;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }


}
