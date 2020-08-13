package com.demo.oauth2.server.demo;

import org.apache.commons.codec.binary.Base64;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.nio.charset.Charset;

public class GetSecret {

    private static final String APP_KEY = "demo-client";
    private static final String SECRET_KEY = "demo-secret";


    public static void main(String[] args){
        System.out.println("secret: "+new BCryptPasswordEncoder().encode("demo-secret"));

        System.out.println("getHeader: "+getHeader());

    }

    /**
     * 构造Basic Auth认证头信息
     *
     * @return
     */
    private static String getHeader() {
        String auth = APP_KEY + ":" + SECRET_KEY;
        byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(Charset.forName("US-ASCII")));
        String authHeader = "Basic " + new String(encodedAuth);
        return authHeader;
    }


}
