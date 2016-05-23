/*  Copyright (c) 2016
 *  by Bjönd Health, Inc., Boston, MA
 *
 *  This software is furnished under a license and may be used only in
 *  accordance with the terms of such license.  This software may not be
 *  provided or otherwise made available to any other party.  No title to
 *  nor ownership of the software is hereby transferred.
 *
 *  This software is the intellectual property of Bjönd Health, Inc.,
 *  and is protected by the copyright laws of the United States of America.
 *  All rights reserved internationally.
 *
 */

package com.bjond.test;

import static org.assertj.core.api.Assertions.assertThat;
import java.security.Key;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.jose4j.base64url.Base64;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.ByteUtil;
import org.junit.Assert;
import org.junit.Test;

import com.bjond.jwtutils.JWTUtil;

/** JUnit Test Suite TestBrigid
 *
 * @version 0.001 10/16/15mport scala.ScalaHelloWorld;
 * @author Stephen Agneta
 * @since Build 1.000
 *
 */

public class TestJWTUtils {
 
    /////////////////////////////////////////////////////////////////////////
    //                      Unit Tests below this point                    //
    /////////////////////////////////////////////////////////////////////////

    
    @Test
    public void sanityCheck() throws Exception {
        Assert.assertTrue("I ran ok!", true);
        System.out.println("This is a test"); // You should see this in the html report in stdout.
    }

    
    @Test
    public void test_generateJWTToken() throws Exception {
        final byte[] keyBytes = JWTUtil.generateRandomKey_AES128();
        final Key key         = JWTUtil.generateAESKey(keyBytes);

        final String issuer   = "Bjönd, Inc";
        final String audience = "Axis Health";
        final String subject  = "Adapter Token";
        
        final String token     = JWTUtil.generateJWTToken(Base64.encode(keyBytes), issuer, audience, subject, "this is a test", 10);
        final JwtClaims claims = JWTUtil.validateTokenAndProcessClaims(key,  issuer,  audience, subject, 30,  token);


        assertThat(claims).isNotNull();

        final Map<String, List<Object>> claimsMap2 = claims.flattenClaims();
        assertThat(claimsMap2).isNotNull();
        assertThat(claimsMap2.get("json")).hasSize(1).contains("this is a test");
    }
    
    @Test
    public void constructionAndVerification_JWE() throws Exception {
        final String helloWorld = "Hello World!";
        
        // https://bitbucket.org/b_c/jose4j/wiki/Home
        // Basic JWE construction and verification.
        final Key key = new AesKey(ByteUtil.randomBytes(16));
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(helloWorld);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(key);
        final String serializedJwe = jwe.getCompactSerialization();


        jwe = new JsonWebEncryption();
        jwe.setKey(key);
        jwe.setCompactSerialization(serializedJwe);


        assertThat(jwe.getPayload()).isEqualTo(helloWorld);
    }

    @Test
    public void produceAndConsume_JWE_JWT() throws Exception {

        //Create the Claims, which will be the content of the JWT
        final JwtClaims claims = new JwtClaims();
        claims.setIssuer("Issuer");  // who creates the token and signs it
        claims.setAudience("Audience"); // to whom the token is intended to be sent
        claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
        claims.setGeneratedJwtId(); // a unique identifier for the token
        claims.setIssuedAtToNow();  // when the token was issued/created (now)
        claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
        claims.setSubject("subject"); // the subject/principal is whom the token is about
        claims.setClaim("email","mail@example.com"); // additional claims/attributes about the subject can be added
        List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
        claims.setStringListClaim("groups", groups); // multi-valued claims work too

        // JWE construction and insert into JWE thus producing JWE/JWT
        final Key key = new AesKey(ByteUtil.randomBytes(16));
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(claims.toJson());
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(key);
        final String serializedJWT = jwe.getCompactSerialization();


        final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setRequireExpirationTime() // the JWT must have an expiration time
            .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
            .setRequireSubject() // the JWT must have a subject claim
            .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
            .setExpectedAudience("Audience") // to whom the JWT is intended for
            .setDecryptionKey(key)
            .setEnableRequireEncryption() 
            .setDisableRequireSignature()
            .setSkipSignatureVerification()
            .build(); // create the JwtConsumer instance

        //  Validate the JWT and process it to the Claims
        final JwtClaims jwtClaims = jwtConsumer.processToClaims(serializedJWT);
        System.out.println("JWT validation succeeded! " + jwtClaims);        

        // If it didn't blow up with an InvalidJwtException we are good!
    }



    @Test
    public void ensure_Base64_AES_256_Key_Works() throws Exception {

        //Create the Claims, which will be the content of the JWT
        final JwtClaims claims = new JwtClaims();
        claims.setIssuer("Issuer");  // who creates the token and signs it
        claims.setAudience("Audience"); // to whom the token is intended to be sent
        claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
        claims.setGeneratedJwtId(); // a unique identifier for the token
        claims.setIssuedAtToNow();  // when the token was issued/created (now)
        claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
        claims.setSubject("subject"); // the subject/principal is whom the token is about
        claims.setClaim("email","mail@example.com"); // additional claims/attributes about the subject can be added
        List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
        claims.setStringListClaim("groups", groups); // multi-valued claims work too

        // JWE construction and insert into JWE thus producing JWE/JWT
        final byte[] AESKey = ByteUtil.randomBytes(16);

        /////////////////////////////////////////////////////////////////////////
        // This base64AESKeyString is the Base64 secrete key we will generate  //
        // and register with the Bjond System                                  //
        /////////////////////////////////////////////////////////////////////////
        final String base64AESKeyString = Base64.encode(AESKey);
        final byte[] AESKeyDecoded = Base64.decode(base64AESKeyString);

        
        final Key key = new AesKey(AESKeyDecoded);
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(claims.toJson());
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(key);
        final String serializedJWT = jwe.getCompactSerialization();


        final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setRequireExpirationTime() // the JWT must have an expiration time
            .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
            .setRequireSubject() // the JWT must have a subject claim
            .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
            .setExpectedAudience("Audience") // to whom the JWT is intended for
            .setDecryptionKey(key)
            .setEnableRequireEncryption() 
            .setDisableRequireSignature()
            .setSkipSignatureVerification()
            .build(); // create the JwtConsumer instance

        //  Validate the JWT and process it to the Claims
        final JwtClaims jwtClaims = jwtConsumer.processToClaims(serializedJWT);
        System.out.println("JWT validation succeeded! " + jwtClaims);        

        // If it didn't blow up with an InvalidJwtException we are good!
    }


    @Test
    public void ensureAESKeyGeneration() throws Exception {
        final byte[] AESKey = ByteUtil.randomBytes(16); // 128 Bit
        final Key key = new AesKey(AESKey);


        final String base64Key = Base64.encode(AESKey);
        final byte[] key2 = Base64.decode(base64Key);    

        assertThat(base64Key).isNotEmpty();
        assertThat(Arrays.equals(AESKey, key2));


        
        // Just go through the motions, any exceptions?
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload("Hello World!");
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(key);
        final String serializedJwe = jwe.getCompactSerialization();
        jwe = new JsonWebEncryption();
        jwe.setKey(key);
        jwe.setCompactSerialization(serializedJwe);


        
    }

    
}

