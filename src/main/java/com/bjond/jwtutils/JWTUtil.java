/*  Copyright (c) 2016
 *  by Bjönd, Inc., Boston, MA
 *
 *  This software is furnished under a license and may be used only in
 *  accordance with the terms of such license.  This software may not be
 *  provided or otherwise made available to any other party.  No title to
 *  nor ownership of the software is hereby transferred.
 *
 *  This software is the intellectual property of Bjönd, Inc.,
 *  and is protected by the copyright laws of the United States of America.
 *  All rights reserved internationally.
 *
 */

package com.bjond.jwtutils;



import java.security.Key;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jose4j.base64url.Base64;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;


/**
 Utilities for the JWT RFC-7519 using Jose4j <br>
 http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#JWS <br>
 <br>
 Makes usage much simpler and consolidates common practice.<br>
<br>
<br>
 * <a href="mailto:Stephen.Agneta@bjondinc.com">Steve 'Crash' Agneta</a>
 *
 * @version 1.0
 *
 */

public class JWTUtil {

	/**
	 * Validates a token (the JWT compact serialization) passed as a parameter
     * given the proper key, issuer, audience and subject. The clockSkewInSeconds
     * is the maximum clock skew allowed between current time and the time held within 
     * token. 30 seconds is a tight skew. 5 minutes is the default on Kerberos. 
	 *
     * If the token is invalid the InvalidJwtException is tossed.
     *
     *
	 * @param key Valid cypher key for encryption
	 * @param issuer Corporate Name of the Issuer of this token.
	 * @param audience The audience of the token. That is whom it is meant for. Usually a corporate name.
	 * @param subject  The subject of the token. Meaning what you are securing.
	 * @param clockSkewInSeconds Maximum allowable time skey for validation.
	 * @param token The actual JWT token.
	 * @return JwtClaims which will contain your claims map.
	 *
	 * @throws InvalidJwtException Tossed if the token does not pass validation. Expired. Bad Key. Wrong claims. Etcetera.
	 */
    public static JwtClaims validateTokenAndProcessClaims(final Key key,
                                                          final String issuer,
                                                          final String audience,
                                                          final String subject,
                                                          final int clockSkewInSeconds,
                                                          final String token) throws InvalidJwtException {

        final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setRequireExpirationTime() // the JWT must have an expiration time
            .setAllowedClockSkewInSeconds(clockSkewInSeconds) // allow some leeway in validating time based claims to account for clock skew
            .setExpectedIssuer(issuer) // whom the JWT needs to have been issued by
            .setExpectedAudience(audience) // to whom the JWT is intended for
            .setExpectedSubject(subject)
            .setDecryptionKey(key)
            .setEnableRequireEncryption() 
            .setDisableRequireSignature()
            .setSkipSignatureVerification()
            .build(); // create the JwtConsumer instance

        //  Validate the JWT and process it to the Claims
        return jwtConsumer.processToClaims(token);
    }



	/**
	 * Generates a JWT Token given a set of parameters common to JWT implementations.
	 *
	 * @param bjondServerEncryptionKey The Base64 encoded Encyrption key
	 * @param bjondAdapterSubject  The indended Subject of the generated token
	 * @param bjondAdapterAudience The intended Audience of the generated token
	 * @param issuer The indended Issuer of the generated token
	 * @param json JSON snippet that will be inserted into the claim under the key 'json'
	 * @return JWT token string of the form string.string.string
	 *
	 * @throws JoseException if any issue occurs during generation. Mostly likely a key issue.
	 */
    public static String generateJWTToken(final String bjondServerEncryptionKey,
                                          final String bjondAdapterSubject,
                                          final String bjondAdapterAudience,
                                          final String issuer,
                                          final String json) throws JoseException {

        final Key key = JWTUtil.generateAESKey(JWTUtil.base64Decode(bjondServerEncryptionKey));
		final Map<String, List<String>> claimsMap = new HashMap<>();

		claimsMap.put("json", Arrays.asList(json));
        return JWTUtil.generateJWT_AES128(
                                          key,
                                          issuer,
                                          bjondAdapterAudience,
                                          bjondAdapterSubject,
                                          claimsMap,
                                          1
                                          );
	}

    
	/**
	 * Generates a JWT token using AES_128_CBC_HMAC_SHA_256.
	 *
	 * @param key Valid cypher key for encryption
	 * @param issuer Corporate Name of the Issuer of this token.
	 * @param audience The audience of the token. That is whom it is meant for. Usually a corporate name.
	 * @param subject The subject of the token. Meaning what you are securing.
	 * @param claimsMap The map of claims in JWT speak
	 * @param expirationTimeMinutesInTheFuture The maximum number of minutes this generated token is valid.
	 * @return JWT token string of the form string.string.string
	 *
	 * @throws JoseException Tossed if there is any failure during generation.
	 */
    public static String generateJWT_AES128(final Key key,
                                            final String issuer,
                                            final String audience,
                                            final String subject,
                                            final Map<String, List<String>> claimsMap,
                                            final int expirationTimeMinutesInTheFuture) throws JoseException {

        final JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);  // who creates the token and signs it
        claims.setAudience(audience); // to whom the token is intended to be sent
        claims.setExpirationTimeMinutesInTheFuture(expirationTimeMinutesInTheFuture); // time when the token will expire (10 minutes from now)
        claims.setGeneratedJwtId(); // a unique identifier for the token
        claims.setIssuedAtToNow();  // when the token was issued/created (now)
        claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
        claims.setSubject(subject); // the subject/principal is whom the token is about

        // Each claims key can point to a List of claims
        claimsMap.keySet().stream().forEach(k -> claims.setStringListClaim(k, claimsMap.get(k)));
            
        final JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(claims.toJson());
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(key);
        
        return jwe.getCompactSerialization();
    }
                                            
    
	/**
	 * Given a properly constructed AES key as an array of bytes,
     * geneates the corresponding JCE key.
	 *
	 * @param key Actual byte array of the AES 128 key.
	 * @return Jose4j key suitable for encryption
	 */
    public static Key generateAESKey(final byte[] key) {
        return new AesKey(key);
    }

    
	/**
	 * Generates an AES 128 key using a cryptographically 
     * secure random number generator.
	 *
	 * @return byte array of AES 128 key.
	 */
    public static byte[] generateRandomKey_AES128() {
        return ByteUtil.randomBytes(16);
    }

	/**
	 * Convenience method that generates a corresponding Base64
     * encoding if any arbitrary byte array.
	 *
	 * @param key byte array of an encryption key
	 * @return encoding of byte array suitable for over the wire transmission
	 */
    public static String base64Encode(final byte[] key) {
        return Base64.encode(key);
    }

	/**
	 * Convenience method that decodes a Base64 string
     * into the corresponding byte array.
	 *
	 * @param key base64 encryption key.
	 * @return the byte array decoded from the base64.
	 */
    public static byte[] base64Decode(final String key) {
        return Base64.decode(key);
    }

    
}
