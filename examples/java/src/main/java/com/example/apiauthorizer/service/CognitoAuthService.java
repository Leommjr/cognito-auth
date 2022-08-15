package com.example.apiauthorizer.service;


import com.example.apiauthorizer.Exception.LoginException;
import com.example.apiauthorizer.Exception.RefreshException;
import com.example.apiauthorizer.Exception.ResetException;
import com.example.apiauthorizer.Exception.TokenException;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.*;
import software.amazon.awssdk.utils.BinaryUtils;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

/**
 * Classe para fazer o login do usuário utilizando SRP
 * Fortemente baseada no código de exemplo disponibilzado para a versão 1 do SDK (atualmente estamos na 2)
 */
public class CognitoAuthService {

    private final CognitoIdentityProviderClient cognitoClient;
    private static final String N_hex =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                    + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                    + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                    + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                    + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                    + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                    + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                    + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                    + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                    + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                    + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                    + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                    + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                    + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
    private static final BigInteger N = new BigInteger(N_hex, 16);
    private static final BigInteger g = BigInteger.valueOf(2);
    private static final BigInteger k;
    private static final int EPHEMERAL_KEY_LENGTH = 1024;
    private static final int DERIVED_KEY_SIZE = 16;
    private static final String DERIVED_KEY_INFO = "Caldera Derived Key";
    private static final ThreadLocal<MessageDigest> THREAD_MESSAGE_DIGEST =
            ThreadLocal.withInitial(() -> {
                try {
                    return MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    throw new SecurityException("Exception in authentication", e);
                }
            });
    private static final SecureRandom SECURE_RANDOM;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG");

            MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
            messageDigest.reset();
            messageDigest.update(N.toByteArray());
            byte[] digest = messageDigest.digest(g.toByteArray());
            k = new BigInteger(1, digest);
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(e.getMessage(), e);
        }
    }
    final static class Hkdf {
        private static final int MAX_KEY_SIZE = 255;
        private final byte[] EMPTY_ARRAY = new byte[0];
        private final String algorithm;
        private SecretKey prk = null;


        /**
         * @param algorithm REQUIRED: The type of HMAC algorithm to be used.
         */
        private Hkdf(String algorithm) {
            if (!algorithm.startsWith("Hmac")) {
                throw new IllegalArgumentException("Invalid algorithm " + algorithm
                        + ". Hkdf may only be used with Hmac algorithms.");
            } else {
                this.algorithm = algorithm;
            }
        }

        private static Hkdf getInstance() throws NoSuchAlgorithmException {

            return new Hkdf("HmacSHA256");
        }

        /**
         * @param ikm REQUIRED: The input key material.
         */
        public void init(byte[] ikm) {
            this.init(ikm, null);
        }

        /**
         * @param ikm  REQUIRED: The input key material.
         * @param salt REQUIRED: Random bytes for salt.
         */
        private void init(byte[] ikm, byte[] salt) {
            byte[] realSalt = salt == null ? EMPTY_ARRAY : salt.clone();
            byte[] rawKeyMaterial = EMPTY_ARRAY;

            try {
                final Mac e = Mac.getInstance(this.algorithm);
                if (realSalt.length == 0) {
                    realSalt = new byte[e.getMacLength()];
                    Arrays.fill(realSalt, (byte) 0);
                }

                e.init(new SecretKeySpec(realSalt, this.algorithm));
                rawKeyMaterial = e.doFinal(ikm);
                final SecretKeySpec key = new SecretKeySpec(rawKeyMaterial, this.algorithm);
                Arrays.fill(rawKeyMaterial, (byte) 0);
                this.unsafeInitWithoutKeyExtraction(key);
            } catch (final GeneralSecurityException var10) {
                throw new RuntimeException("Unexpected exception", var10);
            } finally {
                Arrays.fill(rawKeyMaterial, (byte) 0);
            }

        }

        /**
         * @param rawKey REQUIRED: Current secret key.
         * @throws InvalidKeyException
         */
        private void unsafeInitWithoutKeyExtraction(SecretKey rawKey) throws InvalidKeyException {
            if (!rawKey.getAlgorithm().equals(this.algorithm)) {
                throw new InvalidKeyException(
                        "Algorithm for the provided key must match the algorithm for this Hkdf. Expected "
                                + this.algorithm + " but found " + rawKey.getAlgorithm());
            } else {
                this.prk = rawKey;
            }
        }

        /**
         * @param info   REQUIRED
         * @param length REQUIRED
         * @return converted bytes.
         */
        private byte[] deriveKey(String info, int length) {
            return this.deriveKey(info != null ? info.getBytes(StandardCharsets.UTF_8) : null, length);
        }

        /**
         * @param info   REQUIRED
         * @param length REQUIRED
         * @return converted bytes.
         */
        private byte[] deriveKey(byte[] info, int length) {
            final byte[] result = new byte[length];

            try {
                this.deriveKey(info, length, result, 0);
                return result;
            } catch (final ShortBufferException var5) {
                throw new RuntimeException(var5);
            }
        }

        /**
         * @param info   REQUIRED
         * @param length REQUIRED
         * @param output REQUIRED
         * @param offset REQUIRED
         * @throws ShortBufferException
         */
        private void deriveKey(byte[] info, int length, byte[] output, int offset)
                throws ShortBufferException {
            this.assertInitialized();
            if (length < 0) {
                throw new IllegalArgumentException("Length must be a non-negative value.");
            } else if (output.length < offset + length) {
                throw new ShortBufferException();
            } else {
                final Mac mac = this.createMac();
                if (length > MAX_KEY_SIZE * mac.getMacLength()) {
                    throw new IllegalArgumentException(
                            "Requested keys may not be longer than 255 times the underlying HMAC length.");
                } else {
                    byte[] t = EMPTY_ARRAY;

                    try {
                        int loc = 0;

                        for (byte i = 1; loc < length; ++i) {
                            mac.update(t);
                            mac.update(info);
                            mac.update(i);
                            t = mac.doFinal();

                            for (int x = 0; x < t.length && loc < length; ++loc) {
                                output[loc] = t[x];
                                ++x;
                            }
                        }
                    } finally {
                        Arrays.fill(t, (byte) 0);
                    }

                }
            }
        }
        /**
         * @return the generates message authentication code.
         */
        private Mac createMac() {
            try {
                final Mac ex = Mac.getInstance(this.algorithm);
                ex.init(this.prk);
                return ex;
            } catch (final NoSuchAlgorithmException var2) {
                throw new RuntimeException(var2);
            } catch (final InvalidKeyException var3) {
                throw new RuntimeException(var3);
            }
        }

        /**
         * Checks for a valid pseudo-random key.
         */
        private void assertInitialized() {
            if (this.prk == null) {
                throw new IllegalStateException("Hkdf has not been initialized");
            }
        }
    }

    private BigInteger a;
    private BigInteger A;
    private String userPoolID;
    private String clientId;
    private String region;


    public CognitoAuthService(String userPoolID, String clientid){
        do {
            a = new BigInteger(EPHEMERAL_KEY_LENGTH, SECURE_RANDOM).mod(N);
            A = g.modPow(a, N);
            System.out.println("A: " + A.toString());
        } while (A.mod(N).equals(BigInteger.ZERO));
        System.out.println("a: "+ a.toString());
        this.region = "sa-east-1";
        this.userPoolID = userPoolID;
        this.clientId = clientid;
        this.cognitoClient =  CognitoIdentityProviderClient.builder()
                .region(Region.of(this.region))//this.pool.getRegion()
                .credentialsProvider(ProfileCredentialsProvider.create())
                .build();
    }
    private BigInteger getA() {
        return A;
    }
    private byte[] getPasswordAuthenticationKey(String userId,
                                                String userPassword,
                                                BigInteger B,
                                                BigInteger salt) {
        // Authenticate the password
        // u = H(A, B)
        MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
        messageDigest.reset();
        messageDigest.update(A.toByteArray());
        BigInteger u = new BigInteger(1, messageDigest.digest(B.toByteArray()));
        if (u.equals(BigInteger.ZERO)) {
            throw new SecurityException("Hash of A and B cannot be zero");
        }

        // x = H(salt | H(poolName | userId | ":" | password))
        messageDigest.reset();
        messageDigest.update(this.userPoolID.split("_", 2)[1].getBytes(StandardCharsets.UTF_8));
        messageDigest.update(userId.getBytes(StandardCharsets.UTF_8));
        messageDigest.update(":".getBytes(StandardCharsets.UTF_8));
        byte[] userIdHash = messageDigest.digest(userPassword.getBytes(StandardCharsets.UTF_8));

        messageDigest.reset();
        messageDigest.update(salt.toByteArray());
        BigInteger x = new BigInteger(1, messageDigest.digest(userIdHash));
        BigInteger S = (B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N)).mod(N);
        //S = (B - g^x)^(a + ux)
        Hkdf hkdf;
        try {
            hkdf = Hkdf.getInstance();
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(e.getMessage(), e);
        }
        hkdf.init(S.toByteArray(), u.toByteArray());
        return hkdf.deriveKey(DERIVED_KEY_INFO, DERIVED_KEY_SIZE);
    }
    private InitiateAuthRequest initiateUserSrpAuthRequest(String username) {

        Map<String, String> authmap = new HashMap<String, String>(){{
            put("USERNAME", username);
            put("SRP_A", getA().toString(16));
        }};

        return InitiateAuthRequest.builder()
                        .authFlow(AuthFlowType.USER_SRP_AUTH)
                                .authParameters(authmap)
                                        .clientId(this.clientId)//this.pool.getClient_id()
                                                .build();
    }
    private InitiateAuthRequest initiateRefreshTokenRequest(String refreshToken) {

        Map<String, String> authmap = new HashMap<String, String>(){{
            put("REFRESH_TOKEN", refreshToken);
        }};

        return InitiateAuthRequest.builder()
                .authFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
                .authParameters(authmap)
                .clientId(this.clientId)//this.pool.getClient_id()
                .build();
    }
    private RespondToAuthChallengeRequest userSrpAuthRequest(InitiateAuthResponse challenge,
                                                             String password
    ) {
        String userIdForSRP = challenge.challengeParameters().get("USER_ID_FOR_SRP");
        String usernameInternal = challenge.challengeParameters().get("USERNAME");

        BigInteger B = new BigInteger(challenge.challengeParameters().get("SRP_B"), 16);
        if (B.mod(N).equals(BigInteger.ZERO)) {
            throw new SecurityException("SRP error, B cannot be zero");
        }

        BigInteger salt = new BigInteger(challenge.challengeParameters().get("SALT"), 16);
        byte[] key = getPasswordAuthenticationKey(userIdForSRP, password, B, salt);

        Date timestamp = new Date();
        byte[] hmac = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            mac.init(keySpec);
            mac.update(this.userPoolID.split("_", 2)[1].getBytes(StandardCharsets.UTF_8));
            mac.update(userIdForSRP.getBytes(StandardCharsets.UTF_8));
            byte[] secretBlock = BinaryUtils.fromBase64(challenge.challengeParameters().get("SECRET_BLOCK"));
            mac.update(secretBlock);
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
            simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
            String dateString = simpleDateFormat.format(timestamp);
            byte[] dateBytes = dateString.getBytes(StandardCharsets.UTF_8);
            hmac = mac.doFinal(dateBytes);
        } catch (Exception e) {
            System.out.println(e);
        }

        SimpleDateFormat formatTimestamp = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
        formatTimestamp.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));

        Map<String, String> srpAuthResponses = new HashMap<>();
        srpAuthResponses.put("PASSWORD_CLAIM_SECRET_BLOCK", challenge.challengeParameters().get("SECRET_BLOCK"));
        srpAuthResponses.put("PASSWORD_CLAIM_SIGNATURE", new String(Objects.requireNonNull(BinaryUtils.toBase64Bytes(hmac)), StandardCharsets.UTF_8));
        srpAuthResponses.put("TIMESTAMP", formatTimestamp.format(timestamp));
        srpAuthResponses.put("USERNAME", usernameInternal);

        return RespondToAuthChallengeRequest.builder()
                .challengeName(challenge.challengeName())
                .clientId(clientId)
                .session(challenge.session())
                .challengeResponses(srpAuthResponses).build();
    }

    /******************************************************************************************************************
     ************************************************* PUBLIC METHODS *************************************************
     ******************************************************************************************************************/

    /**
     * Função de login utilizando o protocolo Secure Remote Password (SRP)
     *
     * @param username
     * @param password
     * @param newPassword
     * @return dados da sessão
     */
    public String login(String username, String password, String newPassword) throws LoginException {
        String authresult = null;
        String accessToken = null;
        String refreshToken = null;
        JSONObject jresult = new JSONObject();
        InitiateAuthRequest authReq = initiateUserSrpAuthRequest(username);
        try {
            //AnonymousCredentialsProvider creds = AnonymousCredentialsProvider.create();
            final InitiateAuthResponse authRes = this.cognitoClient.initiateAuth(authReq);
            System.out.println("SRP_A: " + authReq.authParameters().get("SRP_A"));
            if (authRes.challengeName().equals(ChallengeNameType.PASSWORD_VERIFIER)) {
                RespondToAuthChallengeRequest challengeRequest = userSrpAuthRequest(authRes, password);
                System.out.println("SRP_B: " + authRes.challengeParameters().get("SRP_B"));
                RespondToAuthChallengeResponse result = this.cognitoClient.respondToAuthChallenge(challengeRequest);
                if(result.challengeName() != null){
                    if(result.challengeName().equals(ChallengeNameType.NEW_PASSWORD_REQUIRED)) {
                        if (newPassword != null) {
                            Map<String, String> newPassmap = new HashMap<String, String>() {{
                                put("USERNAME", username);
                                put("NEW_PASSWORD", newPassword);
                            }};
                            RespondToAuthChallengeRequest challengeRequest2 = RespondToAuthChallengeRequest.builder()
                                    .challengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                                    .clientId(this.clientId)
                                    .challengeResponses(newPassmap)
                                    .session(result.session()).build();
                            RespondToAuthChallengeResponse result2 = this.cognitoClient.respondToAuthChallenge(challengeRequest2);
                            accessToken = result2.authenticationResult().accessToken();
                            refreshToken = result2.authenticationResult().refreshToken();
                            jresult.put("Access Token", accessToken);
                            jresult.put("Refresh Token", refreshToken);
                            authresult = jresult.toString();
                        } else {
                             throw new LoginException("Primeiro acesso do usuário. Necessário informar o parâmetro newPassword para gerar uma nova senha");
                        }
                    }
                }else {
                    System.out.println(result);
                    accessToken = result.authenticationResult().accessToken();
                    refreshToken = result.authenticationResult().refreshToken();
                    jresult.put("Access Token", accessToken);
                    jresult.put("Refresh Token", refreshToken);
                    authresult = jresult.toString();
                }
            }
        }catch(Exception e) {
            if(e instanceof NullPointerException){
                throw new LoginException("Parameter password required");
            }
            throw new LoginException(e.getMessage());
        }
        return authresult;
    }
    public String reset(String username, String code, String newPassword) throws ResetException {
        JSONObject jresult = new JSONObject();
        String authresult = null;
        ConfirmForgotPasswordRequest request = ConfirmForgotPasswordRequest.builder()
                .clientId(this.clientId)
                .username(username)
                .password(newPassword)
                .confirmationCode(code)
                .build();
        try {
            ConfirmForgotPasswordResponse response = this.cognitoClient.confirmForgotPassword(request);
            jresult.put("Success", "OK");
            authresult = jresult.toString();
        }catch (Exception e) {
            throw new ResetException(e.getMessage());
        }
        return authresult;

    }
    public String refresh(String authToken) throws RefreshException {

        JSONObject jresult = new JSONObject();
        if(authToken == null)
            throw new RefreshException("Parameter refreshToken required!");
        InitiateAuthRequest init = initiateRefreshTokenRequest(authToken);
        try {
            final InitiateAuthResponse authRes = this.cognitoClient.initiateAuth(init);
            jresult.put("new Access Token", authRes.authenticationResult().accessToken());
            return jresult.toString();

        }catch(Exception e) {
            throw new RefreshException(e.getMessage());
        }


    }

}
