package com.example.apiauthorizer.util;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.example.apiauthorizer.Exception.TokenException;
import com.example.apiauthorizer.model.UserPool;


import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

public class JwtVerifierUtil {

    private final String JWK_SUFFIX = "/.well-known/jwks.json";
    private String URL;

    /**
     * Valida o token seguindo a documentação da Amazon:
     * <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html">...</a>
     * @param token
     * @return JWT caso passe pela validação
     * @throws TokenException
     */
    public static DecodedJWT verify(String token) throws TokenException {
        UserPool pool = new UserPool();
        //Step 1
        try {
            DecodedJWT jwt = JWT.decode(token);
        //Step 2
            final JwkProvider jwkProvider = new UrlJwkProvider(JwtVerifierUtil.constructJWKUrl(pool));
            Jwk jwk = jwkProvider.get(jwt.getKeyId());
            RSAPublicKey publicKey = (RSAPublicKey) jwk.getPublicKey();
            Algorithm algorithm = Algorithm.RSA256(publicKey);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(jwt.getIssuer())
                    .build();
            // When verifying a token the time validation occurs automatically,
            // resulting in a JWTVerificationException being throw when the values are invalid.
            DecodedJWT jwt_v = verifier.verify(token);
            //Step 3
            if(JwtVerifierUtil.verifyIssuer(jwt_v.getIssuer(), pool)){
                if(jwt_v.getClaim("token_use").asString().equals("access")) {
                    return jwt;
                } else {
                    throw new TokenException("Wrong Token use");
                }
            } else {
                throw  new TokenException("Wrong Issuer pool id");
            }
        } catch (Exception e){
            throw new TokenException(e.getMessage());
        }

    }

    /**
     * Constroi url onde estão as keys JWK
     * @param pool
     * @return string da url
     */
    private static String constructJWKUrl(UserPool pool) {
        return "https://cognito-idp."+pool.getRegion()+".amazonaws.com/"+pool.getUserPoolId();//+this.JWK_SUFFIX;

    }

    /**
     * Valida o Issuer do token JWT
     * @param iss
     * @param pool
     * @return se o Issuer é valido ou não
     */
    private static boolean verifyIssuer(String iss, UserPool pool) {
        String[] issParts = iss.split("/");
        return Objects.equals(issParts[issParts.length - 1], pool.getUserPoolId());

    }
}
