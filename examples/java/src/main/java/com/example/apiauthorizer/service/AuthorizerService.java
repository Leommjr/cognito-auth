package com.example.apiauthorizer.service;


import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.apiauthorizer.Exception.AuthorizerException;
import com.example.apiauthorizer.util.JwtVerifierUtil;
import com.example.apiauthorizer.Exception.TokenException;

import java.util.Objects;

/**
 * Classe para validar o JWT informado pelo o usuário
 * validar se o perfil de acesso é válido para determinada requisição
 */
public class AuthorizerService {

    public AuthorizerService() {

    }

    /**
     * Método estático para validar o JWT via JwtVerifierUtil.verify e o perfil do usuário utilizando verifyProfile
     * @param authToken
     * @param method
     * @throws TokenException
     */
    public static void authorize(String authToken, String method) throws TokenException {
        try {
            DecodedJWT jwt = JwtVerifierUtil.verify(authToken);
            if(!(AuthorizerService.verifyProfile(jwt.getClaim("cognito:groups").asArray(String.class), method))){
                throw new AuthorizerException("Permission Denied!");
            }

        } catch (Exception e) {
            System.out.println(e);
            throw new AuthorizerException(e.getMessage());

        }
    }

    /**
     * Valida o perfil do usuário pela claim "cognito:groups"
     * @param profiles
     * @param method
     * @return se o perfil é válido ou não para o método informado.
     */
    private static boolean verifyProfile(String[] profiles, String method) {
        for(String i : profiles){
            switch (method){
                case "GET":
                    if(Objects.equals(i, "Perfil-CONSULTA") || Objects.equals(i, "Perfil-ALL")){
                        return true;
                    }
                case "POST":
                case "PUT":
                case "DELETE":
                    if(Objects.equals(i, "Perfil-ESCRITA") || Objects.equals(i, "Perfil-ALL")){
                        return true;
                    }
                default:
                    break;
            }
        }
        return false;
    }

}
