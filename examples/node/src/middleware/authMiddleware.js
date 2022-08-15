import express from 'express';
import AWSCognito from 'aws-sdk';
import * as jose from 'jose';

const identityServiceProvider = new AWSCognito.CognitoIdentityServiceProvider({
    region: process.env.REGION || 'sa-east-1',
  });

function validateProfile(profile, method) {
    for (let i of profile){
        switch (method) {
            case 'GET':
                if(i === 'Perfil-ALL' || i === 'Perfil-CONSULTA'){
                    return true;
                }
            case 'POST':
            case 'PUT':
            case 'PATCH':
            case 'DELETE':
                if(i === 'Perfil-ALL' || i === 'Perfil-ESCRITA'){
                    return true;
                }
            default:
                continue;
        }
    }
    return false;
}

/*
    Middleware responsável pela validação do usuário (Autorização)
    Basicamente, valida o jwt informado pelo usuário via identityServiceProvider.getUser
    Extrai o array de perfis do usuário do jwt (cognito:groups) e verifica se o usuário pode acessar determinado recurso

    Retorno: Quando falso, é retornado o status 401 com a mensagem "Access Denied"
             Em sucesso, o middleware passa a execução para o próximo da fila, que é o recurso alvo
             Em caso de erro, a execução é direcionada para o middleware que trata os erros
*/
async function authMiddleware(req, res, next) {
    try{
        let token = req.headers['authorization'];
        token = token.substring(7);
        const user = await identityServiceProvider.getUser({AccessToken: token }).promise();
        if(user){
            const profile = jose.decodeJwt(token)['cognito:groups'];
            if(validateProfile(profile, req.method)){
                req.user = {
                    id: user.UserAttributes.find((attr) => attr.Name === 'sub')?.Value,
                    email: user.UserAttributes.find((attr) => attr.Name === 'email')?.Value, 
                };
                next();
            } else {
                res.status(401).json({Error: "Access Denied!"});
            }
        }
    } catch(err){
        //if(err.code === 'MissingRequiredParameter'){
        //    res.status(401).json({Error: "Access Denied!"});
       // }else {
        res.status(401).json({Error: "Access Denied!"});
        }
};

export default authMiddleware;