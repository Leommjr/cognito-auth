import { AuthenticationDetails, CognitoUser, CognitoUserAttribute, CognitoUserPool, CognitoRefreshToken } from 'amazon-cognito-identity-js';

const userPool = new CognitoUserPool({
    UserPoolId: process.env.USER_POOL_ID || '',
    ClientId: process.env.CLIENT_ID || '',
});

const pool_region = process.env.REGION || 'sa-east-1';

let sessionUser;

/*
    Função responsável pela autenticação dos usuários no Cognito
    Callbacks:
        onSucess: retorna uma Promise com o valor de sessão do usuário
        onFailure: retorna uma Promise rejeitada e seu motivo
        newPasswordRequired: Quando o usuário ainda não alterou sua senha temporária, esse callback é chamado.
                             Para o usuário gerar nova senha, basta informar em um parâmetro newPassword.

*/

function singin(username, password, newPassword=null) {
    return new Promise((resolve, reject) => {
    let authDetails = new AuthenticationDetails({
        Username : username,
        Password : password
    });
    let userData = {
        Username : username,
        Pool : userPool
    };
    let cognitoUser = new CognitoUser(userData);
    console.log(cognitoUser);
    cognitoUser.authenticateUser(authDetails, {
        onSuccess: function (session, userConfirmationNecessary) {
            resolve(session);
        },
        newPasswordRequired: function (userAttributes, requiredAttributes) {
            delete userAttributes.email_verified;
            delete userAttributes.email;
            sessionUser = userAttributes;
            if(newPassword){
            cognitoUser.completeNewPasswordChallenge(newPassword, sessionUser, {
                onSuccess: function (session, userConfirmationNecessary) {
                    resolve(session);
                },
                onFailure: function (err) {
                    reject(err);
                }
            });
            }
            else {
                reject(new Error("User must change temporary Password. Use newPassword parameter"));
            }


        },
        onFailure: function (err) {
            reject(err);
        },
    });
  })
}

/* 
    Função responsável pela atualização do token de acesso utilizando o refreshToken   
*/
function refresh(username, refreshToken) {
    return new Promise((resolve, reject) => { 
        let userData = {
            Username : username,
            Pool : userPool
        };
        let token = new CognitoRefreshToken({ RefreshToken: refreshToken })
        let cognitoUser = new CognitoUser(userData);
        cognitoUser.refreshSession(token, (err, session) => {
            if (err){
                reject(err);
            }
            resolve(session);

        });
    });

}


export default {singin, refresh};
