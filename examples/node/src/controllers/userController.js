import cognitoHelper from '../helpers/cognito.js';



async function singin(req,res){
    try {
        const username = req.body.username;
        const password = req.body.password;
        const newPassword = req.body.newPassword;
        const result = await cognitoHelper.singin(username, password, newPassword);
        res.status(200).json({ "Access Token": result.getAccessToken().getJwtToken(),
         "Id Token": result.getIdToken().getJwtToken(),
          "Refresh Token": result.getRefreshToken().getToken() });
    } catch (err) {
        res.status(400).json({ message: err.message });
        
    }
    
}
async function refreshToken(req, res) {
    try{
        const refreshToken = req.body.refreshToken;
        const username = req.body.username;
        const result = await cognitoHelper.refresh(username, refreshToken);
        res.status(200).json({ "Access Token": result.getAccessToken().getJwtToken(),
         "Id Token": result.getIdToken().getJwtToken(),
          "Refresh Token": result.getRefreshToken().getToken() });
    } catch (err) {
        res.status(400).json({ message: err.message });
        
    }
}

function getProfile(req,res){
    res.status(200).json(req.user);
    
}

function updateUser(req,res){
    res.status(200).json({Result: "Usuario Alterado"});
}

function getUsers(req,res){
    res.status(200).json({
        "Leonardo": {
            "Nome": "Leonardo Marinho",
            "Role": "Admin",
            "CPF": "111.111.234-56"
        },
        "Fernando":{
            "Nome": "Fernando Almeida",
            "Role": "Developer",
            "CPF": "456.878.234-43"

        }
    })
}

export default {singin, getProfile, updateUser, refreshToken, getUsers };