import express from 'express';
import axios from 'axios';

async function authMiddleware2(req, res, next) {
    try{
        let token = req.headers['authorization'];
        token = token.substring(7);
        axios
        .post('http://18.228.26.64:8080/authorizer/api/authorize',{
            accessToken: token,
            method: req.method
        })
        .then(function(response){
            next();
        })
        .catch(function (err) {
            next(err.response);
        });
    }catch(err){
       res.status(401).json({Error: "Access Denied!"});
        
    }
};

export default authMiddleware2;