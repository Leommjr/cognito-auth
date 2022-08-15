import express from 'express';
const router = express.Router();

router.get('/', function(req, res) {
    console.log("index");
    res.status(200).json({
      Message: "Greetings!"
    })
    
  });


export default router;