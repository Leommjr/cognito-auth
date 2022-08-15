import express from 'express';
import helmet from 'helmet';
import 'dotenv/config';
import parser from 'body-parser';



const app = express();
app.use(helmet());
app.use(parser.json());

//ROUTES
import indexRouter from './routes/index.js';
import userRouter from './routes/user.js';



app.use('/', indexRouter);
app.use('/api/v1/users', userRouter);
app.use(function(err, req, res, next) {
  console.error(err.stack);
  res.status(err.status).send(err.data);
});
app.listen(3001);