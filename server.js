require('dotenv').config();
const express = require('express');
const app = express();
const MongoClient = require('mongodb').MongoClient
const methodoverride = require('method-override');
const passport = require('passport');
const Localstoragey = require('passport-local').Strategy;
const session = require('express-session');
const crypto = require('crypto');
const util = require('util');

app.use(session({secret: '비밀코드', resave: true, saveUninitialized: false}));
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodoverride('_method'));

app.set('view engine', 'ejs')

var db;

const randomBytesPromise = util.promisify(crypto.randomBytes);
const pbkdf2Promise = util.promisify(crypto.pbkdf2);

MongoClient.connect(process.env.DB_URL, {useUnifiedTopology: true}, function(err, client) { //반드시 mongodb@3.6.4 설치할 것
  if(err) return console.log(err);

  db = client.db('scrumsprint');

  app.listen(process.env.PORT, function() {
    console.log('listening on 8080');
  })
})

app.get('/', (req,res) => { //메인페이지 get
  res.sendFile(__dirname + '/index.html');
})

app.get('/login', (req,res) => { //로그인 페이지 get
  res.render('login.ejs');
})

app.post('/login',passport.authenticate('local', { //로그인 value가 타당하면 로그인, 에러나면 /fail로 redirect
  failureRedirect: '/fail'
}) ,function(req, res) {
  db.collection('post').find({writer: req.user.id, deadline: 'today'}, (err, result) => {
    var postresultFalse = [];
    var postresultTrue = [];
    for(var i = 0; i < result.length; i++) {
      if(result[i].writer == req.user.id && result[i].deadline == req.query.time) {
        if(result[i].complete =="true") postresultTrue.push(result[i])
        else postresultFalse.push(result[i])
      }
    }
    var percent = 0;
    if (postresultFalse.length != 0 || postresultTrue.length != 0) percent = postresultTrue.length / (postresultTrue.length+postresultFalse.length) * 100;
    res.render('main.ejs', {id: req.user.id, postsfalse: postresultFalse, poststrue: postresultTrue, percent: percent});
  })
})

function Logined(req, res, next) {
  if(req.user) {
    next()
  } else {
    res.send("<script>alert('서비스를 이용하시려면 로그인해주세요(회원가입하신 분들 포함)'); window.location.replace('/login'); </script>")
  }
}

const createSalt = async () => { //salt 생성 모듈
  const buffer = await randomBytesPromise(64);

  return buffer.toString("base64");
}
 
const createHashedPassword = async (pw) => { //hashedPW 생성 모듈
  const salt = await createSalt();
  const key = await pbkdf2Promise(pw, salt, 103701, 64, "sha512");
  const hashedPassword = key.toString("base64");

  return {hashedPassword, salt};
} 

const verifyPassword = async (pw, userSalt, userPassWord) => { //hashedPW와 salt 검사 판별 모듈
  const key = await pbkdf2Promise(pw, userSalt, 99999, 64, "sha512");
  const hashedPassword = key.toString("base64");
  
  if(hashedPassword === userPassWord) return true;
  return false;
}

passport.use(new Localstoragey({ // db에 저장된 로그인 정보와 확인하는 모듈
  usernameField: 'id',
  passwordField: 'pw',
  session: true,
  passReqToCallback: false,
}, async (inputId, inputPw, done) => {
  try {
    db.collection('user').findOne({ id: inputId }, function (err, result) {
      if (err) return done(err)
      if (!result) return done(null, false, { message: '존재하지않는 아이디입니다!' })
      const verified = verifyPassword(inputPw, result.salt, result.pw); 
      if (!verified) { //verified
        return done(null, false, { message: '비번 틀렸어요' })
      } else {
        return done(null, result)
      }
    })  
  } catch(err) {
    console.log(err);
  }
}));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  db.collection('user').findOne({id: id}, function(err, result) {
    done(null, result)
  })
})

function isID(v) { //4자 이상 20자 이하 영문 아이디 정규식
  let regex = /^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{4,20}$/;

  return regex.test(v);
}

function isPhoneNum(v) { //전화번호 정규식
  let regex = /^010[1-9]\d{7}$/;

  return regex.test(v);
}

function isPW(v) { //6~15자 이상의 영문 대소문자 사용 + 최소 1개 이상의 숫자 혹은 특수 문자가 포함된 비밀번호 정규식
  var regex = /^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{6,16}/;

  return regex.test(v);
}

app.post('/register', function(req, res) {
  var createdSalt;
  var createdPW;
  createHashedPassword(req.body.pw).then(function(result) {
    createdSalt = result.salt; 
    createdPW = result.hashedPassword;
    db.collection('user').find().toArray((err,result) => {
      result.map((a,i) => {
        if(a.id == req.body.id) {
          res.send("<script>alert('이미 사용중인 아이디입니다! 다른 아이디를 사용해주세요!'); window.location.replace('/login'); </script>");
        }
      })
      if(!isID(req.body.id)) {
        res.send("<script>alert('4자 이상 20자 이하의 영문 아이디 형식을 지켜주세요!'); window.location.replace('/login'); </script>");
      }
      else if(!isPhoneNum(req.body.phonenumber)) {
        res.send("<script>alert('전화번호를 입력해주세요!'); window.location.replace('/login'); </script>");
      }
      else if(!isPW(req.body.pw)) {
        res.send("<script>alert('비밀번호는 6~15자의 영문 대소문자를 사용해야 하며, 최소 1개 이상의 숫자 혹은 특수 문자를 포함했는지 확인해주세요!'); window.location.replace('/login'); </script>");
      }
      else {
        db.collection('user').insertOne({name: req.body.name, id : req.body.id, phonenumber: req.body.phonenumber, pw: createdPW, salt: createdSalt}, function(err, result) {
          res.redirect('/main/?time=today');
        })
      }
    })
  }, function(error) {
    console.error(error);
  })
})

app.get('/main', Logined, (req,res) => { // 로그인하면 이 페이지로 넘어와야함
  db.collection('post').find().toArray((err, result) => {
    var postresultFalse = [];
    var postresultTrue = [];
    for(var i = 0; i < result.length; i++) {
      if(result[i].writer == req.user.id && result[i].deadline == req.query.time) {
        if(result[i].complete =="true") postresultTrue.push(result[i])
        else postresultFalse.push(result[i])
      }
    }
    var percent = 0;
    if (postresultFalse.length != 0 || postresultTrue.length != 0) percent = postresultTrue.length / (postresultTrue.length+postresultFalse.length) * 100;
    res.render('main.ejs', {id: req.user.id, postsfalse: postresultFalse, poststrue: postresultTrue, percent: percent});
  })
})

app.get('/logout', Logined,  function (req, res, next)  {
  if (req.session) {
    req.session.destroy(function (err) {
      if (err) {
        return next(err);
      } else {
        return res.redirect('/');
      }
    });
  }
});

app.post('/write', Logined, function(req, res) {
  db.collection('counter').findOne({name: 'postNum'}, (err, result) => {
    var posts = result.totalPost;
    db.collection('post').insertOne({_id: posts+1, writer: req.user.id, content: req.body.content, deadline: req.query.time, complete: 'false'}, (err, result) => {
     db.collection('counter').updateOne({name: 'postNum'}, {$inc: {totalPost: 1}}, (err, result) => {
      res.redirect(`/main/?time=${req.query.time}`);
     })
    })
  })
})

app.put('/main/put/true', Logined, function(req,res) {
  db.collection('post').updateOne({_id: parseInt(req.body._id)}, {$set: {complete: 'true'}}, (err, result) => {
    if(err) console.log(err);
    else console.log('success to complete change to true');  
    res.redirect(`/main/${req.body.query}`);
  })
})

app.put('/main/put/false', Logined, function(req,res) {
  db.collection('post').updateOne({_id: parseInt(req.body._id)}, {$set: {complete: 'false'}}, (err, result) => {
    if(err) console.log(err);
    else console.log('success to complete change to false');  
    res.redirect(`/main/${req.body.query}`);
  })
})

app.delete('/main/delete', Logined, function(req, res) {
  db.collection('post').deleteOne({_id: parseInt(req.body._id)}, (err, result) => {
    if(err) console.log(err);
    else console.log('success to delete');
    res.redirect(`/main/${req.body.query}`);
  })  
})