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
app.use(express.static('public'));

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

app.get('/register', (req, res) => {
  res.render('register.ejs');
})

app.get('/fail', (req, res) => {
  res.sendFile(__dirname + '/fail.html');
})

app.get('/find/user', (req, res) => {
  res.render('finduser.ejs');
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

function isKoreanName(v) {
  let regex = /^[가-힣]{1,10}$/;

  return regex.test(v);
}

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
  var doublecheck = false;
  createHashedPassword(req.body.pw).then(function(result) {
    createdSalt = result.salt; 
    createdPW = result.hashedPassword;
    db.collection('user').find().toArray((err,result) => {
      result.map((a,i) => {
        if(a.id == req.body.id) {
          doublecheck = true;
          return res.send("<script>alert('이미 사용중인 아이디입니다! 다른 아이디를 사용해주세요!'); window.location.replace('/register'); </script>");
        }
      })
      if(!isKoreanName(req.body.name)) {
        return res.send("<script>alert('한글로 이름을 작성해주세요!'); window.location.replace('/register'); </script>")
      }
      else if(!isID(req.body.id)) {
        return res.send("<script>alert('4자 이상 20자 이하의 영문 아이디 형식을 지켜주세요!'); window.location.replace('/register'); </script>");
      }
      else if(!isPhoneNum(req.body.phonenumber)) {
        return res.send("<script>alert('전화번호를 입력해주세요!'); window.location.replace('/register'); </script>");
      }
      else if(!isPW(req.body.pw)) {
        return res.send("<script>alert('비밀번호는 6~15자의 영문 대소문자를 사용해야 하며, 최소 1개 이상의 숫자 혹은 특수 문자를 포함했는지 확인해주세요!'); window.location.replace('/register'); </script>");
      }
      else if(!doublecheck) {
        db.collection('user').insertOne({name: req.body.name, id : req.body.id, phonenumber: req.body.phonenumber, pw: createdPW, salt: createdSalt, group: [], groupleader: []}, function(err, result) {
          return res.redirect('/main/?time=today');
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

app.get('/main/group', Logined, (req, res) => {
  db.collection('user').findOne({id: req.query.user}, (err, result) => {
    res.render('group.ejs', {id: req.query.user, group: result.group, groupleader: result.groupleader});
  })
})

app.get('/main/group/make', (req, res) => {
  res.render('groupmake.ejs', {id: req.user.id});
})

app.get('/main/group/private', (req, res) => {
  db.collection('group').findOne({groupname: req.query.groupname}, (err, result) => {
    return res.render('groupdetail.ejs', {group: result, id: req.user.id});
  })
})

app.post('/main/group/code', (req, res) => {
  var resultGroup;
  db.collection('group').find().toArray((err, result) => {
    for(var i = 0; i < result.length; i++) {
      if(result[i].groupcode == req.body.code) {
        resultGroup = result[i];
        break;
      }
    }
    if(resultGroup != null) {
      db.collection('user').updateOne({id: req.user.id}, {$push: {group: resultGroup.groupname}}, (err2, result2) => {
        db.collection('group').updateOne({groupname: resultGroup.groupname}, {$push: {groupmember: req.user.id}}, (err, result3) => {
          return res.status(200).send({message: 'it was a correct code'});
        })
      })
    }
    else {
      return res.status(400).send("<script>alert('잘못된 코드를 입력하였습니다. 다시 한 번 입력해주세요!'); location.reload(); </script>")
    }
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
      res.status(200).send({message: 'success to post'});
     })
    })
  })
})

app.put('/main/put/true', Logined, function(req,res) {
  db.collection('post').updateOne({_id: parseInt(req.body._id)}, {$set: {complete: 'true'}}, (err, result) => {
    if(err) console.log(err);
    res.status(200).send({message: 'success to complete change to true'}); 
  })
})

app.put('/main/put/false', Logined, function(req,res) {
  db.collection('post').updateOne({_id: parseInt(req.body._id)}, {$set: {complete: 'false'}}, (err, result) => {
    if(err) console.log(err);
    res.status(200).send({message: 'success to complete change to false'});
  })
})

app.delete('/main/delete', Logined, function(req, res) {
  db.collection('post').deleteOne({_id: parseInt(req.body._id)}, (err, result) => {
    if(err) console.log(err);
    res.status(200).send({message: 'success to delete'});
  })  
})

// 그룹명 정규식(아직 정규식이 완성이 안 됨)
// function isGroupName(v) {
//   let regex = /""/;

//   return regex.test(v);
// }

function isGroupinfo(v) {
  let regex = /^[ㄱ-ㅎㅏ-ㅣ가-힣]{1,20}$/;

  return regex.test(v);
}

app.post('/groupmake', (req, res) => {
  if(!isGroupinfo(req.body.groupinfo)) {
    return res.send("<script>alert('그룹 정보는 반드시 한글로만 100자 이내로 입력해주세요!'); window.location.replace('/main/group/make'); </script>");
  }
  // else if(!isGroupName(req.body.groupname)) {
  //   return res.send("<script>alert('그룹명은 반드시 한글,영어,숫자를 이용하여 10자 이내로 입력해주세요!'); window.location.replace('/main/group/make'); </script>");
  // }
  else {
    db.collection('group').find().toArray((err, result) => {
      for(var i = 0; i < result.length; i++) {
        if(result[i].groupname == req.body.groupname) {
          return res.status(400).send("<script>alert('해당 그룹명은 이미 존재합니다. 다른 그룹명을 입력해주세요'); window.location.replace('/main/group/make'); </script>");
        }
      }
      db.collection('group').insertOne({groupname: req.body.groupname, groupinfo: req.body.groupinfo, groupleader: req.user.id, groupmember: [], groupcode: req.body.groupcode}, (err1, result1) => {
        db.collection('user').updateOne({id: req.user.id}, {$push: {groupleader: req.body.groupname}}, (err2, result2) => {
          return res.status(200).send({message: 'success to make a group'});
        })
      })
    })
  }
})

app.put('/groupmember/put', (req, res) => {
  db.collection('group').findOne({groupname: req.query.groupname}, (err, result) => {
    if(result.groupleader != req.user.id) {
      return res.status(400).send({message: 'you are not a groupleader'});
    }
    else {
      db.collection('group').updateOne({groupname: req.query.groupname}, {$pull: {groupmember: req.body.member}}, (err, result) => {
        if(err) console.log(err);
        db.collection('user').updateOne({id: req.body.member}, {$pull: {group: req.query.groupname}}, (error, result) => {
          if(error) console.log(error);
          res.status(200).send({message: 'success to delete member'});
        })
      })
    }
  })
})

app.delete('/group/delete', (req, res) => {
  db.collection('group').findOne({groupname: req.query.groupname}, (err, result) => {
    if(result.groupleader != req.user.id) {
      return res.status(400).send({message: 'you are not a groupleader'});
    }
    else {
      var list = result.groupmember;
      db.collection('group').deleteOne({groupname: req.query.groupname}, (err,result) => {
        db.collection('user').updateOne({id: req.user.id}, {$pull: {groupleader: req.query.groupname}}, (err, result) => {
          for(var i = 0; i < list.length; i++) {
            db.collection('user').updateOne({id: list[i]}, {$pull: {group: req.query.groupname}}, (err, result) => {
              if(err) console.log(err);
              return res.status(200).send({message: "success to delete group"});
            })
          }
        })
      })
    }
  })
})

app.get('/main/group/sprint', (req, res) => {
  db.collection('post').find().toArray((err, result) => {
    var postresultFalse = [];
    var postresultTrue = [];
    for(var i = 0; i < result.length; i++) {
      if(result[i].writer == req.query.groupname) {
        if(result[i].complete =="true") postresultTrue.push(result[i])
        else postresultFalse.push(result[i])
      }
    }
    var percent = 0;
    if (postresultFalse.length != 0 || postresultTrue.length != 0) percent = postresultTrue.length / (postresultTrue.length+postresultFalse.length) * 100;
    res.render('groupsprint.ejs', {groupname: req.query.groupname, postsfalse: postresultFalse, poststrue: postresultTrue, percent: percent});
  })
})

app.post('/group/write', (req,res) => {
  db.collection('counter').findOne({name: "postNum"}, (err,result) => {
    var total = result.totalPost;
    db.collection('post').insertOne({_id: total+1, writer: req.query.groupname, content: req.body.content, complete: 'false'}, (err, result) => {
      db.collection('counter').updateOne({name: 'postNum'}, {$inc: {totalPost: 1}}, (err, result) => {
        res.status(200).send({message: "success to post in groupname"});
      })
    })
  })
})

app.put('/main/group/put/true', Logined, function(req,res) {
  db.collection('post').updateOne({_id: parseInt(req.body._id)}, {$set: {complete: 'true'}}, (err, result) => {
    if(err) console.log(err);
    res.status(200).send({message: 'success to complete change to true'}); 
  })
})

app.put('/main/group/put/false', Logined, function(req,res) {
  db.collection('post').updateOne({_id: parseInt(req.body._id)}, {$set: {complete: 'false'}}, (err, result) => {
    if(err) console.log(err);
    res.status(200).send({message: 'success to complete change to false'});
  })
})

app.delete('/main/group/delete', Logined, function(req, res) {
  db.collection('post').deleteOne({_id: parseInt(req.body._id)}, (err, result) => {
    if(err) console.log(err);
    res.status(200).send({message: 'success to delete'});
  })  
})

// 아이디 중복확인 버튼을 만드는 거 어떰? (잠깐 대기 맨 마지막에 구현해도 될 듯?)
// group 이름 정규식 만들기
// 날짜도 기록해서 날짜별로 todo 뭐 있었는지 볼 수 있게 하기(이건 어떡할까 구현할까 말까)
// 나머지는 디자인 좀 몰두하자 ㅎㅎ