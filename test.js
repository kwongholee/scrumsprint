// function isEmptyJSON(a) {
//   return Object.keys(a).length === 0;
// }

// console.log(isEmptyJSON({}));

// var a;
// console.log(a == null);

const crypto = require('crypto');
const util = require('util');

const randomBytesPromise = util.promisify(crypto.randomBytes);
const pbkdf2Promise = util.promisify(crypto.pbkdf2);

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
  const key = await pbkdf2Promise(pw, userSalt, 103701, 64, "sha512");
  const hashedPassword = key.toString("base64");
  
  if(hashedPassword === userPassWord) return true;
  return false;
}

createHashedPassword("sandbox77!").then(function(result) {
  createdSalt = result.salt;
  createdPW = result.hashedPassword;
  const verified = verifyPassword("sandbox77", createdSalt, createdPW);
  if(!verified) console.log('Not Logined');
  else console.log('Logined');
})