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

const createSalt = async () => {
  const buffer = await randomBytesPromise(64);

  return buffer.toString("base64");
}

const createHashedPassword = async (pw) => {
  const salt = await createSalt();
  const key = await pbkdf2Promise(pw, salt, 103701, 64, "sha512");
  const hashedPassword = key.toString("base64");

  return { hashedPassword, salt };
}

const verifyPassword = async (pw, userSalt, userPassWord) => {
  const key = await pbkdf2Promise(pw, userSalt, 103701, 64, "sha512");
  const hashedPassword = key.toString("base64");

  return hashedPassword === userPassWord;
}

createHashedPassword("sandbox77!").then(function (result) {
  const createdSalt = result.salt;
  const createdPW = result.hashedPassword;
  verifyPassword("sandbox77!", createdSalt, createdPW).then(function (verified) {
    if (!verified) console.log('Not Logined');
    else console.log('Logined');
  });
});




// function is(a) {
//   let regex = /^.{1,10}$/;

//   console.log(regex.test(a));
// }
// is("hi1");