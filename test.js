function isEmptyJSON(a) {
  return Object.keys(a).length === 0;
}

console.log(isEmptyJSON({}));