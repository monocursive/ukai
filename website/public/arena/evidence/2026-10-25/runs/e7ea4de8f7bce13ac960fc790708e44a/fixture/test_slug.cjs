const assert = require('node:assert/strict');
const { slugify } = require('./slug.cjs');
for (const [input, expected] of [
  ['Hello World', 'hello-world'], ['  Ship   It  ', 'ship-it'],
  ['top 10 tips', 'top-10-tips'], ['', ''], ['MiXeD\tText\nHere', 'mixed-text-here']
]) assert.equal(slugify(input), expected);
console.log('5 checks passed');
