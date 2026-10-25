const { tokens } = require('word-segments');
exports.slugify = text => tokens(text).join('-');
