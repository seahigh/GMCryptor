var os = require('os');
exports.C1C2C3 = 1;
exports.C1C3C2 = 0;
exports = module.exports = require('./gmCryptor-c-addon-' + os.platform() + "-" + os.arch());