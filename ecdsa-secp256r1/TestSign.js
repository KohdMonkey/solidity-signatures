// const assertRevert   = require('../helpers/assertRevert');
const bigNumber      = require('bignumber.js');
const crypto         = require('crypto');
const ecPem          = require('ec-pem');
const ethereumJSUtil = require('ethereumjs-util');

// Create curve object for key and signature generation.
var prime256v1 = crypto.createECDH('prime256v1');
prime256v1.generateKeys();
console.log('public key: ');
console.log(prime256v1.getPublicKey('hex'));

// Reformat keys.
var pemFormattedKeyPair = ecPem(prime256v1, 'prime256v1');
publicKey = [
  '0x' + prime256v1.getPublicKey('hex').slice(2, 66),
  '0x' + prime256v1.getPublicKey('hex').slice(-64)
];

console.log('formatted public key: ');
console.log(publicKey);

// Create random message and sha256-hash it.
var message = Buffer.from('hello, world');
var hash = ethereumJSUtil.sha256(message);
messageHash = ethereumJSUtil.bufferToHex(hash);
console.log('message hash: ');
console.log(messageHash);


// Create signature. sha256 from RSA
var signer = crypto.createSign('RSA-SHA256');
signer.update(message);
var sigString = signer.sign(pemFormattedKeyPair.encodePrivateKey(), 'hex');

// Reformat signature / extract coordinates.
var xlength = 2 * ('0x' + sigString.slice(6, 8));
var sigString = sigString.slice(8)
signature = [
  '0x' + sigString.slice(0, xlength),
  '0x' + sigString.slice(xlength + 4)
];

console.log('signature: ');
console.log(signature);