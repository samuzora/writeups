const rd = require("reallydangerous")

const signer = new rd.Signer(" gateway05")
console.log(signer.sign("anonymous_user"))
console.log(signer.sign("pro_user"))
