const rd = require("reallydangerous")

// value, sig
const test = ["anonymous_user", "G9WrB5pktBpto7_KosU9DT8jF0I"]

const filename = "/home/samuzora/ctf/tools/hashcat/rockyou.txt"
const wordlist = require("fs").readFileSync(filename, 'utf-8').split('\n')

Promise.all(wordlist.map(async letter => {
  const signer = new rd.Signer(letter);
  if (signer.verify_signature(test[0], test[1])) {
    console.log(letter)
    process.exit()
  }
}
))
