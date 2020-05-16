import parse from 'url-parse'
import crypto from 'crypto'
import randomatic from 'randomatic'

const algorithm = 'rc4'

export const encrypt = function (text, key, randomEncrypt = false){
  const iv = Buffer.alloc(0)
  if (randomEncrypt && text.indexOf('\t') === -1) {
    text = `${text}\t${randomatic('Aa0', 6)}`
  }

  const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);
  let crypted = cipher.update(text, 'utf8', 'hex')
  crypted += cipher.final('hex');
  return crypted.toString();
}
 
export const decrypt = function (text, key){
  const iv = Buffer.alloc(0)
  let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), iv);
  // const decipher = crypto.createCipher(algorithm, key)
  // @ts-ignorej
  let dec = decipher.update(text, 'hex', 'utf8')
  dec += decipher.final('utf8');

  if (dec.indexOf('\t') > -1) {
    dec = dec.substring(0, dec.indexOf('\t'))
  }

  return dec;
}

export const parseLine = (line) => {
  let account = parse(line.substring(0, line.indexOf(' ')))
  account.host = account.hostname
  account.label = line.substring(line.indexOf(' ')).trim()
  if (account.auth.split(':')[2].length > 0) {
    account.privateKeyFile = account.auth.split(':')[2]
    account.password = ''
  } else {
    account.privateKeyFile = ''
  }

  return account
}