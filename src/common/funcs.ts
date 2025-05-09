import crypto from 'node:crypto'
import randomatic from 'randomatic'

// 使用 AES-256-CBC 替代 RC4
const algorithm = 'aes-256-cbc'

export const encrypt = function (text, key, randomEncrypt = false) {
  // 生成随机 IV
  const iv = crypto.randomBytes(16)

  if (randomEncrypt && text.indexOf('\t') === -1) {
    text = `${text}\t${randomatic('Aa0', 6)}`
  }

  // 确保密钥长度为32字节
  const keyBuffer = Buffer.from(key, 'hex').slice(0, 32)

  const cipher = crypto.createCipheriv(algorithm, keyBuffer, iv)
  let encrypted = cipher.update(text, 'utf8', 'hex')
  encrypted += cipher.final('hex')

  // 返回 IV + 加密数据
  return iv.toString('hex') + encrypted
}

export const decrypt = function (text, key) {
  // 从加密文本中提取 IV
  const iv = Buffer.from(text.slice(0, 32), 'hex')
  const encryptedText = text.slice(32)

  // 确保密钥长度为32字节
  const keyBuffer = Buffer.from(key, 'hex').slice(0, 32)

  const decipher = crypto.createDecipheriv(algorithm, keyBuffer, iv)
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8')
  decrypted += decipher.final('utf8')

  if (decrypted.indexOf('\t') > -1) {
    decrypted = decrypted.substring(0, decrypted.indexOf('\t'))
  }

  return decrypted
}
// 定义接口描述解析结果
interface ParsedAccount {
  protocol: string
  hostname: string
  host: string
  port: string
  auth: string
  label: string
  privateKeyFile: string
  password: string
  username: string
}

/**
 * 解析 SSH URL 格式的连接字符串
 * @param line - 格式如 "ssh://user:pass:keyfile@host:port label"
 * @returns ParsedAccount 解析后的账号信息
 */
export const parseLine = (line: string): ParsedAccount => {
  const urlString = line.substring(0, line.indexOf(' '))
  const url = new URL(urlString)

  // 组合并解码认证信息
  const auth = `${url.username}:${decodeURIComponent(url.password)}`
  const authParts = auth.split(':')

  const account: ParsedAccount = {
    protocol: url.protocol.replace(':', ''),
    hostname: url.hostname,
    host: url.hostname,
    port: url.port,
    auth,
    label: line.substring(line.indexOf(' ')).trim(),
    privateKeyFile: '',
    password: '',
    username: authParts[0] || '',
  }

  // 处理私钥文件和密码
  if (authParts[2] && authParts[2].length > 0) {
    account.privateKeyFile = authParts[2]
    account.password = ''
  } else {
    account.privateKeyFile = ''
    account.password = authParts[1] || ''
  }

  return account
}
