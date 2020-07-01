const path = require('path')
const { Utils } = require('@semo/core')
const { inquirer, fs } = Utils
const funcs = require('../common/funcs')

const CFG_PATH = `${process.env.HOME}/.semo/.ssh-accounts`
const CFG_TEMPLATE = 'ssh://${username}:${password}:${privateKeyFile}@${host}:${port} ${label}'
const CFG_VIEW_TEMPLATE = 'ssh://${username}@${host}:${port} ${label}'
const LOGIN_CMD = 'expect ${script} ${username} ${host} ${port} ${password} ${privateKeyFile} ${opts}'

const deleteAndSave = async (cfgData, chooseAccountIndex) => {
  cfgData.splice(chooseAccountIndex, 1)
  fs.writeFileSync(CFG_PATH, cfgData.join("\n"))
}

const save = async (account, key, argv, cfgData, chooseAccountIndex, refresh = false) => {
  let answers 
  if (!refresh) {
    answers = await inquirer.prompt([
      {
        type: 'input',
        name: 'label',
        message: 'Enter a label to help you to remember:',
        validate: answer => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }
          return true
        },
        default: account ? account.label : argv.keywords.length > 0 ? argv.keywords.join(' ') : undefined
      },
      {
        type: 'input',
        name: 'host',
        message: 'Enter a ssh host:',
        validate: answer => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }
          return true
        },
        default: account ? account.hostname : undefined
      },
      {
        type: 'input',
        name: 'port',
        message: 'Enter a ssh port: (default is 22)',
        filter: answer => {
          return answer ? Number(answer) : 22
        },
        validate: answer => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }
  
          if (!Utils._.isInteger(Number(answer)) || Number(answer) > 65535) {
            return 'Please provide a valid ssh port.'
          }
  
          return true
        },
        default: account ? account.port : undefined
      },
      {
        type: 'input',
        name: 'username',
        message: 'Enter a ssh username:',
        validate: answer => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }
          return true
        },
        default: account ? account.username : undefined
      },
      {
        type: 'password',
        name: 'password',
        message: 'Enter a ssh password: (input nothing if use private key)'
      },
      {
        type: 'password',
        name: 'passwordConfirm',
        message: 'Confirm the password you just enter:',
        validate: (answer, answers) => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }
          if (answers.password !== answer) {
            return 'Confirmed password not match.'
          }
          return true
        },
        when: answers => {
          if (answers.password.length === 0) {
            return false
          }
          return true
        }
      },
      {
        type: 'input',
        name: 'privateKeyFile',
        message: 'Enter private key file path:',
        validate: answer => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }
  
          return true
        },
        when: answers => {
          if (answers.password.length === 0) {
            return true
          }
          return false
        },
        default: account ? account.privateKeyFile : undefined
      }
    ])
  } else {
    answers = account
  }
  
  
  if (chooseAccountIndex === -1) {
    cfgData.push(
      Utils._.template(CFG_TEMPLATE)({
        host: answers.host,
        port: answers.port,
        label: answers.label,
        username: answers.username,
        password: answers.password ? funcs.encrypt(answers.password, key) : '',
        privateKeyFile: answers.privateKeyFile ? funcs.encrypt(answers.privateKeyFile, key) : '' 
      })
    )
  } else {
    cfgData[chooseAccountIndex] = Utils._.template(CFG_TEMPLATE)({
      host: answers.host,
      port: answers.port,
      label: answers.label,
      username: answers.username,
      password: answers.password ? funcs.encrypt(answers.password, key) : '',
      privateKeyFile: answers.privateKeyFile ? funcs.encrypt(answers.privateKeyFile, key) : '' 
    })
  }

  fs.writeFileSync(CFG_PATH, cfgData.join("\n"))
}

export const plugin = 'ssh'
export const command = 'ssh [keywords..]'
export const desc = 'SSH tool, includes add/edit, delete, list|ls, login|to operations'

export const builder = function (yargs) {
  yargs.option('op', {
    default: false,
    describe: 'Set operatioin, default is login, support: add, edit, list, ls, delete, login, to.',
  })
  yargs.option('key', {
    default: false,
    describe: 'Key to be used to encrypt or decrypt ssh accounts.',
    alias: 'k'
  })

  yargs.option('opts', {
    default: false,
    describe: 'Extra options for SSH login',
    alias: 'o'
  })
}

export const handler = async function (argv) {
  const { Utils } = argv.$semo
  argv.op = argv.op || 'login'
  if (['add', 'edit', 'list', 'ls', 'delete', 'login', 'to'].indexOf(argv.op) === -1) {
    Utils.error(`Invalid operation: ${argv.op}!`)
  }

  let cfgFiltered
  argv.key = Utils.pluginConfig('key', '')
  argv.key = String(argv.key)
  await fs.ensureFileSync(CFG_PATH)
  let cfgData = fs.readFileSync(CFG_PATH, 'utf-8')
  if (!cfgData) {
    cfgData = []
  } else {
    cfgData = cfgData.trim().split('\n')
  }

  cfgFiltered = cfgData.filter(line => {
    return argv.keywords.every(keyword => line.indexOf(keyword) > -1)
  })

  if (argv.op === 'list' || argv.op === 'ls') {
    cfgFiltered.map(line => {
      let account = funcs.parseLine(line)
      console.log(Utils._.template(CFG_VIEW_TEMPLATE)({
        host: account.hostname,
        port: account.port,
        username: account.username,
        label: account.label
      }))
      
    })
    return
  }

  let chooseAccount
  if (argv.op !== 'add') {
    if (argv.op === 'delete' && cfgFiltered.length >= 1 || cfgFiltered.length > 1) {
      const accountChoose = await inquirer.prompt([
        {
          type: 'list',
          name: 'chooseAccount',
          message: 'Choose an account to continue',
          choices: cfgFiltered.map(line => {
            let account = funcs.parseLine(line)
  
            return {
              value: line,
              name: Utils._.template(CFG_VIEW_TEMPLATE)({
                host: account.hostname,
                port: account.port,
                username: account.username,
                label: account.label
              })
            }
          })
        }
      ])
      chooseAccount = accountChoose.chooseAccount
    } else if (cfgFiltered.length === 1) {
      chooseAccount = cfgFiltered[0]
    } else {
      Utils.error('No matched accounts were found!')
    }
  }

  if (argv.op !== 'delete' && argv.op !== 'list' && argv.op !== 'ls') {
    if (!argv.key) {
      ({ key: argv.key } = await inquirer.prompt([
        {
          type: 'password',
          name: 'key',
          message: 'Enter key to encrypt or decrypt:',
          validate: answer => {
            if (answer.length === 0) {
              return 'Please enter at least one char.'
            }
  
            return true
          },
        },
      ]))
    }
  }
  
  
  const key = Utils.md5(argv.key)
  const chooseAccountIndex = cfgData.indexOf(chooseAccount)
  let account
  if (chooseAccount) {
    account = funcs.parseLine(chooseAccount)
    account.password = account.password ? funcs.decrypt(account.password, key) : ''
    account.privateKeyFile = account.privateKeyFile ? funcs.decrypt(account.privateKeyFile, key) : ''
  }

  if (['add', 'edit'].indexOf(argv.op) > -1) {
    await save(account, key, argv, cfgData, chooseAccountIndex)
    Utils.info('Done!')
  } else if (argv.op === 'delete') {
    await deleteAndSave(cfgData, chooseAccountIndex)
    Utils.info('Done!')
  } else if (['login', 'to'].indexOf(argv.op) > -1) {

    try {
      if (account.privateKeyFile) {
        if (!fs.existsSync(path.resolve(account.privateKeyFile.replace('~', process.env.HOME)))) {
          Utils.error('Private key not exist')
        }
      }

      // Change encrypt info on each login
      await save(account, key, argv, cfgData, chooseAccountIndex, true)

      Utils.exec(Utils._.template(LOGIN_CMD)({
        script: path.resolve(__dirname, '../../', 'login.exp'),
        host: account.hostname,
        port: account.port,
        username: account.username,
        password: account.password ? account.password : '-',
        privateKeyFile: account.privateKeyFile ? account.privateKeyFile : '-',
        opts: argv.opts ? argv.opts : '-'
      }))
    } catch (e) {
      Utils.exec(e.message)
    }
  }
}