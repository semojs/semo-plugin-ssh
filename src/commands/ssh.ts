import { input, password, select } from '@inquirer/prompts'
import { ArgvExtraOptions, error, exec, info, md5 } from '@semo/core'
import { ensureFileSync } from 'fs-extra'
import _ from 'lodash'
import fs from 'node:fs'
import { decrypt, encrypt, parseLine } from '../common/funcs.js'
import crypto from 'node:crypto'

import { fileURLToPath } from 'node:url'
import path from 'node:path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

export const plugin = 'ssh'
export const command = 'ssh [keywords..]'
export const desc =
  'SSH tool, includes add/edit, delete, list|ls, login|to operations'

export const builder = function (yargs) {
  yargs.option('op', {
    describe:
      'Set operatioin, default is login, support: add, edit, list, ls, delete, login, to.',
  })
  yargs.option('encrypt-key', {
    describe: 'Key to be used to encrypt or decrypt ssh accounts.',
    alias: 'key',
  })

  yargs.option('opts', {
    describe: 'Extra options for SSH login',
  })
}

const CFG_PATH = `${process.env.HOME}/.semo/.ssh-accounts`
const CFG_TEMPLATE =
  'ssh://${username}:${password}:${privateKeyFile}@${host}:${port} ${label}'
const CFG_VIEW_TEMPLATE = 'ssh://${username}@${host}:${port} ${label}'
const LOGIN_CMD =
  "expect ${script} ${username} ${host} ${port} '${password}' ${privateKeyFile} ${opts}"

export const handler = async function (argv: ArgvExtraOptions) {
  try {
    if (argv.op === 'generate-key' || argv.op === 'gen-key') {
      console.log(crypto.randomBytes(32).toString('hex'))
      info('Done!')
      return
    }
    argv.op = argv.op || 'login'
    if (
      [
        'add',
        'edit',
        'list',
        'ls',
        'delete',
        'login',
        'to',
        'generate-key',
        'gen-key',
      ].indexOf(argv.op) === -1
    ) {
      error(`Invalid operation: ${argv.op}!`)
      return
    }

    argv.encryptKey = argv.$core.getPluginConfig('encryptKey', '')
    argv.encryptKey = String(argv.encryptKey)
    ensureFileSync(CFG_PATH)
    const cfgDataRead = fs.readFileSync(CFG_PATH, 'utf-8')
    let cfgData: string[] = []
    if (cfgDataRead) {
      cfgData = cfgDataRead.trim().split('\n')
    }

    const cfgFiltered =
      argv.keywords && argv.keywords.length > 0
        ? cfgData.filter((line) => {
            return argv.keywords.every((keyword) => line.indexOf(keyword) > -1)
          })
        : cfgData

    if (argv.op === 'list' || argv.op === 'ls') {
      cfgFiltered.map((line) => {
        const account = parseLine(line)
        console.log(
          _.template(CFG_VIEW_TEMPLATE)({
            host: account.hostname,
            port: account.port,
            username: account.username,
            label: account.label,
          })
        )
      })
      return
    }

    let chooseAccount
    if (argv.op !== 'add') {
      if (
        (argv.op === 'delete' && cfgFiltered.length >= 1) ||
        cfgFiltered.length > 1
      ) {
        chooseAccount = await select({
          message: 'Choose an account to continue',
          choices: cfgFiltered.map((line) => {
            const account = parseLine(line)

            return {
              value: line,
              name: _.template(CFG_VIEW_TEMPLATE)({
                host: account.hostname,
                port: account.port,
                username: account.username,
                label: account.label,
              }),
            }
          }),
        })
      } else if (cfgFiltered.length === 1) {
        chooseAccount = cfgFiltered[0]
      } else {
        error('No matched accounts were found!')
      }
    }

    if (argv.op !== 'delete' && argv.op !== 'list' && argv.op !== 'ls') {
      if (!argv.encryptKey) {
        argv.encryptKey = await password({
          message: 'Enter encryptKey to encrypt or decrypt:',
          validate: (answer) => {
            if (answer.length === 0) {
              return 'Please enter at least one char.'
            }

            return true
          },
        })
      }
    }

    const key =
      argv.encryptKey.length !== 64
        ? md5(argv.encryptKey) + md5(argv.encryptKey)
        : argv.encryptKey
    const chooseAccountIndex = cfgData.indexOf(chooseAccount)
    let account
    if (chooseAccount) {
      account = parseLine(chooseAccount)
      account.password = account.password ? decrypt(account.password, key) : ''
      account.privateKeyFile = account.privateKeyFile
        ? decrypt(account.privateKeyFile, key)
        : ''
    }

    if (['add', 'edit'].indexOf(argv.op) > -1) {
      await save(account, key, argv, cfgData, chooseAccountIndex)
      info('Done!')
    } else if (argv.op === 'delete') {
      await deleteAndSave(cfgData, chooseAccountIndex)
      info('Done!')
    } else if (['login', 'to'].indexOf(argv.op) > -1) {
      if (account.privateKeyFile) {
        if (!account.privateKeyFile.startsWith('~')) {
          account.privateKeyFile = '~/.ssh/' + account.privateKeyFile
        }
        if (
          !fs.existsSync(
            path.resolve(account.privateKeyFile.replace('~', process.env.HOME))
          )
        ) {
          error('Private key not exist')
        }
      }

      // Change encrypt info on each login
      await save(account, key, argv, cfgData, chooseAccountIndex, true)

      exec(
        _.template(LOGIN_CMD)({
          script: path.resolve(__dirname, '../../', 'login.exp'),
          host: account.hostname,
          port: account.port,
          username: account.username,
          password: account.password ? account.password : '-',
          privateKeyFile: account.privateKeyFile ? account.privateKeyFile : '-',
          opts: argv.opts ? argv.opts : '-',
        })
      )
    }
  } catch (e) {
    if (argv.verbose) {
      error(e)
    } else {
      exec(e.message)
    }
  }
}

const deleteAndSave = async (cfgData, chooseAccountIndex) => {
  cfgData.splice(chooseAccountIndex, 1)
  fs.writeFileSync(CFG_PATH, cfgData.join('\n'))
}

const save = async (
  account,
  key,
  argv,
  cfgData,
  chooseAccountIndex,
  refresh = false
) => {
  let answers: Record<string, string> = {}
  if (!refresh) {
    const questions = [
      {
        type: 'input',
        name: 'label',
        message: 'Enter a label to help you to remember:',
        validate: (answer) => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }
          return true
        },
        default: account
          ? account.label
          : argv.keywords && argv.keywords.length > 0
            ? argv.keywords.join(' ')
            : undefined,
      },
      {
        type: 'input',
        name: 'host',
        message: 'Enter a ssh host:',
        validate: (answer) => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }
          return true
        },
        default: account ? account.hostname : undefined,
      },
      {
        type: 'input',
        name: 'port',
        message: 'Enter a ssh port: (default is 22)',
        filter: (answer) => {
          return answer ? Number(answer) : 22
        },
        validate: (answer) => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }

          if (!_.isInteger(Number(answer)) || Number(answer) > 65535) {
            return 'Please provide a valid ssh port.'
          }

          return true
        },
        default: account ? account.port : undefined,
      },
      {
        type: 'input',
        name: 'username',
        message: 'Enter a ssh username:',
        validate: (answer) => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }
          return true
        },
        default: account ? account.username : undefined,
      },
      {
        type: 'password',
        name: 'password',
        message: 'Enter a ssh password: (input nothing if use private key)',
      },
      {
        type: 'password',
        name: 'passwordConfirm',
        message: 'Confirm the password you just enter:',
        validate: (answer) => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }

          if (answer !== answers.password) {
            return 'Passwords do not match.'
          }

          return true
        },
      },
      {
        type: 'input',
        name: 'privateKeyFile',
        message: 'Enter private key file path:',
        validate: (answer) => {
          if (answer.length === 0) {
            return 'Please enter at least one char.'
          }

          return true
        },

        default: account ? account.privateKeyFile : undefined,
      },
    ]
    for (const question of questions) {
      if (question.type === 'input') {
        if (
          question.name === 'privateKeyFile' &&
          answers.password.length !== 0
        ) {
          continue
        }
        const test = await input({
          message: question.message,
          default: question.default,
          validate: question.validate,
        })
        answers[question.name] = test
      } else if (question.type === 'password') {
        if (
          question.name === 'passwordConfirm' &&
          answers.password.length === 0
        ) {
          continue
        }

        answers[question.name] = await password({
          message: question.message,
          validate: question.validate,
        })
      }
    }
  } else {
    answers = account
  }

  if (chooseAccountIndex === -1) {
    cfgData.push(
      _.template(CFG_TEMPLATE)({
        host: answers.host,
        port: answers.port,
        label: answers.label,
        username: answers.username,
        password: answers.password ? encrypt(answers.password, key) : '',
        privateKeyFile: answers.privateKeyFile
          ? encrypt(answers.privateKeyFile, key)
          : '',
      })
    )
  } else {
    cfgData[chooseAccountIndex] = _.template(CFG_TEMPLATE)({
      host: answers.host,
      port: answers.port,
      label: answers.label,
      username: answers.username,
      password: answers.password ? encrypt(answers.password, key) : '',
      privateKeyFile: answers.privateKeyFile
        ? encrypt(answers.privateKeyFile, key)
        : '',
    })
  }

  fs.writeFileSync(CFG_PATH, cfgData.join('\n'))
}
