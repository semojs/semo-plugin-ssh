import * as funcs from '../common/funcs'
import { Utils } from '@semo/core'

export const hook_repl = new Utils.Hook('semo', () => {
  return {
    ssh: funcs
  }
})