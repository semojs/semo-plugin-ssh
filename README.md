# semo-plugin-ssh

semo-plugin-ssh 顾名思义，这是一个用来管理 ssh 账号的命令行工具，基于 `Semo`，能够完成添加账户，列表和查询账户，删除账户，登录账户等操作。

## 安装和使用

```
$ npm i -g @semo/cli semo-plugin-ssh
$ semo ssh add
$ semo ssh edit
$ semo ssh list|ls
$ semo ssh delete
$ semo ssh login|to
```

## 帮助信息

```
semo ssh <op> [keywords..]

SSH tool, includes add/edit, delete, list|ls, login|to operations

选项：
  --key, -k                  Key to be used to encrypt and decrypt ssh accounts.                         [默认值: false]
  --opts, -o                 extra options for ssh login                                                 [默认值: false]
```

## 密钥管理

密钥用多种管理方式，其中常用的一种是放在 `Semo` 本机通用配置中：`~/.semo/.semorc.yml`

```yml
semo-plugin-ssh:
  key: [YOUR_SECRET_KEY]
```

这样，所有的账户都会使用这个 key 进行加解密。

另外，我们也可以把这个 key 隐藏起来，比如放到自己的云笔记里，这样，无论是创建账户加密时还是登录账户解密时都会询问等待输入 key，这样甚至可以做到不同的账户使用不同的 key 进行加密，当然这样管理起来就比较麻烦，不推荐使用；还可以通过命令的 `--key` 选项提供 key，这是最不推荐的一种方式，但是可以工作。

关于 Key 的选择，如果配置在配置文件中或者记在笔记里，可以设置的长一些，如果是自己记在心里，那就不宜过长。

账户配置文件会放到 `~/.semo/.ssh-accounts，但是由于是加密的，所以相对比较安全

## 特殊用法

- 配置中的 label 和 命令行中的 keywords 可以组合使用，在 edit, delete, list, login 子命令执行时，都可以通过 keywords 过滤 label，并且 keywords 支持多个，过滤取的是交集，方便快速定位
- login 命令的 `--opts` 参数将会传给 ssh 命令，因此我们可以做其他端口映射， tunnel 等用途

## 依赖和兼容性

这个工具依赖机器有安装 OpenSSH 和 expect 命令行工具，因此基本上大多数 Linux 以及 MacOS 都应该是支持的，Windows 就不支持了。

## 协议

MIT