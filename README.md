# security_selinux

## 目标

SELinux （安全增强式 Linux ， Security-Enhanced Linux ）是 Linux 历史上杰出的安全子系统。 SELinux SIG 的工作目标是将 SELinux 引入 OpenHarmony 。

> 1. SELinux 是一组内核修改和用户空间工具，其提供了访问控制安全策略机制，包括了强制访问控制（ Mandatory Access Control ， MAC ）。
> 2. SELinux 已经被添加到各种 Linux 发行版中。其软件架构力图将安全决策的执行与安全策略分离，并简化涉及执行安全策略的软件的数量。

## 仓库

涉及到的仓库有以下几个。

| 仓库 | 源码目录 | 说明 |
| --- | --- | --- |
| [security_selinux](https://gitee.com/openharmony/security_selinux.git) | `base/security/selinux/` | 策略和一些自研接口 |
| [third_party_selinux](https://gitee.com/openharmony/third_party_selinux.git) | `third_party/selinux/` | SELinux 的主仓库 |
| [productdefine_common](https://gitee.com/openharmony/productdefine_common.git) | `productdefine/common/` | 添加 SELinux 组件定义 |
| [third_party_toybox](https://gitee.com/openharmony/third_party_toybox.git) | `third_party/toybox/` | 完善了 `ls` 的 SELinux 支持 |
| [startup_init_lite](https://gitee.com/openharmony/startup_init_lite.git) | `base/startup/init_lite/` | 系统启动加载策略并分化服务的标签 |
| [third_party_FreeBSD](https://gitee.com/openharmony/third_party_FreeBSD.git) | `third_party/FreeBSD/` | 提供 fts 库 |
| [third_party_pcre](https://gitee.com/openharmony/third_party_pcre2.git) | `third_party/pcre/` | 提供 pcre2 库 |
| [build](https://gitee.com/openharmony/build.git) | `build/` | 编译控制 |

## 架构

### 整体架构

![整体架构](docs/images/整体架构.png)

在 [third_party_selinux](https://gitee.com/openharmony/third_party_selinux.git) 中使用了下面四个 SELinux 的组件。

| 组件 | 来源 | 作用 | 形式 |
| --- | --- | --- | --- |
| `checkpolicy/` | [selinux/checkpolicy](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/checkpolicy) | `checkpolicy` | 可执行文件 |
| `libselinux/` | [selinux/libselinux](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/libselinux) | `libselinux.so`、`getenforce`、`setenforce` | 动态库 |
| `libsepol/` | [selinux/libsepol](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/libsepol) | 提供内部使用的 API | 动态库 |
| `seclic/` | [selinux/seclic](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/secilc) | `seclic` | 可执行文件 |

> 本仓库主要位于图中的编译侧，在板侧有两个动态库供 init 调用三方库。

### 目录结构

```
.
├── config                  # 板侧    三方库配置文件
├── docs                    #         文档资源
│   └── images
├── interfaces
│   ├── policycoreutils     # 板侧    libload_policy.so、librestorecon.so
│   │   ├── include
│   │   └── src
│   └── tools               # 板侧    load_policy、restorecon
│       ├── load_policy
│       └── restorecon
├── scripts                 # 编译侧  策略编译脚本
├── sepolicy                # 编译侧  策略文件
└── test                    #         测试程序
```

## 验证

### 编译代码

1. 根据文档[《获取源码》](https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/quick-start/quickstart-standard-sourcecode-acquire.md)获取主线代码。
1. 根据文档[《源码编译》](https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/quick-start/quickstart-standard-running-hi3516-build.md)编译主线代码。

### 编译镜像

运行以下命令编译打包支持 SELinux 的镜像。

```
./build.sh --product-name Hi3516DV300 --gn-args "build_selinux=true"
```

### 运行验证

将镜像烧录到 Hi3516DV300 开发板上，开机，通过串口拿到 Shell ，在其中执行。

```
ls -lZ /         # 查看文件标签是否成功
ps -eZ           # 查看进程标签是否成功
setenforce 1     # 进行各种操作，观察是否被拦截，以及串口是否有 avc denied
```
