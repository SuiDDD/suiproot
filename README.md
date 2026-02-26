## 🤯SuiPRoot
在 Windows Subsystem for Linux (WSL) 环境下使用 Android NDK 交叉编译 PRoot 二进制文件
## 📝项目简介
本项目提供了一套完整的自动化脚本，用于在 WSL (Ubuntu/Debian) 环境下，利用最新的 Android NDK r29 工具链，为 AArch64 架构的 Android 设备编译定制版的 PRoot。
该构建方案采用了 “混合链接策略”：
 * 静态集成 Talloc: 将 talloc 2.4.2 直接嵌入 proot 主程序，消除对外部非系统库的依赖。
 * 动态链接 Bionic: 链接至 Android 原生 libc.so 和 libdl.so，确保在 API 35 (Android 15) 上的系统调用兼容性与稳定性。
🛠️ 技术特性
 * WSL 友好: 适配 Linux 子系统下的交叉编译路径解析。
 * 一命速通: 脚本提供下载+补丁+编译等一条龙服务，支持continue断点续编。
 * 现代 Android 适配: 针对 ashmem 和 memfd 进行了源码级头文件补丁。
 * 二进制分析:
   * Type: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /system/bin/linker64, stripped
   * Dependencies: 仅依赖 libc.so 和 libdl.so，极其易于在 /data/local/tmp 部署。
## 🍵如何使用
```
curl -fSSLO https://raw.githubusercontent.com/SuiDDD/suiproot/main/suiproot.sh && chmod +x suiproot.sh && ./suiproot.sh
```
若已将`suiproot.sh`下载到本地,可直接执行
```
sudo chmod +x ./suiproot.sh && ./suiproot.sh
```
若编译中途退出,可断点续编(前提是已将源码等下载完毕)
```
sudo chmod +x ./suiproot.sh && ./suiproot.sh continue
```
## 📑开源协议
[GPL-3.0-or-later](https://github.com/SuiDDD/suiproot/blob/main/LICENSE)
## ❤️特别鸣谢
[Android NDK](https://developer.android.com/ndk)

[PRoot](https://github.com/proot-me/proot)

[Talloc](https://talloc.samba.org/)

[Termux](https://github.com/termux)

[Termux-PRoot](https://github.com/termux/proot)

[WSL2(Ubuntu)](https://github.com/microsoft/WSL2-Linux-Kernel)

...
<div align="right">
<strong>SuiDDD</strong><br>
2026.02.26 21:00<br>
<em>Baotou, Inner Mongolia, China</em>
</div>
