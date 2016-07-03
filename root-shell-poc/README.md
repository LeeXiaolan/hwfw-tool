- 使用方法请参考[PWN华为HG8120C光猫（三）][part-3]
- 需要准备好tftp服务器，`payload-mod.bin` 中预设tftp服务器IP为 `192.168.1.2`，请确认tftp服务IP。
- `payload-mod.bin` 加载到目标设备后，若 `ssh` 到目标设备 `2222` 端口失败，请开启tftp服务器的写权限，重新加载，此时将在tftp目录下生成 `dropbear.log`，从中查看`dropbear`执行失败原因。如果找不到 `dropbear.log`请使用tftp客户端在电脑上确认tftp服务器确实可写。
- `rsa` 和 `rsa.pub` 是 `ssh-keygen` 生成的，为了安全，请自行生成。`hostkey` 也可用 `dropbearkey` 自行生成。
- 不能正常获取root shell的原因可能很多，包中文件，在我设备 `hg8120c` 上确认执行成功，其它型号可能由于 `ublibc` 版本不同而失败，自行使用对应版本 `uclibc` 编译 `dropbear` 即可。

[part-3]: <http://blog.leexiaolan.tk/pwn-huawei-hg8120c-ont-upgrade-pack-format-part-3> (获取HG8120C光猫root shell)
