Huawei ONT HG8120C upgrade file repack tool
==========

Tools for working with Huawei ONT HG8120C firmware upgrade file. It can unpack upgrade file and repack up after your modification. The repacking process will recalculate some checksums, after that, you can fire up on your device safely. It maybe also works for other devices in HG8xxx serials, but not tested.

Usage:
---------

1. `./hwfw unpack -r fw test/upgrade.bin`

		saving   /var/UpgradeCheck.xml(1069)...
		saving   /mnt/jffs2/equipment.tar.gz(84238)...
		saving   /mnt/jffs2/ProductLineMode(1)...
		saving   /mnt/jffs2/TelnetEnable(1)...
		saving x /tmp/duit9rr.sh(4801)...
		saving   /var/efs(68)...

1. Modifying files interest you under the `fw` directory.

		Usually the file marked with an `x`, it will be executed with `root` permission.

1. `./hwfw pack -r fw upgrade-mod.bin`
1. Happy upgrading or pwning.

About the `test/upgrade.bin`
------------------------
This is not a real firmware upgrade file, it just used to enable maintenance. So you are safe to use it without worry of bricking your device, unless your modification does.
