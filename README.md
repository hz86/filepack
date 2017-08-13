# filepack
美少女万華鏡 罪と罰の少女 pack文件 打包/解包工具

### 说明
支持 FilePackVer3.1
这工具支持《美少女万華鏡 罪と罰の少女》游戏中的pack文件解包和打包
需要注意的是，文件解包后输出的png文件其实不是真正的png文件。需要使用其他工具转换格式。

### 使用方法
```
打包命令 filepack31 enpack in_dir out_file
解包命令 filepack31 unpack in_file out_dir
```
### 例子
```
filepack31 enpack data0 data0.pack
filepack31 unpack data0.pack data0
```
