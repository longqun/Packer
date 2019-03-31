这里是PE文件加壳程序。
===

<br>
1:目前支持源程序16个区段的压缩。对于超过16个的区段可以修改数据结构实现。
<br>
2:不支持加过其他壳的程序加壳，目前只支持exe文件。
<br>
3:支持Windows10下执行，对于重定位进行了处理，可以支持随机地址的执行。
<br>

编译流程：
-------
将Packer和Stub都设置成x86 release下编译即可
<br>

文件运行截图:
-------
<br>
![image](https://github.com/longqun/Packer/raw/master/ScreenShot/5.jpg)

程序处理流程:
-------
1读取加壳文件，外壳DLL
<br>
2:选择加壳文件需要压缩的地方，对于资源段选择不压缩，其他区段都进行压缩。
<br>
3:重新构造区段表，分别有这么几个区段 .OldDat(原始压缩的数据) .Shell(外壳DLL代码) .tls(用来支持加壳tls程序) .CRT(用来支持加壳tls程序) .reloc(外壳DLL重定位信息) .rcsc(资源如果有的话)
<br>
4:利用aPLib进行压缩，将压缩之后的数据复制到目标文件.OldDat区段缓冲区。
<br>
5:对于外壳DLL进行重定位，资源数据修复
<br>
6:设置导出变量的数据，在外壳DLL中将使用到的变量
<br>
7:写入文件
<br>

原始区段信息
<br>
![image](https://github.com/longqun/Packer/raw/master/ScreenShot/1.jpg)
<br>
原始目录
<br>
![image](https://github.com/longqun/Packer/raw/master/ScreenShot/2.jpg)
<br>
加壳后的区段信息
<br>
![image](https://github.com/longqun/Packer/raw/master/ScreenShot/3.jpg)
<br>
加壳之后的目录表
<br>
![image](https://github.com/longqun/Packer/raw/master/ScreenShot/4.jpg)