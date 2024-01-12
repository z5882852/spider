## 豆瓣搜索网站逆向
> 本项目仅供学习，不得用于商业用途，否则后果自负
### 项目介绍
豆瓣的数据在`window.__DATA__`中，但是这个数据是经过加密的，所以需要解密。

通过逆向研究，发现豆瓣算法包括以下:
- xxhash64
- rc4
- bplist

其中均可以通过Python的库进行解密，但是需要注意的是，rc4的key是动态的，需要计算获取。
- **xxhash库**: 
  - 用于计算xxhash64。
  - > pip install xxhash
- **pycryptodome库**: 
  - 用于计算rc4。
  - > pip install pycryptodome
- **plistlib库**: 
  - 用于解析bplist。由于豆瓣修改了bplist的解析方式，直接解析会报错，所以这里重写_read_object方法。
  - plistlib库是Python自带的，不需要安装。

