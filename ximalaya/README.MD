# 喜马拉雅网页端登录协议
> 本项目仅供学习，不得用于商业用途，否则后果自负

## 功能

- ### 密码登录
- ### 自动通过滑块验证码

## 核心算法

### sessionId

- **算法: 时间戳转换36进制 + 6位随机字符** 

### signature

- **算法: sha1(urlencode(json对象) + 固定值)** 

### password

- **算法: rsa加密** 

### xm-sign

- **算法: md5(服务器时间戳)(随机1-100整数)服务器时间戳(随机1-100整数)当前时间戳** 

## 主要事项

> 当密码登录频繁时候会弹窗短信验证码验证
