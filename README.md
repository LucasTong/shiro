# shiro
安全框架


    Apache Shiro是一个强大且易用的Java安全框架,执行身份验证、授权、密码学和会话管理。相比较Spring Security，shiro有小巧、简单、易上手等的优点。所以很多框架都在使用shiro。

    Shiro包含了三个核心组件：Subject, SecurityManager 和 Realms。

    Subject代表了当前用户的安全操作。
    SecurityManager则管理所有用户的安全操作。它是Shiro框架的核心，典型的Facade模式，Shiro通过SecurityManager来管理内部组件实例，并通过它来提供安全管理的各种服务。
    Realm充当了Shiro与应用安全数据间的“桥梁”或者“连接器”。也就是说，当对用户执行认证（登录）和授权（访问控制）验证时，Shiro会从应用配置的Realm中查找用户及其权限信息。

