


# OSSFS

### 简介

ossfs能让您在Linux/Mac OS X 系统中把inspur oss的bucket挂载到本地文件系统中，您能够便捷的通过本地文件系统操作OSS上的对象，实现数据的共享。

### 功能

ossfs基于s3fs构建，具有s3fs的全部功能。主要功能包括：

* 支持posix文件系统的大部分功能，包括文件读写，目录，链接操作，权限，uid/gid，以及扩展属性（extended attributes）。
* 通过oss的multipart功能上传大文件。
* 通过server-side copy实现重命名。
* MD5 校验保证数据完整性。
* 元数据缓存。
* 数据缓存。
* 自定义region。

### 安装

#### 预编译的安装包

我们为常见的linux发行版制作了安装包：

- Ubuntu-16.04
- CentOS-7.0

对于Ubuntu，安装命令为：

```
sudo apt-get update
sudo apt-get install fuse libcurl4-gnutls libxml2 libssl
sudo dpkg -i ossfs_package
```

对于CentOS6.5及以上，安装命令为：

```
sudo yum localinstall ossfs_package
```

#### 源码安装


1. 保证具有以下依赖:

   * fuse >= 2.8.4
   * automake
   * gcc-c++
   * make
   * libcurl
   * libxml2
   * openssl

    可以采用一下命令进行安装依赖
   
    Ubuntu:

    ```
    sudo apt-get install automake autotools-dev g++ git libcurl4-gnutls-dev \
                        libfuse-dev libssl-dev libxml2-dev make pkg-config
    ```

    CentOS:

    ```
    sudo yum install automake gcc-c++ git libcurl-devel libxml2-devel \
                    fuse-devel make openssl-devel
    ```


2. 编译安装:

   ```
   cd ossfs-fuse
   ./autogen.sh
   ./configure
   make
   sudo make install
   ```

### 运行

设置access key/id信息，将其存放在`${HOME}/.passwd-ossfs`或者`/etc/passwd-ossfs`文件中，
注意这个文件的权限必须正确设置，建议设为600.

将access key/id信息保存到`${HOME}/.passwd-ossfs`中，并设置权限
```
echo ACCESS_KEY_ID:SECRET_ACCESS_KEY > ${HOME}/.passwd-ossfs
chmod 600 ${HOME}/.passwd-ossfs
```

将已创建好的桶`mybucket`挂载到指定目录`/path/to/mountpoint`：

```
ossfs mybucket /path/to/mountpoint
```
#### 示例

挂载:

将`mybucket`这个bucket挂载到`/tmp/ossfs`目录下，AccessKeyId是`osstestAccessKeyId`，
AccessKeySecret是`osstestAccessKeySecret`，oss endpoint是`http://oss.cn-north-3.inspurcloudoss.com/`

```
echo osstestAccessKeyId:osstestAccessKeySecret > ${HOME}/.passwd-ossfs
chmod 600 ${HOME}/.passwd-ossfs
mkdir /tmp/ossfs
ossfs mybucket /tmp/ossfs -ourl=http://oss.cn-north-3.inspurcloudoss.com/
```

卸载bucket:

```bash
umount /tmp/ossfs # root user
fusermount -u /tmp/ossfs # non-root user
```

#### 常用设置

* 如果使用ossfs的机器是浪潮云ECS，可以使用内网域名来**避免流量收费**和**提高速度**：

    ```
    ossfs mybucket /tmp/ossfs -ourl=http://oss-innet.cn-north-3.inspurcloudoss.com/
    ```

* 遇到错误可以打开debug模式

    ```
    ossfs mybucket /path/to/mountpoint -o passwd_file=${HOME}/.passwd-ossfs -o dbglevel=info -f -o curldbg
    ```

* 使用`ossfs --help`来查看更多可用的参数

### 局限性

与本地文件系统相比，ossfs提供的文件系统具有一些局限性。包括：

* 随机或者追加写文件会导致整个文件的重写。
* 元数据操作，例如list directory，性能较差，因为需要远程访问oss服务器。
* 文件/文件夹的rename操作不是原子的。
* 多个客户端挂载同一个oss bucket时，依赖用户自行协调各个客户端的行为。例如避免多个客户端写同一个文件等等。
* 不支持hard link。
* 不建议用在高并发读/写的场景，这样会让系统的load升高

### 相关链接

* [s3fs](https://github.com/s3fs-fuse/s3fs-fuse) - 通过fuse接口，挂载s3 bucket到本地文件系统。

### License

Copyright (C) 2010 Randy Rizun rrizun@gmail.com

Licensed under the GNU GPL version 2