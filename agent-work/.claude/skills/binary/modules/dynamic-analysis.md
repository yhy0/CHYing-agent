# 动态分析模块

## 适用场景
- 运行时行为跟踪（系统调用、库函数、网络）
- 反调试绕过与动态调试
- 运行时内存 dump 和数据提取
- Frida 动态插桩

## 检查清单

```yaml
行为跟踪:
  - [ ] strace -f 全面跟踪（首选）
  - [ ] strace -e network 网络调用
  - [ ] strace -e file 文件操作
  - [ ] ltrace -f 库函数跟踪
  - [ ] ltrace -e 'SSL_*+EVP_*' 加密函数

GDB 调试:
  - [ ] 入口点/main 断点
  - [ ] 关键函数断点（encrypt/decrypt/send/recv）
  - [ ] 内存 dump（解密后的数据）
  - [ ] 寄存器/栈检查
  - [ ] 条件断点

反调试检测:
  - [ ] ptrace(PTRACE_TRACEME)
  - [ ] /proc/self/status (TracerPid)
  - [ ] 时间检测 (rdtsc/gettimeofday)
  - [ ] 环境检测 (/proc/cpuinfo)
  - [ ] signal handler 检测 (SIGTRAP)

Frida 插桩:
  - [ ] 函数参数/返回值拦截
  - [ ] 内存读写监控
  - [ ] 加密函数 hook
  - [ ] 自定义函数替换
```

## 分析流程

### Step 1: strace 系统调用跟踪

```bash
# 全面跟踪（最常用，信息最丰富）
strace -f -s 500 -o /tmp/strace.log ./target
# -f: 跟踪子进程
# -s 500: 字符串截取长度 500
# -o: 输出到文件（避免与程序输出混合）

# 分类分析 strace 结果
grep 'connect\|bind\|listen\|accept' /tmp/strace.log     # 网络连接
grep 'open\|openat\|access' /tmp/strace.log               # 文件访问
grep 'write(' /tmp/strace.log | grep -v 'PIPE'            # 数据写入
grep 'read(' /tmp/strace.log                               # 数据读取
grep 'exec\|clone\|fork' /tmp/strace.log                  # 进程创建
grep 'socket\|setsockopt' /tmp/strace.log                 # Socket 创建
grep 'getaddrinfo\|gethostbyname' /tmp/strace.log         # DNS 解析
grep 'mmap\|mprotect\|brk' /tmp/strace.log                # 内存操作

# 专项跟踪
strace -f -e trace=network -s 500 ./target 2>&1           # 仅网络
strace -f -e trace=file -s 500 ./target 2>&1              # 仅文件
strace -f -e trace=process -s 500 ./target 2>&1           # 仅进程
strace -f -e trace=memory -s 500 ./target 2>&1            # 仅内存
strace -f -e trace=signal -s 500 ./target 2>&1            # 仅信号

# 带时间戳（分析执行顺序）
strace -f -t -s 500 -o /tmp/strace_timed.log ./target

# 统计系统调用频率
strace -c ./target 2>&1
```

### Step 2: ltrace 库函数跟踪

```bash
# 全面跟踪
ltrace -f -s 200 ./target 2>&1 | head -200

# 过滤特定函数
ltrace -f -e 'strlen+strcmp+memcmp+strncmp' ./target 2>&1  # 字符串比较
ltrace -f -e 'SSL_*+EVP_*+AES_*' ./target 2>&1            # 加密函数
ltrace -f -e 'malloc+free+calloc+realloc' ./target 2>&1   # 内存分配
ltrace -f -e 'connect+send+recv+read+write' ./target 2>&1 # 网络 I/O

# 跟踪库函数参数和返回值
ltrace -f -s 500 -e 'strcmp' ./target 2>&1
# 输出示例: strcmp("user_input", "correct_password") = -1
# 直接泄露比较目标！
```

### Step 3: GDB 动态调试

#### 基础调试

```bash
# 启动调试
gdb -q ./target

# 常用命令
b main              # main 断点
b *0x401234         # 地址断点
b encrypt           # 函数名断点
b *main+0x50        # 偏移断点

r                   # 运行
r < input.txt       # 带输入运行
r arg1 arg2         # 带参数运行

c                   # 继续执行
ni                  # 单步（不进入函数）
si                  # 单步（进入函数）
finish              # 执行完当前函数

# 信息查看
info registers      # 所有寄存器
p $rax              # 单个寄存器
x/20s $rdi          # 字符串
x/20wx $rsp         # 栈（hex word）
x/20gx $rsp         # 栈（hex giant/64-bit）
x/10i $rip          # 反汇编当前位置
bt                  # 调用栈

# 内存搜索
find /b 0x400000, 0x500000, 0x66, 0x6c, 0x61, 0x67  # 搜索 "flag"
```

#### 非交互式 GDB 脚本

```bash
# 一次性执行多条命令
gdb -batch \
    -ex 'b main' \
    -ex 'r' \
    -ex 'info registers' \
    -ex 'x/20s $rdi' \
    -ex 'bt' \
    -ex 'c' \
    ./target

# GDB Python 脚本
cat > /tmp/gdb_script.py << 'EOF'
import gdb

gdb.execute("b main")
gdb.execute("r")

# 查看所有寄存器
regs = gdb.execute("info registers", to_string=True)
print(regs)

# 提取特定内存
rdi = int(gdb.parse_and_eval("$rdi"))
mem = gdb.execute(f"x/s {rdi}", to_string=True)
print(f"RDI points to: {mem}")

gdb.execute("c")
EOF

gdb -q -batch -x /tmp/gdb_script.py ./target
```

#### 内存 dump

```bash
# 在关键点 dump 内存
gdb -batch \
    -ex 'b decrypt_function' \
    -ex 'r' \
    -ex 'finish' \
    -ex 'dump binary memory /tmp/decrypted.bin $rax ($rax+0x100)' \
    ./target

# 查看内存映射并 dump 指定段
gdb -batch \
    -ex 'b main' \
    -ex 'r' \
    -ex 'info proc mappings' \
    ./target

# dump 整个 .text 段（运行时可能已脱壳）
gdb -batch \
    -ex 'b main' \
    -ex 'r' \
    -ex 'dump binary memory /tmp/text_dump.bin 0x400000 0x500000' \
    ./target
```

#### 条件断点（高级）

```bash
# 当 strcmp 的第二个参数包含特定字符串时断下
gdb -q ./target
b strcmp
condition 1 ((char*)$rsi)[0] == 'f' && ((char*)$rsi)[1] == 'l'

# 数据断点（监控内存写入）
watch *0x404060
# 每次该地址被写入时触发
```

### Step 4: 反调试绕过

#### ptrace 检测绕过

```bash
# 方法 1: LD_PRELOAD 劫持
cat > /tmp/anti_ptrace.c << 'EOF'
#include <sys/ptrace.h>
long ptrace(int request, ...) {
    return 0;
}
EOF
gcc -shared -fPIC /tmp/anti_ptrace.c -o /tmp/anti_ptrace.so
LD_PRELOAD=/tmp/anti_ptrace.so ./target

# 方法 2: GDB 直接 patch
gdb -q ./target
b main
r
# 找到 ptrace 调用，设置返回值
catch syscall ptrace
c
set $rax = 0
c
```

#### /proc 检测绕过

```bash
# 检查 TracerPid
cat /proc/self/status | grep TracerPid

# LD_PRELOAD 劫持 fopen
cat > /tmp/anti_proc.c << 'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

FILE *fopen(const char *path, const char *mode) {
    typedef FILE *(*real_fopen)(const char *, const char *);
    real_fopen orig = (real_fopen)dlsym(RTLD_NEXT, "fopen");

    if (strstr(path, "/proc/self/status") || strstr(path, "TracerPid")) {
        return orig("/dev/null", mode);
    }
    return orig(path, mode);
}
EOF
gcc -shared -fPIC /tmp/anti_proc.c -o /tmp/anti_proc.so -ldl
LD_PRELOAD=/tmp/anti_proc.so ./target
```

#### 时间检测绕过

```bash
# 方法 1: LD_PRELOAD 劫持时间函数
cat > /tmp/anti_time.c << 'EOF'
#include <time.h>
#include <sys/time.h>

static time_t base_time = 0;

time_t time(time_t *t) {
    if (!base_time) base_time = 1000000;
    time_t result = base_time++;
    if (t) *t = result;
    return result;
}

int gettimeofday(struct timeval *tv, void *tz) {
    if (!base_time) base_time = 1000000;
    if (tv) {
        tv->tv_sec = base_time++;
        tv->tv_usec = 0;
    }
    return 0;
}
EOF
gcc -shared -fPIC /tmp/anti_time.c -o /tmp/anti_time.so
LD_PRELOAD=/tmp/anti_time.so ./target
```

### Step 5: Frida 动态插桩

```python
#!/usr/bin/env python3
"""Frida hook 常用模板"""
import frida
import sys

# 目标进程
pid = frida.spawn(["./target"])
session = frida.attach(pid)

script = session.create_script("""
// Hook 字符串比较函数（泄露比较目标）
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        var s1 = Memory.readUtf8String(args[0]);
        var s2 = Memory.readUtf8String(args[1]);
        if (s1.length > 3 || s2.length > 3) {
            console.log("[strcmp] '" + s1 + "' vs '" + s2 + "'");
        }
    }
});

// Hook 加密函数（获取明文和密钥）
var EVP_EncryptInit = Module.findExportByName(null, "EVP_EncryptInit_ex");
if (EVP_EncryptInit) {
    Interceptor.attach(EVP_EncryptInit, {
        onEnter(args) {
            console.log("[EVP_EncryptInit_ex] cipher type at: " + args[1]);
            // args[3] = key, args[4] = iv
            if (args[3] != ptr(0)) {
                console.log("  Key: " + hexdump(args[3], {length: 32}));
            }
            if (args[4] != ptr(0)) {
                console.log("  IV:  " + hexdump(args[4], {length: 16}));
            }
        }
    });
}

// Hook send/write（监控网络输出）
Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter(args) {
        var size = args[2].toInt32();
        if (size > 0 && size < 10000) {
            console.log("[send] " + size + " bytes:");
            console.log(hexdump(args[1], {length: Math.min(size, 256)}));
        }
    }
});

// Hook recv/read（监控网络输入）
Interceptor.attach(Module.findExportByName(null, "recv"), {
    onLeave(retval) {
        var size = retval.toInt32();
        if (size > 0 && size < 10000) {
            console.log("[recv] " + size + " bytes:");
            console.log(hexdump(this.buf, {length: Math.min(size, 256)}));
        }
    },
    onEnter(args) {
        this.buf = args[1];
    }
});

// Hook 自定义函数（按地址）
var base = Module.findBaseAddress("target");
if (base) {
    Interceptor.attach(base.add(0x1234), {
        onEnter(args) {
            console.log("[custom_func] arg0 = " + args[0]);
            console.log("  data: " + hexdump(args[0], {length: 64}));
        },
        onLeave(retval) {
            console.log("[custom_func] returned: " + retval);
        }
    });
}
""")

script.on('message', lambda msg, data: print(f"[msg] {msg}"))
script.load()
frida.resume(pid)
sys.stdin.read()
```

### Step 6: /proc/pid 运行时分析

```bash
# 启动目标进程
./target &
PID=$!

# 内存映射
cat /proc/$PID/maps

# 命令行参数
cat /proc/$PID/cmdline | tr '\0' ' '

# 环境变量
cat /proc/$PID/environ | tr '\0' '\n'

# 打开的文件描述符
ls -la /proc/$PID/fd/

# 网络连接
cat /proc/$PID/net/tcp
cat /proc/$PID/net/tcp6

# 内存 dump（需要 root 或同用户）
dd if=/proc/$PID/mem bs=1 skip=$((0x400000)) count=$((0x100000)) of=/tmp/mem_dump.bin 2>/dev/null

kill $PID
```

## 常见场景

### 场景 1: 程序读取输入并比较

```bash
# ltrace 直接泄露比较结果
ltrace -f -e 'strcmp+strncmp+memcmp' ./target <<< "test"
# 输出: strcmp("test", "s3cr3t_fl4g") = ...
```

### 场景 2: 程序解密内部数据

```bash
# 在解密函数返回后 dump
gdb -batch \
    -ex 'b decrypt' \
    -ex 'r' \
    -ex 'finish' \
    -ex 'x/s $rax' \
    -ex 'dump binary memory /tmp/decrypted.bin $rax ($rax+256)' \
    ./target
```

### 场景 3: 程序检测调试器

```bash
# 先检测反调试手段
strace -f -e trace=ptrace ./target 2>&1 | grep ptrace
# 如果看到 ptrace(PTRACE_TRACEME) → 使用 LD_PRELOAD 绕过
```

## 工具速查

```bash
# strace
strace -f -s 500 -o /tmp/log ./target      # 全面跟踪
strace -c ./target                          # 统计
strace -f -e network ./target               # 仅网络

# ltrace
ltrace -f -s 200 ./target                   # 全面跟踪
ltrace -e 'strcmp+memcmp' ./target           # 字符串比较

# gdb
gdb -batch -ex 'b main' -ex 'r' -ex 'bt' ./target  # 非交互
gdb -q -x script.py ./target                        # 脚本模式

# frida
frida -f ./target -l hook.js                # 注入 hook
frida-trace -f ./target -i 'strcmp'         # 快速 trace
```
