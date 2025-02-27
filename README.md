# BushSEC PE Injector
一款基于 Python 的 PE 文件注入简易工具，用于将 Shellcode 注入 Windows 可执行文件。

## 概述

`BushSEC PE Injector` 是一款用于将自定义 Shellcode 注入 Windows PE（可移植执行文件）的工具。它支持两种注入模式：单阶段注入（模式1）和多阶段注入（模式2），为不同使用场景提供了灵活性。工具通过 PyQt5 提供图形用户界面，并利用 `pefile` 库进行 PE 文件操作。

## 功能特性

- **模式1（单阶段注入）**：将 Shellcode 注入并修改 PE 文件入口点，直接执行 Shellcode。
- **模式2（多阶段注入）**：注入 Stub 代码，使用 `VirtualAlloc` 分配内存，通过 `CreateThread` 在新线程中执行 Shellcode，并返回原始程序逻辑。(还未完成，目前存在BUG)
- 支持 32 位和 64 位 PE 文件。
- 友好的图形用户界面，便于选择文件和模式。
- 详细的日志记录，便于调试。
- 在注入后验证 PE 文件完整性。

## 安装

### 依赖
- Python 3.x
- `pefile`：`pip install pefile`
- `PyQt5`：`pip install PyQt5`

