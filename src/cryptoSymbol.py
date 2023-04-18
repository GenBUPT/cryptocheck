from enum import Enum

class SymbolType(Enum):
    BaseType = 0
    InterType = 1
    StringType = 2
    FuncRetType = 3
    DoubelType = 4
    CryptoType =5
    SSLIO = 6
    
"""
用来表示密码学应用子图中，函数参数的值的类型，为什么要这么做？这样可以省去C++编译依赖问题、动态检测的路径抵达问题。
一个符号有两个属性：类型，寄存器
类型用来对应操作方式，寄存器保存该类型的值，
在密码学应用中，将会造成密码学误用的参数分为三类：数值类型、字符串类型（字符串类型会保存字符串长度信息（待定））以及OpenSSL VAR
OpenSSL中包含更多的操作行为和语义


虚拟机包含若干寄存器和指令序列，从上到下遍历AST，最终计算出某个寄存器的值


"""    

class baseSymbol(object):
    symbolname = ""
    symbolType = 0
    
    
class InterSymbol(baseSymbol):
    symbolVal = 0
    def __init__(self,value):
        super().__init__()
        self.symbolType = SymbolType.InterType
        self.symbolVal = value
class FuncReturnSymbol(baseSymbol):
    def __init__(self) -> None:
        super().__init__()
        self.symbolType = SymbolType.FuncRetType
        self.funRet = 0


class VritualMachine():
    def __init__(self) -> None:
        self.regist = {}
        self.vaules = {}
    def addVar(self,s:baseSymbol):
        self.vaules[s.symbolname] = s
        