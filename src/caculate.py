from z3 import *


class Slover:
    """
        从密码学应用子图中加载一个符号表
        符号表中包含关键函数中影响参数最终值的所有符号
        然后计算
        定义：首先生成虚拟的符号funName_p1 ,funName_p2 ...
        然后递归计算p1 p2 p3 ...的值
        重复这个过程
        注：c函数调用是利用函数栈调用的
        """
    def __init__(self) -> None:
        pass
    