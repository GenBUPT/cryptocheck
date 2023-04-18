import csv
import json
import pandas as pd
from statemachine import StateMachine, State

import queue


"""

算法描述：
    由CSV构成的图分为几部分：
    AST 构成AST解析（用来解析函数名）
    DOM 代码中的一条语句位置（包含多个CFG节点）
    FLOW_TO
    DEF 符号的定义位置
    USE 使用了什么变量（处理一下）
    REACHES ？
    CONTROLS 控制流图
    IS_FUNCTION_OF_CFG 划定函数范围
    symbol 符号
    
    利用 IS_FUNCTION_OF_CFG 来提取每个函数
    
    利用 DOM AST来获得每条语句中是否调用关键函数
    
    FLOW_TO 来进行数据流分析，获得子图（子语句）
    
    图搜索算法+自己设计的符号执行，来确定是否有密码学误用
    DOM 恢复代码，利用clang进行编译，进行符号执行来确定是否存在漏洞
    
    符号执行算法：
    首先匹配关键函数，然后依次对返回值、各个参数值进行符号执行，检测是否存在对应的密码学误用
    
    针对回调函数，使用工具
    """
keyFunctions = ['AES_ecb_encrypt',"AES_set_encrypt_key","EVP_EncryptInit","AES_cbc_encrypt","EVP_BytesToKey","printf"]
nextType = ['IS_AST_PARENT']
def getNodes(data:pd.DataFrame):
    statements = {}
    for index in data.index:
        state = {}
        for label in data.columns:
            state[label] = data[label][index]
        statements[index+1] = state
    return statements
def getEdges(data:pd.DataFrame):
    uptree = {}
    downtree = {}
    for index in data.index:
        start = data['start'][index]
        end = data['end'][index]
        if start not in uptree:
            uptree[start] = []
        if end not in downtree:
            downtree[end] = []
        uptree[start].append({'to':end,'type':data['type'][index],'var':data['var'][index]})
        downtree[end].append({'to':start,'type':data['type'][index],'var':data['var'][index]})
        return uptree,downtree
EdgeType = ['DEF', 'REACHES', 'IS_FUNCTION_OF_AST', 'CONTROLS', 'DOM', 'IS_FUNCTION_OF_CFG', 'FLOWS_TO', 'IS_FILE_OF', 'USE', 'POST_DOM', 'IS_AST_PARENT']
class Graph:
    """
    代码属性图结构，读取csv并生成图
    """
    """
    nodes: 记录CPG中的节点
    edges: 一个词典：分为正序和反序边
    以type为索引
    """
    nodes = []
    edges = {
                'DEF':{'start':{},'end':{}},
                'REACHES':{'start':{},'end':{}},
                'IS_FUNCTION_OF_AST':{'start':{},'end':{}},
                'CONTROLS':{'start':{},'end':{}},
                'DOM':{'start':{},'end':{}},
                'IS_FUNCTION_OF_CFG':{'start':{},'end':{}},
                'FLOWS_TO':{'start':{},'end':{}},
                'IS_FILE_OF':{'start':{},'end':{}},
                'USE':{'start':{},'end':{}},
                'POST_DOM':{'start':{},'end':{}},
                'IS_AST_PARENT':{'start':{},'end':{}}
            }
    def __init__(self,nodes,edges):
        for index in edges.index:
            edgeType = edges['type'][index]
            edgeStart = edges['start'][index]
            edgeEnd = edges['end'][index]
            if edgeStart not in self.edges[edgeType]['start']:
                self.edges[edgeType]['start'][edgeStart] = []
            if edgeEnd not in self.edges[edgeType]['end']:
                self.edges[edgeType]['end'][edgeEnd] = []
            self.edges[edgeType]['start'][edgeStart].append({'to':edgeEnd,'var':edges['var'][index]})
            self.edges[edgeType]['end'][edgeEnd].append({'to':edgeStart,'var':edges['var'][index]})
        statements = [None]* (len(nodes.index)+1)
        for index in nodes.index:
            state = {}
            for label in nodes.columns:
                state[label] = nodes[label][index]
            statements[index+1] = state
        self.nodes = statements
def getFunctionDef(graph:Graph):
    """将整个CPG以函数定义为单元，分割CPG成若干子图

    Args:
        graph (Graph): CPG
    """
    funDef = []
    for funEntry in graph.edges['IS_FUNCTION_OF_AST']['start'].keys():
        for f in graph.edges['IS_FUNCTION_OF_AST']['start'][funEntry]:
            
            funDef.append(f['to'])
    return funDef
def findStatementIndex(graph:Graph,node:int):
    """向上搜索图，找到一条具体表达式的位置（带行号）

    Args:
        graph (Graph): _description_
        node (int): _description_

    Returns:
        int : 函数调用所在的行的位置
    """
    astNode = [node]
    while len(astNode) > 0:
        for _ in range(len(astNode)):
            lastNode = astNode.pop()
            if pd.notnull(graph.nodes[lastNode]['location']):
                return lastNode
            for lastNodes in graph.edges['IS_AST_PARENT']['end'][lastNode]:
                astNode.append(lastNodes['to'])
    return -1
def processFunctionDef(graph:Graph,funAST:int):
    """处理一个函数声明

    Args:
        graph (Graph): CPG
        funRange (tuple): 某个函数的定义域
        流程：
        1.获取所有关键函数
        2.利用数据流关系将一些子图合成大图
        3.最终获得一组密码学应用子图
    """
    astNode = [funAST]
    keyDom = []
    while len(astNode) > 0:
        for _ in range(len(astNode)):
            node = astNode.pop()
            nodeType = graph.nodes[node]['type']
            nodeVar = graph.nodes[node]['code']
            if nodeType == "Callee" and nodeVar in keyFunctions:
                domNode = findStatementIndex(graph,node)
                if domNode > -1:
                    keyDom.append(domNode)
            for nextNode in graph.edges['IS_AST_PARENT']['start'][node]:
                nextIndex = nextNode['to']
                if nextIndex in graph.edges['IS_AST_PARENT']['start']:
                    astNode.append(nextNode['to'])
    return keyDom
def getArg(argNode:int,graph:Graph):
    trueType = ['Identifier',"PrimaryExpression"]
    argument = [argNode]
    args = dict()

    while len(argument)> 0:
        for _ in range(len(argument)):
            node = argument.pop()
            argtype = graph.nodes[node]['type']
            if argtype in trueType:
                argvalue = graph.nodes[node]['code']
                args[node] = {"type":argtype,"value":argvalue}
            if node not in graph.edges['IS_AST_PARENT']['start']:
                continue
            for next in graph.edges['IS_AST_PARENT']['start'][node]:
                argument.append(next['to'])
    return args
def getArgumentList(funNode:int,graph:Graph):
    nodeQueue = [funNode]
    argNode = -1
    while len(nodeQueue) > 0:
        for _ in range(len(nodeQueue)):
            node = nodeQueue.pop()
            if graph.nodes[node]['type'] == "ArgumentList":
                argNode = node
                break
            for next in graph.edges['IS_AST_PARENT']['start'][node]:
                nodeQueue.append(next['to'])
        if argNode != -1:
            break;
    if argNode != -1:
        args = getArg(argNode,graph)
        return args
    else:
        return []
def getFLOWS_TO_statment(graph:Graph,expression:int):
    
    domList = set()
    domQueue = [expression]
    while len(domQueue) > 0:
        size = len(domQueue)
        for _ in range(size):
            node = domQueue.pop()
            if(node!=expression):
                domList.add(node)
            for flows in graph.edges['FLOWS_TO']['end'][node]:
                flowsnode = flows['to']
                if graph.nodes[flowsnode]['type'] != "CFGEntryNode":
                    domQueue.append(flowsnode)
    return domList
def printAST(graph:Graph,node:int):
    queue = [node]
    while len(queue)>0:
        length = len(queue)
        for n in range(length):
            front = queue.pop()
            print(graph.nodes[front])
            print("+++++++++")
            if front in graph.edges['IS_AST_PARENT']['start']:
                for next in graph.edges['IS_AST_PARENT']['start'][front]:
                    queue.append(next['to'])
 
def getSymbols(graph:Graph,node:int)-> set :
    """获得与某关键函数调用有数据依赖的全部语句（向前搜索）

    Args:
        graph (Graph): CPG
        node (int): AST中代表参数的根节点
    """
    varList = set()
    varQueue = [node]
    while len(varQueue) > 0:
        size = len(varQueue)
        for _ in range(size):
            
            p = varQueue.pop()
            varList.add(p)
            for flows_to in graph.edges['FLOWS_TO']['end'][p]:
                flowsnode = flows_to['to']
                if graph.nodes[flowsnode]['type']!="CFGEntryNode":
                    varQueue.append(flows_to['to'])
                    varList.add(flows_to['to'])
    return varList
def getCryptoInfo(graph:Graph):
    """
       提取密码学相关属性，函数调用->参数传递链条
    Args:
        graph (Graph): 代码CPG
    process:
        单位：函数声明
        提取关键函数名
        对于每一个关键函数调用，提取参数
        向上查找参数的数据流
        
        流程：
        1 利用IS_FUNCTION_OF_AST 找到函数定义的入口
        2 利用DOM获得函数内每一条语句的范围
        3 给定的每一个语句范围，深度有限搜索，获得关键函数调用列表
        4 利用FLOWS_TO 获得子图
        
        对于一张子图，一边匹配规则一遍进行密码学属性提取
        
        
        获得两组数据：
        1.传入关键函数的参数
        2.和关键函数有数据依赖的其他语句
    """
    functions = getFunctionDef(graph)
   
    for fun in functions:
        domList = processFunctionDef(graph,fun)
        for dom in domList:
            
            args = getArgumentList(dom,graph)
            argumentKey = sorted(args)
            relateNode = getFLOWS_TO_statment(graph,dom)
            print(relateNode)
            """
            该list每一个元素需要求出一个值，这个值可以是一个数字，一个字符串，一个OpenSSL函数返回结果或者对象，因此symbol类要识别各种类型，然后根据不同的类型计算结果
            """
        
        """
            argumentKey 是一个列表，列表是函数参数的AST根节点
            计算argumentKey中涉及的符号的值，
            利用flow_to 获得和dom相关的语句，用来自上而下计算参数的值
            """
            # 得到了某个关键函数调用语句的参数值or 变量
