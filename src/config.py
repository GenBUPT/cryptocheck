import json
from statemachine import StateMachine, State
def readCsv(filename:str):
    f = open(filename,"r")
    
class Rule:
    function = ""
    param = {}
    misuse = ""
    def __init__(self,function,param,misuse) -> None:
        """
        解析param
        """
        self.function = function
        self.param = param
        self.misuse = misuse
class RuleSet:
    """
    读取规则
    
    序列化状态机
    """
    rules = []
    def readRule(self,filename:str):
        rulelist = json.load(open("../rule/crypto.json","r"))
        for rule in rulelist:
            self.rules.append(Rule(rule['function'],rule['param'],rule['misuse']))
    