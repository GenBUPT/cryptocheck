import pandas as pd
import numpy as np
from graph import Graph
from graph import getCryptoInfo

from z3 import *
nodepath = "../code/test.cpp/nodes.csv"

edgepath = "../code/test.cpp/edges.csv"


nodes = pd.read_csv(nodepath,sep='\t')

edges = pd.read_csv(edgepath,sep='\t')

"""
要处理几种情况，按照节点构建edge索引
"""

graph = Graph(nodes,edges)



getCryptoInfo(graph)
