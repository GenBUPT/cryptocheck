import json
import matplotlib.pyplot as plt

# 从JSON文件中读取数据
plt.rcParams["font.sans-serif"]=["SimHei"] #设置字体
plt.rcParams["axes.unicode_minus"]=False #正常显示负号
with open("functiontt.json") as f:
    data = json.load(f)

# 绘制折线图
X = list(data['catagraph'].keys())
Y = list(data['catagraph'].values())

print(X,Y)
plt.bar(X,Y)

# 添加标签和标题
plt.xlabel("cryptographic type")
plt.ylabel("count")
plt.title("API Quantity Distribution")

# 显示图表

plt.savefig("api.png")
