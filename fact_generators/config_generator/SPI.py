# coding:utf8

import os

# 生成 generator
def getGenerator():
    return generator

# facts生成器, 返回数组表示的csv数据
def generator(p):
    # SPI配置文件路径
    cfgPath = os.path.join(p, "META-INF/services")
    
    # 不存在则跳过
    if not os.path.exists(cfgPath):
        return []
    
    # 接口名->{实现类}
    SPIConfig = {}

    # 遍历cfgPath中的所有文件
    for ele in os.listdir(cfgPath):  # 文件名为接口名
        ItfName = ele.replace('\'', '').replace('\"', '')
        # 拼接得到文件路径
        p = os.path.join(cfgPath, ItfName)
        # 初始化
        if ItfName not in SPIConfig.keys():
            SPIConfig[ItfName] = set()
            
        # 读入文件获取接口的所有实现类
        print("SPI generator handing %s"%(p))
        for line in open(p, 'r').readlines():
            line = line.strip()
            # 空行与注释
            if len(line)==0 or line[0]=="#":
                continue
            # 否则就是实现类的类名
            SPIConfig[ItfName].add(line)
            
    # 把SPIConfig转换为facts
    facts = []
    for interface in SPIConfig.keys():  # 遍历所有的文件名 
        for implClass in SPIConfig[interface]:
            row = [interface, implClass]    # 每一行代表着 接口对应的实现类
            facts.append(row)
    return facts