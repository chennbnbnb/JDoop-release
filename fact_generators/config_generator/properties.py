# coding:utf8

import os

# 生成 generator
def getGenerator():
    return generator

def parseProperties(path):
    print("properties generator handle %s"%(path))

    res = []
    try:
        content = open(path, 'r').read()
        for line in content.split('\n'):
            # 跳过空行
            if len(line)==0:
                continue
            
            # 跳过注释
            if line[0]=='#':
                continue
            
            # 不规范的key = value行
            if len(line.split('='))<2:
                continue
            
            # 解析出kv对
            key = line.split('=')[0].strip()
            value = line.split('=')[1].strip()
            if len(key)==0 or len(value)==0:
                continue
            res.append([key, value])
            
    except UnicodeDecodeError as e:
        print(e)
        
    return res

# facts生成器, 返回数组表示的csv数据
def generator(p):
    # 遍历p中所有的properties文件
    arr = []
    for root, _, fs in os.walk(p):
        for f in fs:
            if f =='pom.properties':
                continue
            if not f.endswith('.properties'):
                continue
            path = os.path.join(root, f)
            arr.append(path)
    
    # 如果没有符合条件的properties文件, 则直接返回
    if len(arr)==0:
        return []
    
    # 开始解析每一个properties文件
    res = []
    for path in arr:
        res+=parseProperties(path)
    return res