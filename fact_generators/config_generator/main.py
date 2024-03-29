# coding:utf8
import sys 
from tempfile import TemporaryDirectory
import shutil
import zipfile
import os

import SPI
import properties

# 所有facts生成器, fact名 => 对应的生成器
factGenerators = {
    'SPI-Config': SPI.getGenerator(),   # 解析SPI相关配置文件
    'properties-Config': properties.getGenerator() # 解析properties配置文件
}

# 所有facts数据, fact名->[ [e1, e2, ...] ]
allFacts = {}

# 初始化
for k in factGenerators.keys():
    allFacts[k] = []


def parseArgs():
    '''
    解析参数, 返回facts输出目录与输出的jar包数组
    '''

    # facts输出目录
    factsDir = ""

    # 输入的jar包数组
    inputJars = []

    # 解析参数
    idx = 1
    while idx<len(sys.argv):
        if sys.argv[idx]=="-o":
            idx+=1
            factsDir = sys.argv[idx]
            idx+=1
        elif sys.argv[idx]=="-i":
            idx+=1
            s = sys.argv[idx] 
            idx+=1
            for fn in s[1:-1].split(","): 
                inputJars.append(fn)
        else:
            idx+=1    
            
    return factsDir, inputJars


def traverseJars(inputJars, tmpDir):    
    # 遍历每一个jar包
    cnt = 0
    for jar in inputJars:
        # 拼接出解压输出目录
        outputPath = os.path.join(tmpDir, str(cnt))
        if not os.path.exists(outputPath):
            os.makedirs(outputPath) 
            
        # 解压到临时目录中
        zfile = zipfile.ZipFile(jar, 'r')
        zfile.extractall(outputPath)
        
        # 遍历所有facts生成器
        for k in factGenerators.keys():
            gen = factGenerators[k] # 生成器
            facts = gen(outputPath) # 生成facts
            allFacts[k]+= facts   # 生成的facts添加到数组中
        
        cnt+=1

def Main(factsDir:str, inputJars:list):
    '''
    外部调用接口
        factsDir: 写入facts的目录
        inputJars: 输入的jar包
    '''
    
    # 创建临时目录
    tmpDir = TemporaryDirectory().name
    print("create "+tmpDir)
    try:
        # 解压所有jar包到临时目录中, 并调用所有的facts生成器
        traverseJars(inputJars, tmpDir)
    finally:
        print("remdir "+tmpDir)
        shutil.rmtree(tmpDir)
    
    # 根据allFacts生成fact文件
    for k in factGenerators.keys():
        o = os.path.join(factsDir, "%s.facts"%(k))  # 路径拼接
        f = open(o, "w")    # 写入文件
        for line in allFacts[k]:    # 遍历每一行
            f.write(line[0])    # 写入该行第一个元素
            for i in range(1, len(line)):   # 写入剩余元素
                f.write('\t'+line[i])
            f.write('\n')
        f.close()
    

if __name__=='__main__':
    # 从argv中解析参数
    factsDir, inputJars = parseArgs()
    
    # 调用生成逻辑
    Main(factsDir, inputJars)
    
    

'''
python3 \
    ./main.py \
    -o ./tmp \
    -i [/home/user/JDoop-release/test_cases/servlet_test/target/JavaWebLearn-1.0-SNAPSHOT.war,/home/user/JDoop-release/mocked_jars/servlet/MockServlet-1.0-SNAPSHOT.jar]
'''