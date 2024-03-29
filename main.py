import os
import sys
import subprocess
import multiprocessing
from datetime import datetime
import re
import argparse
import json

fact_db = './last-analysis/database'        # facts生成目录
res_db = './last-analysis/result'           # 数据流分析结果目录
sink_def_tsv = './sink_rules/primitive_rules/LeakingSinkMethodArg.tsv' # 污点定义文件
leaking_sink_method_name_arg = 'sink_rules/migrated_rules/LeakingSinkMethodNameArg.tsv' # 从白盒迁移的规则: 根据方法名正则定义污点
leaking_sink_method_name_var_arg = 'sink_rules/migrated_rules/LeakingSinkMethodNameVarArg.tsv' # 从白盒迁移的规则: 根据方法名正则定义可变参数的污点

def valid_sink_defination(path):
    '''
    验证污点定义文件的格式是否正确
    '''
    line_idx = 0   # 第几行
    for line in open(path, 'r').read().split('\n'):
        line_idx+=1
        if len(line)==0:
            continue
        row = line.split('\t')
        
        # 一行只能有3个元素
        if len(row)!=3:
            print("line %d: [%s] format wrong "%(line_idx, line))
            return False
        
        # 解析列
        sink_label = row[0] # 污点标签
        arg_idx = row[1]    # 第几个参数
        method_sig = row[2] # 方法的签名
        
        # 检查arg_idx格式是否正确
        if re.match(r'^[0-9]\d*$', arg_idx)==None:
            print("line %d: [%s] format wrong "%(line_idx, line))
            return False
        
        # 检查method_sig  
        matchObj = re.match(r'^\<(.*): (.*) (.*)\((.*)\)\>', method_sig)
        if matchObj==None:
            print("line %d: [%s] format wrong "%(line_idx, line))
            return False
        
        # 检查arg_idx是否有效
        param_list = matchObj.group(4)
        if int(arg_idx)>param_list.count(','):
            print("line %d: [%s] format wrong "%(line_idx, line))
            return False
        
    return True

def init_fact_db(fact_db):
    '''
    初始化fact_db目录, 创建分析前的必须的facts文件
    '''
    # 清空fact_db目录
    os.system('rm -rf %s'%(fact_db))
    os.system("mkdir -p %s"%(fact_db))
    
    # 验证sink定义文件格式是否正确
    if not valid_sink_defination(sink_def_tsv):
        print("valid sink def: %s fail, exit"%(sink_def_tsv))
        exit(1)
        
    # 添加污点定义文件
    os.system('cp %s %s/LeakingSinkMethodArg.facts '%(sink_def_tsv, fact_db))
    os.system('cp %s %s/LeakingSinkMethodNameArg.facts '%(leaking_sink_method_name_arg, fact_db))
    os.system('cp %s %s/LeakingSinkMethodNameVarArg.facts '%(leaking_sink_method_name_var_arg, fact_db))
    
    # 生成一些空的facts关系, 以防止求解时因文件缺失而报错
    arr = ['MainClass.facts', 'KeepClass.facts', 'KeepMethod.facts', 'RootCodeElement.facts', 'KeepClassMembers.facts', 'KeepClassesWithMembers.facts', 'TaintSpec.facts']
    for f in arr:
        path = os.path.join(fact_db, f)
        os.system('touch %s'%(path))

def soot_fact_generate(war_path, fact_db, jobs):
    '''
    调用fact_generators/soot-fact-generator.jar生成facts
    '''
    # 调用生成器
    cmd = 'java '
    cmd+= '-cp ./fact_generators/soot-fact-generator.jar '  # 生成器jar包, fatjar格式, 包含所有的依赖
    cmd+= 'org.clyze.doop.soot.Main '   # 生成器入口类

    # 并行生成facts
    cmd+= '--fact-gen-cores %d '%(jobs)
    
    # fact输出目录
    cmd+= '-d %s '%(fact_db)
    
    # 要分析的war包, 或者spring boot jar包
    cmd+= '-i %s '%(war_path)
    
    # 以下是分析servlet所需的jar包
    cmd+= '-i ./mocked_jars/servlet/MockServlet-1.0-SNAPSHOT.jar '
    cmd+= '-ld ./mocked_jars/servlet/jakarta.servlet-api-5.0.0.jar '
    cmd+= '-ld ./mocked_jars/servlet/javax.servlet-api-4.0.1.jar '
    
    # 对于Spring框架相关方法mock的jar包
    cmd+= '-i ./mocked_jars/spring/MockSpring-1.0-SNAPSHOT.jar '
    
    # mock后jdk的jar包
    cmd+= '-l ./mocked_jars/jdk/rt.jar '
    cmd+= '-l ./mocked_jars/jdk/jce.jar '
    cmd+= '-l ./mocked_jars/jdk/jsse.jar '
    
    # 生成fact的配置
    cmd+= '--full ' # 全程序分析
    cmd+= '--ssa '  # SSA格式的IR
    cmd+= '--allow-phantom '    # 允许空方法与空类
    cmd+= '--ignore-factgen-errors '    # 忽略生成时的异常
    cmd+= '--generate-jimple '  # 保存字节码反编译后的jimple

    return subprocess.check_call(cmd, shell=True)

def config_fact_generate(war_path, fact_db):
    '''
    调用fact_generators/config_generator中的py脚本, 生成配置文件相关fact
    '''
    input_jars = [war_path]
    cmd = "python3 "
    cmd+= "./fact_generators/config_generator/main.py "
    cmd+= "-o %s "%(fact_db)
    cmd+= "-i %s "%(input_jars.__str__().replace(' ', '').replace('\'', ''))
    return subprocess.check_call(cmd, shell=True)

def solver(fact_db, res_db, jobs):
    '''
    调用求解器进行数据流分析
    '''
    # 创建目录
    os.system("mkdir -p %s"%(res_db))
    
    # 求解器参数
    cmd = './solver '
    cmd+= '-j %d '%(jobs)   # 多线程求解
    cmd+= '-F %s '%(fact_db)    # 输入facts目录
    cmd+= '-D %s '%(res_db) # 求解结果目录
    
    return subprocess.check_call(cmd, shell=True)

def resultWC(fn):
    f = open(os.path.join(res_db, fn))
    count = len(f.readlines())
    print("%s: %d"%(fn, count))
    
def analysis(package_path, json_output, threads):
    '''
    进行分析的主过程
        package_path: 要分析的包路径
        json_output: 把分析结果按照json格式写入指定文件中
    '''
    
    # 初始化fact_db目录
    init_fact_db(fact_db)

    # 调用soot fact生成器
    soot_fact_generate(package_path, fact_db, threads)

    # 调用配置文件fact生成器
    config_fact_generate(package_path, fact_db)

    # 开始数据流分析
    print("[%s] start dataflow analysis"%(datetime.now()))
    solver(fact_db, res_db, threads)
    print("[%s] fin dataflow analysis"%(datetime.now()))
    
    print("=====count=======")
    resultWC("SpringBeans.csv")
    resultWC("SpringEntryMethod.csv")
    resultWC("CallGraphEdge.csv")
    resultWC("VarPointsTo.csv")
    print("\n")
    
    print("analysis result as follwed\n")

    # 处理结果, 这里打印结果时忽略掉ctxId字段, 该字段是为了显式污点流用的, 因此要进行一个去重
    LeakingTaintedInformation_immuCtx = set()
    for l in open(os.path.join(res_db, 'LeakingTaintedInformation.csv')).read().split('\n')[0:-1]:
        l = l.split('\t')
        fromLable = l[0]
        toLabel = l[1] 
        sinkInvo = l[2] # 污点方法的调用语句
        sinkParam = l[4]    # 污点方法调用的实参
        source = l[5]   # 污点源
        LeakingTaintedInformation_immuCtx.add((fromLable, toLabel, sinkInvo, sinkParam, source))
        
    # 最后输出结果
    for (fromLable, toLabel, sinkInvo, sinkParam, source) in LeakingTaintedInformation_immuCtx:
        print("[%s=>%s]: "%(fromLable, toLabel))
        print("\tSource: %s"%(source))
        print("\tInvocation to sink method: %s"%(sinkInvo))
        print("\tSink argument: %s"%(sinkParam))
        print("")
        
    # 按照json格式写入指定文件中
    if json_output!=None:
        res = []
        for (fromLable, toLabel, sinkInvo, sinkParam, source) in LeakingTaintedInformation_immuCtx:
            res.append({
                'source_label': fromLable,
                'sink_label': toLabel,
                'sink_invo': sinkInvo,
                'sink_param': sinkParam,
                'source': source
            })
        json.dump(res, open(json_output, 'w'))
        
    return True

def main():
    # 解析argv参数
    parser = argparse.ArgumentParser(
        prog='JDoop Helper Script', # 程序名
        description='helper script for Analysis Java Web program', # 描述
    )
    # 输入文件
    parser.add_argument('package_path', type=str, help='java package path, support .jar/.war/.zip')     
    # 是否json格式输出
    parser.add_argument('-J', '--json', type=str, help='output analysis result in JSON format')
     # 并行核数
    parser.add_argument('-T', '--threads', type=int, help='num of parallel threads', default=multiprocessing.cpu_count())
    # 解析参数
    args = parser.parse_args()
        
    # 开始分析 
    analysis(args.package_path, args.json, args.threads)

if __name__ =="__main__":
    main()