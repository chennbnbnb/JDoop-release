import sys
from queue import Queue
import argparse
import json

# 污点对象传播边
edge_csv_path = './last-analysis/result/TaintObjectPropagateEdge.csv'
# 污点分析的结果
analysis_res_path = './last-analysis/result/LeakingTaintedInformation.csv'


def loadCsv(path):
    '''
    读入csv文件, 解析为嵌套数组
    '''
    res = []
    for row in open(path, 'r').read().split('\n'):
        # 跳过空行
        if len(row) ==0 :
            continue
        res.append(row.split('\t'))
    return res

class Edge:
    '''
    表示一个污点传播边
    '''
    def __init__(self, edge) -> None:
        self.fromCtxId = int(edge[1])    # 区分from的上下文的ID
        self._from = edge[2]     # 该边的起点
        self.toCtxId = int(edge[3])  # 区分to的上下文的ID
        self._to = edge[4]       # 该边的终点
        self.reason = edge[5]    # 产生该边的原因

    def __str__(self) -> str:
        return "[%s] => [%s], reason: %s"%(self._from, self._to, self.reason)
    
    def isStartEdge(self) -> bool:  
        '''
        是否为起始边
        '''
        return self.reason in ['Call source method', 'Spring entry method param']
    
    def getToDesc(self) -> str: 
        '''
        获取对于_to的描述字符串
        '''
        if self.reason=='Instance field store':
            obj = self._to.split('|')[0]
            sig = self._to.split('|')[1]
            return '对象[%s]的[%s]字段'%(obj, sig)
        elif self.reason=='Array index store':
            arr = self._to.split('|')[0] 
            return '数组对象[%s]的索引指针'%(arr)
        else:
            return self._to
    
def sortEdgeBySource(edges):
    '''
    根据污点对象的来源对边进行整理
    '''
    source2edgeSet = {}   # 污点对象=>该污点对象传播的边的集合
    for edge_csv in edges:
        # 获取污点对象id
        source = edge_csv[0]
        if source not in source2edgeSet.keys():
            source2edgeSet[source] = []
        
        # 把该边转换为Edge对象加入到对应的集合中
        source2edgeSet[source].append(Edge(edge_csv))
    return source2edgeSet



class FlowGraph:
    '''
    表示某个污点对象的流向图
    '''
    def __init__(self, edgeSet:list):  
        self.adjList = {}       # 邻接表, adjList[b] = 所有以a为起点的边
        self.startCtxId = None
        for edge in edgeSet:    # 遍历所有边
            edge:Edge
            
            # 把edge记录到邻接表中
            _from = (edge.fromCtxId, edge._from)    # 该边的起始点 
            if _from not in self.adjList.keys():
                self.adjList[_from] = []
            self.adjList[_from].append(edge) 
            
            # 如果找到了起始边, 则记录起始边source的上下文
            if edge.isStartEdge():
                # 所有起始边的from点的上下文应该一致
                assert(self.startCtxId in [None, edge.fromCtxId])
                self.startCtxId = edge.fromCtxId
                
                
            
    def DFS(self, vertex:tuple, end:tuple, path: list, isVisited: map)->bool:
        '''
        通过DFS算法遍历图, 找到从vertex到end的路径, 成功找到时返回True
        '''
        # 已经访问过了, 跳过
        if isVisited.get(vertex, False)==True:
            return False
        
        # 如果vertex就是终点, 则找到路径
        if vertex == end:
            return True
        
        # 标记一下, 已经访问过vertex
        isVisited[vertex] = True
        
        # vertex存在邻接边
        if vertex in self.adjList.keys():           
            # 遍历所有vertex可达的边
            for edge in self.adjList[vertex]:
                edge:Edge
                path.append(edge)   # 在路径数组中添加该边
                _to = (edge.toCtxId, edge._to)  # 该边的可达点
                if self.DFS(_to, end, path, isVisited):    # 从下一个点接着探索, 探索成功则说明edge找对了
                    return True
                else:   # 否则说明edge不对, 弹出
                    path.pop()
            
        return False
    
    def BFS(self, start:tuple, end:tuple, path: list, isVisited: map)->bool:
        '''
        通过BFS算法, 在图self.adjList中搜索start=>end的最短路径, 搜索成功返回True
        '''
        # 任务队列
        que = Queue()
        que.put(start)  # 放入起点
        
        # 是否找到
        found = False
        
        # lastVertex[x]表示到达x的前驱边, 也就是终点为x的边
        pre = {}
        
        while not que.empty():
            v = que.get()
            # print(v)
            
            # 已经到达终点
            if v==end:
                found = True
                break
            
            # 遍历v的邻接边
            if v in self.adjList.keys():
                for edge in self.adjList[v]:
                    edge:Edge
        
                    # 通过edge的可达点
                    _to = (edge.toCtxId, edge._to)
                    
                    # 已经访问过则跳过
                    if isVisited.get(_to, False)==True:
                        continue
                    isVisited[v] = True
                    
                    # 记录前驱边
                    pre[_to] = edge
                    
                    # 探索_to节点
                    que.put(_to)

        # 搜索失败
        if not found:
            return False
        
        # 搜索成功, 从终点开始反推出整个调用路径
        cur = end   # 当前到底的点
        while cur!=start:   # 只要cur有前驱边, 就一直循环
            edge:Edge
            edge = pre[cur] # 获取pre的前驱边
            path.insert(0, edge)    # 从头部倒序插入
            cur = (edge.fromCtxId, edge._from)  # 移动到edge的起始点  
            
        return True
    
    def resolvePath(self, start:tuple, end:tuple) -> list:
        '''
        返回一个数组, 包含从source产生污点对象传播到sinkParam的完整边集
        ''' 
        path = []
        isVisited = {}
        if self.BFS(start, end, path, isVisited):
            return path
        else:
            return None
        
    def __str__(self) -> str:
        str = ''
        for vertex in self.adjList.keys():  # 遍历所有的起点
            str+= '以[%s]为起点的边: \n'%(vertex)
            for edge in self.adjList[vertex]:
                str+= '\t'+ edge.__str__() +'\n' 
        return str
        
class FlowPath:
    '''
    表示一条污点传播路径
    '''
    def __init__(self, analysis_res) -> None:
        self.sourceLabel = analysis_res[0]  # 产生污点对象的源点的标签
        self.sinkLabel = analysis_res[1]    # 污点方法的标签
        self.invo = analysis_res[2]         # 调用sink方法的语句
        self.sinkParamCtxId = int(analysis_res[3])   # sink方法实现的上下文ID
        self.sinkParam = analysis_res[4]        # 调用sink方法时的实参, 该参数指向污点对象 
        self.source = analysis_res[5]       # 表示污点对象来源的字符串
        self.fullPath = []                  # 完整的传播路径
        
    def __str__(self) -> str:
        str = 'taint flow: [%s] ==> [%s]\n'%(self.sourceLabel, self.sinkLabel)
        str+= '\tSource[%s]\n'%(self.fullPath[0]._from)     # 起始节点
        for edge in self.fullPath:
            edge: Edge
            str+= '\t\t|\n'
            str+= '\t\t| %s\n'%(edge.reason)    # 边的原因
            str+= '\t\tV\n'
            if edge._to==self.sinkParam:    # 到达路径终点: sink方法调用的实参
                str+= '\tsink method invocation[%s], argument: [%s]\n'%(self.invo, edge.getToDesc())
            else:
                str+= '\t%s\n'%(edge.getToDesc())   # 边的终点
    
        return str
    
    def printInJson(self) -> list:
        # 无污点流图
        if self.fullPath==None or len(self.fullPath)==0:
            return None

        idx = 0     # 边的索引
        res = []    # 边的列表
        for edge in self.fullPath:
            edge:Edge
            res.append({
                'idx': idx,
                'to': edge._to,
                'remark': edge.reason
            })
            idx+=1
        return res


def showTaintFlow(only_source, json_output):
    # 加载所有的调用边
    edges = loadCsv(edge_csv_path)
    
    # 获取污点对象传播的边集
    src_edgeSet = sortEdgeBySource(edges)
    
    # 为每一个污点对象的边集构造一个流向图
    src_flowGraph = {}
    for src in src_edgeSet.keys():
        src_flowGraph[src] = FlowGraph(src_edgeSet[src])
    
    # json结果
    json_res = []
    
    # 加载污点流分析结果, 也就是起点和终点
    for flow in loadCsv(analysis_res_path):
        path = FlowPath(flow)                   # 获取污点流的源点, 终点, 流入sink点的污点对象
        if only_source!=None and path.source!=only_source:  # 跳过不想看的污点流图
            continue
        graph = src_flowGraph[path.source]    # 获取污点对象传播图
        graph:FlowGraph
        # 搜索从源点到污点参数的传播路径
        path.fullPath = graph.resolvePath((graph.startCtxId, path.source), (path.sinkParamCtxId, path.sinkParam))  
        
        # 输出到STDOUT
        if path.fullPath==None:
            print("污点流[%s]=>[%d, %s]搜索失败"%(path.source, path.sinkParamCtxId, path.sinkParam))
        else:
            print(path) 
            
        # 输出到json文件
        if json_output!=None:
            json_res.append({
                'source_label': path.sourceLabel,   # 污点源标签
                'source': path.source,  # 污点源
                'sink_label': path.sinkLabel,   # 污点方法标签
                'sink_param_ctx_id': path.sinkParamCtxId,   # 污点参数的上下文
                'sink_param': path.sinkParam,   # 污点参数
                'sink_invo': path.invo, # 污点方法调用语句
                'path': path.printInJson()  # 源传播污点的上下文
            })
    
    # 写入json到文件中
    if json_output!=None:
        json.dump(json_res, open(json_output, 'w'))
        

def main():
    # 解析argv参数
    parser = argparse.ArgumentParser(
        prog='JDoop Helper Script', # 程序名
        description='helper script for print taint flow graph', # 描述
    )
    # 只输出某个源点的污点流
    parser.add_argument('-S', '--source', type=str, help='only taint flow from specific source')
    # 是否json格式输出
    parser.add_argument('-J', '--json', type=str, help='output analysis result in JSON format')
    # 解析参数
    args = parser.parse_args()
    
    # 输出污点流图
    showTaintFlow(args.source, args.json)
    
if __name__=='__main__':
    main()
    
''' 
污点流: [user_input] ==> [print]
        污点对象源[<InformationFlowTest: void T6()>/InformationFlowTest.source/0]
                |
                | Taint object transfer: String.value[]=>String
                V
        sink方法调用[<InformationFlowTest: void T6()>/InformationFlowTest.sink/0]的实参[<InformationFlowTest: void T6()>/$stack4

'''