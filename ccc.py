from __future__ import print_function
from collections import defaultdict
from idc import *
from idaapi import *
from idautils import *
from ida_bytes import is_code, is_flow
Set = set

class Graph: 

    def __init__(self,vertices): 
        #No. of vertices 
        self.V= vertices  
        self.looplist=list() 
        # default dictionary to store graph 
        self.graph = defaultdict(list)  
          
        self.Time = 0

    # function to add an edge to graph 
    def addEdge(self,v,u): 
        self.graph[v].append(u) 

    def printgrapph(self):
        for keys,values in self.graph.iteritems():
            for value in values:
                print(keys," has relation with ",value)
            
    def SCCUtil(self,u, low, disc, stackMember, st): 
        loops=list()
        # Initialize discovery time and low value 
        disc[u] = self.Time 
        low[u] = self.Time 
        self.Time += 1
        stackMember[u] = True
        st.append(u) 
        for v in self.graph[u]: 
            if disc[v] == -1 : 
                self.SCCUtil(v, low, disc, stackMember, st) 
                low[u] = min(low[u], low[v])             
            elif stackMember[v] == True:  
                low[u] = min(low[u], disc[v]) 
        w = -1 #To store stack extracted vertices 
        if low[u] == disc[u]: 
            while w != u: 
                w = st.pop() 
                #print (w,end=',')
                stackMember[w] = False 
                loops.append(w);
            #print("",end='\n')
            if(len(loops)>1):
                self.looplist.append(loops)
                
        return self.looplist

    def SCC(self):
        disc = [-1] * (self.V) 
        low = [-1] * (self.V) 
        stackMember = [False] * (self.V) 
        st =list()
        for i in range(self.V): 
            if disc[i] == -1:
                self.SCCUtil(i, low, disc, stackMember, st)
        return self.looplist

            

#printFuncs(userfunc_dict)
class CyclomaticComplexityChoose(Choose):
    def __init__(self, title):
        Choose.__init__(self, title, [ 
                ["Address", 8 | Choose.CHCOL_HEX], 
                ["Name", 30 | Choose.CHCOL_PLAIN],
                ["BasicBlocks", 6 | Choose.CHCOL_DEC],
                ["TarjanLoops", 6 |Choose.CHCOL_DEC],
                ["Loops", 6 |Choose.CHCOL_DEC],
                ["SwitchCases", 6 | Choose.CHCOL_DEC],
                ["MaxPreds", 6 | Choose.CHCOL_DEC],
                ["Pointers", 6 | Choose.CHCOL_DEC],
                ["Cyclomatic_Complexity", 6 | Choose.CHCOL_DEC],
                ["Library func", 6 | Choose.CHCOL_PLAIN] ])

        self.title	= title
        self.colors = (0x0000ff,0x0074ff, 0x00e8ff, 0x00ff00)
        self.items	= []
        self.icon	 = 41
        self.PopulateItems()

    def OnClose(self):
        return True

    def OnSelectLine(self, n):
        item = self.items[int(n)]
        jumpto(int(item[0], 16))

    def OnGetLine(self, index):
        return self.items[index]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        del self.items[n]
        return n

    def OnGetLineAttr(self,n):
        red=0x0000ff
        green=0x00ff00
        maxbbs=int(self.items[0][2])
        bbs = int(self.items[n][2])
        mid=int(maxbbs/2)
        if(n==0):
            color=red
        elif(bbs>mid):
            tmpgreen=int(((bbs*255 )/mid))
            if(tmpgreen>255):
                tmpgreen=255-(tmpgreen-255)
            color=red|(int(tmpgreen)<<8)
            #print("%06x" %tmpgreen)
        elif(bbs<mid):
            tmpred=int((bbs*255)/mid)
            color=int(green)|(tmpred)
            #print("%06x" %tmpred)
        
        return [color, 0]

    def OnRefresh(self, n):
        return n

    def OnCommand(self, n, cmd_id):
        if cmd_id == self.cmd_exc_lib_funcs:
            self.exclude_lib_funcs()
        return n

    def exclude_lib_funcs(self):
        if not len(self.items):
            return False 
        self.items = [i for i in self.items if i[3] != 'True']
        return True

    def show(self):
        n_functions = len(list(Functions()))
        if n_functions > 0:			
            b = self.Show()
            if b == 0:
                #self.cmd_exc_lib_funcs = self.AddCommand("Exclude library functions")
                return True
        else:
            warning("IDA has not identified functions.")
            return False

    def PopulateItems(self):
        userfuncs=self.getUserFuncs()
        
        loopsdict={}
        tarjansloopsdict={}
        bbsdict={}
        switchdict={}
        predsdict={}
        cyclodict={}
        pointerdict={}
        
        for func in userfuncs:
            loops=self.loopsInFunc(func)
            loopsdict.update({func:len(loops)})
            bbs=self.bbDetection(func)
            bbsdict.update({func:bbs.size})
            switchs=self.switchDetection(func)
            switchdict.update({func:switchs})
            preds=self.getBlockPredecessor(func)
            predsdict.update({func:preds})
            pointerdict.update({func:self.pointerCounter(func)})
            tarjanloops=self.tarjansLoops(func)
            tarjansloopsdict.update({func:tarjanloops})
            cyclo=self.cyclomatic_complexity(func)
            cyclodict.update({func:cyclo})
            self.items.append(["%08x" % func,"%s" %userfuncs[func], "%d" % bbsdict[func],"%d" % len(tarjansloopsdict[func]),"%d" % loopsdict[func],"%d" %len(switchdict[func]),
                "%d" %predsdict[func][1],"%d" %pointerdict[func],"%d" %cyclodict[func],"%s" % ((get_func_attr(func, FUNCATTR_FLAGS) & FUNC_LIB) != 0)])
            
            self.items=sorted(self.items, key=lambda student: int(student[2]),reverse=True) 
            
            
    def getFuncs(self):
        ea = get_segm_by_sel(selector_by_name(".text"))
        allfuncs_dict={}
        #for functionAddr in Functions(ea):
        for functionAddr in Functions():
            allfuncs_dict.update({functionAddr: get_func_name(functionAddr)})
        return allfuncs_dict
        
    def getUserFuncs(self):
        userfunc_dict={}
        allfuncs=self.getFuncs()
        for func in allfuncs:
            flags=idc.get_func_attr(func,idc.FUNCATTR_FLAGS)
            if not(flags & FUNC_LIB) and not(flags & FUNC_THUNK):# exclude lib functions 
                userfunc_dict.update({func:allfuncs[func]})
        return userfunc_dict

    def loopsInFunc(self,funcea):
        loops = []
        func_end = find_func_end(funcea)
        for item in FuncItems(funcea):
            for xref in XrefsTo(item, 0):
                if xref.type not in [1,21]:
                    if funcea <= xref.to <= xref.frm <= func_end:
                        if print_insn_mnem(xref.frm) not in ['call', 'retn']:
                            loops.append((hex(xref.frm), hex(xref.to)))
        return loops

    def bbDetection(self,funcea):
        f=idaapi.get_func(funcea)
        bblist=[]
        bblist=idaapi.FlowChart(f)
        return bblist

    def getBlockPredecessor(self,funcea):
        max=-1
        blockaddr=0
        i=0
        func=idaapi.get_func(funcea);
        flowchart=idaapi.FlowChart(func, None, 0x4)
        for block in flowchart:
            i=0
            for s in block.preds():
                i=i+1
            if(i > max):
                max=i
                blockaddr=block.start_ea

        return [blockaddr,max]

    def switchDetection(self,funcea):
        switchDict={}
        funcEndAddr=idc.get_func_attr(funcea,idc.FUNCATTR_END)
        for head_ea in Heads(funcea, funcEndAddr):
            if idc.is_code(idc.get_full_flags(head_ea)):
                switch_info = idaapi.get_switch_info(head_ea)
                if (switch_info and switch_info.jumps != 0):
                    loc = switch_info.jumps
                    element_num = switch_info.get_jtable_size()
                    switchDict.update({loc:element_num})
        return switchDict

    def pointerCounter2(self,funcea):
        switchDict={}
        c=0
        funcEndAddr=idc.get_func_attr(funcea,idc.FUNCATTR_END)
        heads=Heads(funcea, funcEndAddr)
        for head_ea in heads:
            if idc.isOff0(idc.get_full_flags(head_ea)):
                c=c+1
                print (hex(head_ea))    
        #return switchDict

    def pointerCounter(self,funcea):### this function has been written by myself
        switchDict={}
        c=0
        funcEndAddr=idc.get_func_attr(funcea,idc.FUNCATTR_END)
        heads=Heads(funcea, funcEndAddr)
        for head_ea in heads:
            if idc.is_code(idc.get_full_flags(head_ea)):
                if (idc.print_insn_mnem(head_ea) == "lea"):
                    if (idc.get_operand_type(head_ea, 1) == idaapi.o_displ):
                        nexthead=idc.next_head(head_ea)
                        if (idc.print_insn_mnem(nexthead) == "mov"):
                            if (idc.get_operand_type(nexthead, 0) == idaapi.o_displ):
                                c=c+1
                                #print (hex(head_ea))
        return c

        
    def tarjansLoops(self,fva):
        function = idaapi.get_func(fva)
        flowchart = idaapi.FlowChart(function)
        g=Graph(flowchart.size)
        for bb in flowchart:
            for succ in bb.succs():
                g.addEdge(bb.id,succ.id)
        return g.SCC()  

    def cyclomatic_complexity(self,function_ea):
        
        f_start = function_ea
        f_end = idc.find_func_end(function_ea)
        edges = Set()
        boundaries = Set((f_start,))

        for head in Heads(f_start, f_end):
            if is_code(idc.get_full_flags(head)):
                refs = CodeRefsFrom(head, 0)
                refs = Set(filter(lambda x: x>=f_start and x<=f_end, refs))
                
                if refs:
                    head_next = next_head(head, f_end)
                    if is_flow(get_full_flags(head_next)):
                        refs.add(head_next)
                    boundaries.update(refs)
                    #boundaries.union_update(refs)

                    for r in refs:
                        if is_flow(get_full_flags(r)):
                            edges.add((prev_head(r, f_start), r))
                        edges.add((head, r))

        return len(edges) - len(boundaries) + 2    


def show_choose():
    choose = CyclomaticComplexityChoose("Complexity")
    choose.show()

class CyclomaticComplexity_t(plugin_t):
	flags = PLUGIN_UNL
	comment = "Complexity"
	help = ""
	wanted_name = "Complexity"
	wanted_hotkey = ""

	def init(self):
		self.icon_id = 0
		return PLUGIN_OK

	def run(self, arg=0):
		show_choose()

	def term(self):
		pass
        
def PLUGIN_ENTRY():
    return CyclomaticComplexity_t()

if __name__ == '__main__':
    show_choose()
