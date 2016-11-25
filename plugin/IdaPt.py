# Intel PT IDA Plugin
# Last revision: 11/25/2016
# Copyright 2016 Andrea Allievi - MSTIC
#
import sys
import collections
try:
    import idaapi
    from idaapi import *
    from idc import *
    from idautils import *
    IDA_READY = 1
except:
    IDA_READY = 0

class Ida_pt:
    def __init__(self):
        # Init global data here:
        self.BaseAddr = 0                    # The module base address
        self.ModSize = 0                     # The module size
        self.lineNumber = 0                  # Current number of line 
        self.qwLastTraceIp = 0				 # Last IP Trace address
        self.curDelta = 0                    # Current Module Delta
        self.lastPtPck = None                # The last PT packet
        self.hTraceFile = None               # Current trace file handle
        self.retAddrs = []                   # The list of Return Addresses
        self.curTntMaskAndOffset = ["", 0]            # Last TNT packet mask
        #self.Graphs = []                     # The list that contains all the analysed graphs
        self.curColor = self.get_new_color(0xFFFFFF)
        #self.curGraph = collections.OrderedDict() 

    # Get the IDA normalized address
    def GetIdaAddress(self, addr):
        IdaAddr = addr - self.curDelta
        #IdaAddr &= 0xFFFFFFFF
        return (IdaAddr)

    # Get the Trace packet full address
    def GetPtPckFullIP(self, pck): 
        retAddr = self.qwLastTraceIp
        if (pck[2][0] == '1'):
            retAddr &= 0xFFFFFFFFFFFF0000
            retAddr += int(pck[3][-4:], 16)
        elif (pck[2][0] == '2'):
            retAddr &= 0xFFFFFFFF00000000
            retAddr += int(pck[3][-8:], 16)
        else:
            retAddr = int(pck[3], 16)
            self.qwLastTraceIp = retAddr
        return retAddr

    # Get a new color from the color list
    def get_new_color(self, current_color):
        colors = [0xffe699, 0xe1cc85, 0xffcc33, 0xe6ac00, 0xc39200, 0xb38600]
        if (current_color & 0xFFFFFF) == 0xFFFFFF:
            return colors[0]
        
        if current_color in colors:
            pos = colors.index(current_color)
            if pos == len(colors)-1:
                return colors[pos]
            else:
                return colors[pos+1]
        return 0xFFFFFF

    def GetPacket(self, line):
         # Packet format: "OFFSET - PACKET TYPE - PARAMS
        (offset, pckType, param1, param2, param3) = (0, "", 0, 0, 0)
        pckList = line.split()
        if len(pckList) < 2: return None
        offset = int(pckList[0], 16)
        pckType = pckList[1].strip().lower()
        if (len(pckList) > 2): param1 = pckList[2].strip().lower()
        if (len(pckList) > 3): param2 = pckList[3].strip().lower()
        if (len(pckList) > 4): param3 = pckList[4].strip().lower()
        return  (offset, pckType, param1, param2, param3)

    def SetIdaNodeColor(self, node, color = None):
        if (color == None): color = self.curColor
        #node_info = idaapi.node_info_t()
        #node_info.bg_color = color
        #idaapi.set_node_info2(node.startEA, 0, node_info,  idaapi.NIF_BG_COLOR)
        for insr in Heads(node.startEA, node.endEA):
            idc.SetColor(insr, CIC_ITEM, color) 

    def ColorInstruction(self, ea):
        oldColor = idc.GetColor(ea, idc.CIC_ITEM)
        # Grab the new color
        newColor = self.get_new_color(oldColor)
        idc.SetColor(ea, idc.CIC_ITEM, newColor)

    def ParseFileAndGetStartAddr(self, fileFullPath):
        line = ""               # The read file line
        curLineNumber = 3       # Current line number
        qwStartAddr = 0         # Start address found in the Dump

        hDump = open(fileFullPath, "r")
        hdrLine = hDump.readline().strip()
        if hdrLine[:21].lower() != "AaLl86 Intel PT Trace".lower():
            return False

        # Grab the executable name
        targetName = hDump.readline().strip()
        if targetName[:16].lower() == "executable name:":
            # This text file describe an executable
            targetName = targetName[17:].strip()
            print("Found \"%s\" executable name." % targetName)
        elif targetName[:19].lower() == "kernel driver name:" :
            # This text file describe a kernel driver 
            targetName = targetName[20:].strip()
            print("Found \"%s\" kernel mode driver name." % targetName)
        elif targetName[:22].lower() == "binary dump file name:":
            # This text file describe a generic PT dump
            targetName = targetName[23:].strip()
            print("Found \"%s\" binary dump file name." % targetName)
        else:
            return False

        # Grab the base address and the size:
        baseAddrLine = hDump.readline().strip()
        if baseAddrLine[:13].lower() == "base address:":
            delimPos = -1
            baseAddrLine = baseAddrLine[14:].strip()
            delimPos = baseAddrLine.find("-")
            if (delimPos < 0): baseAddrStr = baseAddrLine.strip()
            else: baseAddrStr = baseAddrLine[:delimPos].strip()
            try:
                if (baseAddrStr.startswith("0x")): self.BaseAddr = int(baseAddrStr, 16)
                else: self.BaseAddr = int(baseAddrStr, 10)
            except Exception as e:
                return False         
       
            # Now grab the module size
            if delimPos > 0:
                sizeStr = baseAddrLine[delimPos + 1:].strip()
                if sizeStr.lower().startswith("size:"): sizeStr = sizeStr[5:].strip()
                elif sizeStr.lower().startswith("size"): sizeStr = sizeStr[4:].strip()
                try:
                    if (sizeStr.startswith("0x")): self.ModSize = int(sizeStr, 16)
                    else: self.ModSize = int(sizeStr, 10)
                except Exception as e:
                    return False         
            else:
                self.modSize = 0
        else:
            return False
        
        # Get current DELTA value
        self.curDelta = self.GetModuleDelta()
        print("Found module base address %s - size: %s - Delta: %s." % (hex(self.BaseAddr), hex(self.ModSize), hex(self.curDelta)))

        # Now search the "Begin Trace Dump" string:
        while True:
            line = hDump.readline()
            if (line == ""):
                self.ModSize = 0
                self.BaseAddr = 0
                return False
            if line.lower().startswith("begin trace dump"): break
            curLineNumber += 1
        
        # Found, start by analysing one packet and get the start
        while True:
            line = hDump.readline()
            pck = self.GetPacket(line)
            pckType = pck[1]
            curLineNumber += 1
            if pckType == "fup":
                # Arg1 - Address type (IpBytes) - in powers of "2"
                # Arg2 - Final address
                if (int(pck[2][0]) != 3): return False
                qwStartAddr = int(pck[3], 16)
                break
            elif pckType == "tip"or pckType == "tip.pgd" or pckType == "tip.pge":
                # Arg1 - Address type (IpBytes) - in powers of "2"
                # Arg2 - Final address
                if (int(pck[2][0]) != 3): return False
                qwStartAddr = int(pck[3], 16)
                break
        
        print("Found the starting address from the DUMP: %s" % hex(qwStartAddr - self.curDelta))
        self.hTraceFile = hDump
        self.qwLastTraceIp = qwStartAddr
        self.lastPtPck = pck
        return self.GetIdaAddress(qwStartAddr)			# IDA Speaking

    def GetModuleDelta(self):
        if (IDA_READY == 0): return 
        loaded_mod_base_addr = idaapi.get_imagebase()
        return (self.BaseAddr - loaded_mod_base_addr)

    def GetIdaFuncBlock(self, ea):
        if (IDA_READY == 0 or ea == 0): return None
        f = idaapi.get_func(ea)			# Grab the function associated to the current EA
        if (f is None):
            # Try to create a function 
            import idc
            idc.MakeCode(ea)
            idc.MakeFunction(ea)

        if (f is None):
            return None

        graph = idaapi.FlowChart(f, flags=FC_PREDS) 	# Create the FlowChart associated to it
        for block in graph:
            if block.startEA <= ea and block.endEA > ea:
                # found my block
                return block
        return None

    # Get a function node from a graph
    def GetGraphNode(self, graph, ea):
        nodes = graph.keys()
        for node in nodes:
            if (ea >= node.startEA and ea < node.endEA ):
                return node
        return None

    def CreateFuncGraph(self, ea):
        # Get and analyse the entire flow chart and produce the Binary Graph
        f = idaapi.get_func(ea)			# Grab the function associated to the current EA
        flowchart = idaapi.FlowChart(f, flags=idaapi.FC_PREDS) 	# Create the FlowChart associated to it
        graph = collections.OrderedDict() 

        # Build the entire graph
        for curBlock in flowchart:
            # Get left and right edge
            lastInsr = idc.PrevHead(curBlock.endEA)
            leftAddr = idc.NextHead(lastInsr)
            rightAddr = GetOperandValue(lastInsr, 0)

            # Create the node
            if (curBlock not in graph):
                graph[curBlock] = (self.GetIdaFuncBlock(leftAddr), self.GetIdaFuncBlock(rightAddr))
        return graph

    def StartPtAnalysis(self, startEa):
        curEa = startEa
        nextEa = 0                   # Next IDA Address

        
        while True:
            #Read next packet
            line = self.hTraceFile.readline()
            if (line == '' or line.strip() == 'END'): break
            line = line.strip()
            if (line == ''): continue
            nextPck = self.GetPacket(line)
            self.lineNumber += 1

            nextEa = self.AnalyseNextChunk(curEa, nextPck)
            if (nextEa == 0): 
                # Here it means that we are in 2 totally different points in the code (kernel drivers are a good example)
                if (nextPck[1][:3] != "fup" and nextPck[1][:3] != "tip"):
                    print("I found an internal error. Packet ID: %s, type: %s, current IP: %s" % (hex(nextPck[0]), nextPck[1], hex(curEa)))
                    break
                completePtAddr = self.GetPtPckFullIP(nextPck)
                nextEa = self.GetIdaAddress(completePtAddr)
                print("Found another unrelated block of code in the DUMP. Start at %s. Line #%d in the dump file." % (hex(nextEa), self.lineNumber))
            elif (nextEa == -1):
                # Some errors or we are done
                break

            self.lastPtPck = nextPck
            curEa = nextEa
        return True
        
    def Is64BitPe(self):
        info = idaapi.get_inf_structure()
        return info.is_64bit()

    def AnalyseNextChunk(self, startEa, nextPck):
        prevPck = self.lastPtPck;
        curEa = startEa             
        endEa = 0                   # The ending Address
        curRetAddr = 0              # Current REturn Address

        if (nextPck[0] == 0x7c7): 
           ciao = nextPck[0]


        #Analyse here the next packet
        pckType = nextPck[1]
        if pckType == "fup" or pckType == "tip" or pckType == "tip.pge":
            # Arg1 - Address type (IpBytes) - in powers of "2"
            # Arg2 - Final address
            completePtAddr = self.GetPtPckFullIP(nextPck)
            endEa = self.GetIdaAddress(completePtAddr)
            if (endEa == startEa): return startEa
        elif pckType == "tip.pgd":
            # Asynchronous event here
            return startEa
        elif pckType[:3] == "tnt":
            # Taken - not taken packet here, allow them to decide what to do
            if (nextPck != prevPck):
                self.curTntMaskAndOffset = [nextPck[2], 0]
        else:
            # Not interesting packets
            return startEa
        
        # Grab current REturn address if any
        if (len(self.retAddrs) > 0):
            curRetAddr = self.retAddrs[-1];

        # Cycle between each instruction
        while (True):
            mnem = idc.GetMnem(curEa)
            if (mnem == ''):
                # Internal Error here
                print ("Unable to disassemble the instruction at address %s. Current packet: %s." % (hex(curEa), hex(nextPck[0])))   
                return -1

            targetEa = 0
            #Color this instruction
            self.ColorInstruction(curEa)

            if (mnem == "call" or mnem == "jmp"):
                targetEa = idc.GetOperandValue(curEa, 0)        # Only if the Operand is idc.o_near
                nextEa = idc.NextHead(curEa)
                opType = idc.GetOpType(curEa, 0)
                if (opType == idc.o_mem):
                    # Read the memory
                    if (self.Is64BitPe()): targetEa = idc.Qword(targetEa)
                    else: targetEa = idc.Dword(targetEa)
                elif (opType == idc.o_reg):
                    # How to detect the value of the register?
                    # Simple, wait for the next packet
                    if (mnem == "call"): self.retAddrs.append(nextEa)
                    cmt = idc.CommentEx(curEa, 0)
                    if (cmt is None): cmt = "Target: "
                    cmt += (hex(endEa)[:-1]) + " "
                    idc.MakeComm(curEa, cmt)
                    return endEa        # This is a clever hack
                if (idc.GetOpType(targetEa, 0) > -1):           # if idc.isHead(targetEa):
                    if (mnem == "call"): self.retAddrs.append(nextEa)
                    self.lastPtPck = nextPck
                    return self.AnalyseNextChunk(targetEa, nextPck)
                else:
                    if (mnem == "call"):
                        #Imported function, skip this
                        targetEa = nextEa
                    else:
                        # Imported API, return the ret Address
                        if (len(self.retAddrs) > 0):
                            targetEa = self.retAddrs.pop()
                            return targetEa            
                        else:
                            return -1
 
            elif (mnem == "ja" or mnem == "jae" or mnem == "jb" or mnem == "jbe" or             
                mnem == "je" or mnem == "jg" or mnem == "jge" or mnem == "jl" or mnem == "jle" or 
                mnem == "jna" or mnem == "jnae" or mnem == "jnb" or mnem == "jnbe" or mnem == "jnc" or 
                mnem == "jne" or mnem == "jng" or mnem == "jnge" or mnem == "jnl" or mnem == "jnle" or
                mnem == "jno" or mnem == "jns" or mnem == "jnz" or mnem == "jo" or mnem == "jp" or
                mnem == "jpe" or mnem == "jpo" or mnem == "js" or mnem == "jz" or mnem == "jp" or
                mnem == "jc" or mnem == "jecxz" or mnem == "jcxz" or mnem == "jrcxz" or 
                mnem == "loop" or mnem == "loope" or mnem == "loopne" or mnem == "loopnz" or mnem == "loopz"):
                # A COFI packet, analyse it and decide what will be the next instruction
                (mask, offset) = (self.curTntMaskAndOffset[0], self.curTntMaskAndOffset[1])
                if (offset >= len(mask)):
                    # Still not reached the right point
                    return curEa

                if (mask[offset] == '!'):
                    # Taken, go to the right
                    targetEa = idc.GetOperandValue(curEa, 0)
                else:
                    targetEa = idc.NextHead(curEa)

                # Increase the currently analysed offset and determine if I have to stop or not
                if (offset + 1 >= len(mask)):
                    # I need to exit here
                    self.curTntMaskAndOffset = ["", 0]
                    return targetEa
                else:
                    self.curTntMaskAndOffset = [mask, offset + 1]

            elif (mnem == "ret" or mnem == "retn"):
                (mask, offset) = (self.curTntMaskAndOffset[0], self.curTntMaskAndOffset[1])

                #Pop the RET address and continue from there
                if (len(self.retAddrs) > 0):
                    targetEa = self.retAddrs.pop()
                else:
                    # We are done, go to another block (if any)
                    return 0

                if (offset < len(mask)):
                    # Intel Manual, section 36.4.2.1 - Taken/Not-taken (TNT) Packet
                    # It seems that the TNT packets tracks even the RET opcodes
                    if (mask[offset] != '!'):
                        # Signal here the error??
                        raise StandardError("The TNT bit should not be 0 for a RET opcode")

                    # Increase the currently analysed offset and determine if I have to stop or not
                    if (offset + 1 >= len(mask)):
                        # I need to exit here
                        self.curTntMaskAndOffset = ["", 0]
                        return targetEa
                    else:
                        self.curTntMaskAndOffset = [mask, offset + 1]
                #End of Ret branch
            # For each other instructions continue until we reach endEa
            else:
                targetEa = idc.NextHead(curEa)

            if (targetEa == endEa):
                return targetEa
            curEa = targetEa

            # The following code worked:
            #if (endEa == 0 or targetEa < endEa): 
            #    curEa = targetEa
            #elif (targetEa == endEa):
            #    return targetEa
            #elif (curRetAddr != 0 and curRetAddr <= endEa):
            #    # There should be a RET somewhere
            #    curEa = targetEa
            #else:
            #    return targetEa

    def Run(self, fileName = ''):
        # Ask the user for a file if needed
        if fileName == '' or fileName == None:
            fileName = idc.AskFile(0, "*.*", "Select a PT dump file...") 
        
        # Run the engine and get the base start address:
        qwStartEa = self.ParseFileAndGetStartAddr(fileName)
        if (qwStartEa == 0): 
            print "Error! The specified dump file is not valid!"
            return False 
        #print "Obtained %s has start virtual address." % hex(qwStartEa)
        return self.StartPtAnalysis(qwStartEa)

if (IDA_READY == 0):
    print "This Script requires IDA Python to properly work."
    print "Open me in IDA please!"
    raw_input("Press any key to exit...")
else:
    plugin = Ida_pt()
    plugin.Run()



