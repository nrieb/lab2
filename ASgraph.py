#! /usr/bin/env python

class ASGraph(object):
    self.nodes = {}
    self.graph = []
    
    def add(self, path, subnets):
        prevKey = -1
        #TODO see if this path needs to be reversed or not
        for AS in path:
            if !self.nodes.has_key(AS):
                self.nodes[AS] = self.Node(len(self.graph))
                self.graph.append(set([]))
            
            if prevKey != -1:
                self.graph[prevKey].add(self.nodes[AS])
            
            prefKey = self.node[AS].key
        
        

    class Node(object):
        
        def __init__(self, key):
            self.key = key
            self.subnets = []

        def add_subnets(self, subnets): 
            self.subnets.append(subnet)
