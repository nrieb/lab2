#! /usr/bin/env python

class ASGraph(object):
    # graph with 1 root node set means we assume only one directed
    # edge between any two nodes

    def __init__(self, nodes={}, graph=[]):
        self.nodes = {'root' : self.Node(0, [], [])}
        self.graph = [set([])]
        for AS, node in nodes.viewitems():
            if AS == 'root':
                continue
            self[AS] = node

        for adj_list in graph:
            self.graph.append(adj_list)
            
    
    def add(self, path, subnets, withdrawn):
        #TODO see if i need to propagate withdrawn further
        #if i do, then i have to make sure nothing else pointing to it
        #with the same subnet
        assert len(path)
        #add to root first
        prevKey = 0
        #path is initially closest to farthest
        for AS in path:
            assert AS != 'root'
            if not self.nodes.has_key(AS):
                self.nodes[AS] = self.Node(len(self.graph), [], [])
                self.graph.append(set([]))

            self.graph[prevKey].add(self.nodes[AS])
            self.nodes[AS].add_subnets(subnets)
            self.nodes[AS].add_withdrawn(withdrawn)
            prefKey = self.nodes[AS].key
        
        

    def __repr__(self):
        return "ASGraph(nodes=%r, graph=%r)" % (self.nodes, self.graph)

    class Node(object):
        
        def __init__(self, key, subnets, withdrawn):
            self.key = key
            self.subnets = subnets
            self.withdrawn = withdrawn

        def add_subnets(self, subnets):
            for subnet in subnets:
                self.subnets.append(subnet)
        
        def add_withdrawn(self, subnets):
            for subnet in subnets:
                self.withdrawn.append(subnets)

        def __repr__(self):
            return "self.Node(key=%r, subnets=%r, withdrawn=%r)" % (self.key, self.subnets, self.withdrawn)
