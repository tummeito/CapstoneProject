import { nanoid } from 'nanoid';
import {
  Edge,
  EdgeChange,
  Node,
  NodeChange,
  OnNodesChange,
  OnEdgesChange,
  applyNodeChanges,
  applyEdgeChanges,
  XYPosition,
  Position,
} from 'reactflow';
import { create } from 'zustand';
 
export type RFState = {
  nodes: Node[];
  edges: Edge[];
  onNodesChange: OnNodesChange;
  onEdgesChange: OnEdgesChange;
  addChildNode: (parentNode: Node, position: XYPosition) => void;
  updateNodeLabel: (nodeId: string, label: string) => void;
  updateNodeText: (nodeId: string, text: string) => void;
  updateAllNodes: (newNodes: Node[], newEdges: Edge[]) => void;
  addNewNode: () => void;
};
 
const useStore = create<RFState>((set, get) => ({
  nodes: [
    {
      id: 'root',
      type: 'mindmap',
      data: { label: 'Main QUEST' , text: ''},
      position: { x: 0, y: 0 },
    },
  ],
  edges: [],
  onNodesChange: (changes: NodeChange[]) => {
    set({
      nodes: applyNodeChanges(changes, get().nodes),
    });
  },
  onEdgesChange: (changes: EdgeChange[]) => {
    set({
      edges: applyEdgeChanges(changes, get().edges),
    });
  },
  addChildNode: (parentNode: Node, position: XYPosition) => {
    const newNode = {
      id: nanoid(),
      type: 'mindmap',
      data: { label: '', text: '' },
      position,
      parentNode: parentNode.id,
    };
   
    const newEdge = {
      id: nanoid(),
      source: parentNode.id,
      target: newNode.id,
    };
   
    set({
      nodes: [...get().nodes, newNode],
      edges: [...get().edges, newEdge],
    });
  },
  updateNodeLabel: (nodeId: string, label: string) => {
    set({
      nodes: get().nodes.map((node) => {
        if (node.id === nodeId) {
          node.data = { ...node.data, label };
        }
   
        return node;
      }),
    });
  },
  updateNodeText: (nodeId: string, text: string) => {
    set({
      nodes: get().nodes.map((node) => {
        if (node.id === nodeId){
          node.data = { ...node.data, text};
        }

        return node;
      })
    })
  },
  addNewNode: () => {
    const newNode = {
      id: nanoid(),
      type: 'mindmap',
      data: { label: 'New ROOT' , text: ''},
      position: { x: 200, y: 0 }
    };

    set ({
      nodes: [...get().nodes, newNode]
    });
  },
  updateAllNodes: (newNodes: Node[], newEdges: Edge[]) => {
    set ({
      nodes: [...newNodes],
      edges: [...newEdges]
    })
  }
}));


 
export default useStore;