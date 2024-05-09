import ReactFlow, {
    ConnectionLineType,
    NodeOrigin,
    Node,
    OnConnectEnd,
    OnConnectStart,
    useReactFlow,
    useStoreApi,
    Controls,
    Panel,
  } from 'reactflow';
import { shallow } from 'zustand/shallow';
 
import useStore, { RFState } from './storeage';
import CustomNode from './CustomNode';
import CustomEdge from './CustomEdge';

import 'reactflow/dist/style.css';
import React, { useRef, useCallback, useState, MouseEvent } from 'react';

const nodeTypes = {
    mindmap: CustomNode,
  };
   
const edgeTypes = {
    mindmap: CustomEdge,
  };
  

const selector = (state: RFState) => ({
  nodes: state.nodes,
  edges: state.edges,
  onNodesChange: state.onNodesChange,
  onEdgesChange: state.onEdgesChange,
  addChildNode: state.addChildNode,
  updateAllNodes: state.updateAllNodes,
});


const nodeOrigin: NodeOrigin = [0.5, 0.5];


function Flow() {
  
  const { nodes, edges, onNodesChange, onEdgesChange, addChildNode, updateAllNodes } = useStore(
    selector,
    shallow,
  );
  const store = useStoreApi()
  const connectingNodeId = useRef<string | null>(null);
  const { project } = useReactFlow();
  
  const getChildNodePosition = (event: MouseEvent, parentNode?: Node) => {
    const { domNode } = store.getState();

    if (
      !domNode ||
      !parentNode?.positionAbsolute ||
      !parentNode?.width ||
      !parentNode?.height
    ) {
      return;
    }

    const { top, left } = domNode.getBoundingClientRect();

    const panePosition = project({
      x: event.clientX - left,
      y: event.clientY - top,
    });

    return {
      x: panePosition.x - parentNode.positionAbsolute.x + parentNode.width / 2,
      y: panePosition.y - parentNode.positionAbsolute.y + parentNode.height / 2,
    };
  };
  const onConnectStart: OnConnectStart = useCallback((_, { nodeId }) => {
    connectingNodeId.current = nodeId;
  }, []);
 
  const onConnectEnd: OnConnectEnd = useCallback(
    (event) => {
        const { nodeInternals } = store.getState();
        const targetIsPane = (event.target as Element).classList.contains(
          'react-flow__pane'
        );
        const node = (event.target as Element).closest('.react-flow__node');
  
        if (node) {
          node.querySelector('input')?.focus({ preventScroll: true });
        } else if (targetIsPane && connectingNodeId.current) {
          const parentNode = nodeInternals.get(connectingNodeId.current);
          // @ts-ignore comment
          const childNodePosition = getChildNodePosition(event, parentNode);
  
          if (parentNode && childNodePosition) {
            addChildNode(parentNode, childNodePosition);
          }
        }
      },
      [getChildNodePosition]
  );
  
  const exportToJson = () => {

    const jsonData = {nodes, edges};
    const jsonString = JSON.stringify(jsonData);
    const blob = new Blob([jsonString], { type: 'application/json' });

    // Create a temporary URL for the Blob
    const url = window.URL.createObjectURL(blob);

    // Create a temporary <a> element to trigger the download
    const a = document.createElement('a');
    a.href = url;
    a.download = 'exported_data.json';

    // Append the <a> element to the DOM
    document.body.appendChild(a);

    // Click on the <a> element to trigger the download
    a.click();

    // Cleanup: remove the temporary <a> element and revoke the temporary URL
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  };
  
  // const [jsonData, setJsonData] = useState(null);

  const handleFileChange = (event: React.ChangeEvent<any>) => {
    const file = event.target.files[0];
    const reader = new FileReader();
    
    reader.onload = (e) => {
      try {
        if (e.target != null && typeof(e.target.result) == "string") {
          const parsedJson = JSON.parse(e.target.result);
          console.log("e.target.result", parsedJson);
          const newNodes = parsedJson["nodes"];
          const newEdges = parsedJson["edges"];
          console.log("newNodes", newNodes);
          console.log("newEdges", newEdges);
          updateAllNodes(newNodes, newEdges);
          // const { newNodes, newEdges } = parsedJson;
          // updateAllNodes(newNodes, newEdges);
        }
      } catch (error) {
        console.error('Error parsing JSON file: ', error);
      }
    };

    reader.readAsText(file);
  };

  // const handleUpload = () => {
  //   // Process jsonData array of objects here
  //   console.log('Uploaded JSON data: ', jsonData);
  // };

  return (

    <ReactFlow
    nodes={nodes}
    edges={edges}
    onNodesChange={onNodesChange}
    onEdgesChange={onEdgesChange}
    onConnectStart={onConnectStart}
    onConnectEnd={onConnectEnd}
    nodeTypes={nodeTypes}
    edgeTypes={edgeTypes}
    nodeOrigin={nodeOrigin}
    // defaultEdgeOptions={defaultEdgeOptions}
    // connectionLineStyle={connectionLineStyle}
    connectionLineType={ConnectionLineType.Straight}
    fitView
    >
      <Controls showInteractive={false} />
      <Panel position="top-right">
        <button onClick={exportToJson}>Export current Nodes and Edges</button>
        <div />
        <div>
          <h1>Upload Json file</h1>

          <input type="file" onChange={handleFileChange} />
        </div>
      </Panel>
      <Panel position="top-left"><h1>Quest Tracker</h1></Panel>
    </ReactFlow>
  );
}
 
export default Flow;