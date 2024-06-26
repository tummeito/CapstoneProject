import { Handle, NodeProps, Position } from 'reactflow';
 
import useStore from '../storeage';
 
export type NodeData = {
  label: string;
  text: string;
};
 
function CustomNode({ id, data }: NodeProps<NodeData>) {
  const updateNodeLabel = useStore((state) => state.updateNodeLabel);
  const updateNodeText = useStore((state) => state.updateNodeText);
 
  return (
    <>
      <div className="inputWrapper">
        <div className="dragHandle">
          {/* icon taken from grommet https://icons.grommet.io */}
          <svg viewBox="0 0 24 24">
            <path
              fill="#333"
              stroke="#333"
              strokeWidth="1"
              d="M15 5h2V3h-2v2zM7 5h2V3H7v2zm8 8h2v-2h-2v2zm-8 0h2v-2H7v2zm8 8h2v-2h-2v2zm-8 0h2v-2H7v2z"
            />
          </svg>
        </div>
        <input
          value={data.label}
          onChange={(evt) => updateNodeLabel(id, evt.target.value)}
          className="input"
        />

      </div>
      <div className="inputWrapper">
      <input
          value={data.text}
          onChange={(evt) => updateNodeText(id, evt.target.value)}
          className="textBox"
        />
      </div>

      
      <Handle type="target" position={Position.Top} />
      <Handle type="source" position={Position.Top} />
    </>
  );
}
 
export default CustomNode;