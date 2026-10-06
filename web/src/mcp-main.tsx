import { createRoot } from 'react-dom/client';
import { McpApproval } from './McpApproval';
import './styles.css';
const root = document.getElementById('root');
if (!root) throw new Error('Missing App root');
createRoot(root).render(<McpApproval />);
