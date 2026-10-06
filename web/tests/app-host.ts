//! Test-only reference host using the official MCP Apps bridge.
import { AppBridge, PostMessageTransport } from '@modelcontextprotocol/ext-apps/app-bridge';
import type { CallToolRequest, CallToolResult } from '@modelcontextprotocol/client';
declare global {
  interface Window {
    avAppHtml: string;
    avInitialResult: CallToolResult;
    avCallTool: (params: CallToolRequest['params']) => Promise<CallToolResult>;
    avDeliverResult: (result: CallToolResult) => Promise<void>;
  }
}
const frame = document.createElement('iframe');
frame.title = 'Agents Vault MCP App';
frame.setAttribute('sandbox', 'allow-scripts');
frame.style.cssText = 'width:100%;min-height:1000px;border:0;display:block';
document.body.style.margin = '0';
document.body.append(frame);
if (!frame.contentWindow) throw new Error('Missing App frame');
const bridge = new AppBridge(
  null,
  { name: 'Official SDK test host', version: '0.1.0' },
  { serverTools: {}, serverResources: {} },
  { hostContext: { theme: 'dark', displayMode: 'inline' } },
);
bridge.oncalltool = (params) => window.avCallTool(params);
bridge.addEventListener('initialized', () => {
  void bridge
    .sendToolInput({ arguments: {} })
    .then(() => bridge.sendToolResult(window.avInitialResult));
});
window.avDeliverResult = (result) => bridge.sendToolResult(result);
await bridge.connect(new PostMessageTransport(frame.contentWindow, frame.contentWindow));
frame.srcdoc = window.avAppHtml;
