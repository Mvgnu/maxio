import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { readConfig } from './config';
import { createServer } from './server';
try{const config=await readConfig(),{server,service}=createServer(config);if(config.service?.autoStart)await service.start();let closing=false;async function close(){if(closing)return;closing=true;await service.stop();await server.close();process.exit(0);}process.on('SIGTERM',()=>void close());process.on('SIGINT',()=>void close());process.stdin.on('end',()=>void close());await server.connect(new StdioServerTransport());}catch{console.error('MaxIO MCP startup failed: verify private MAXIO_MCP_CONFIG and owner-selected settings');process.exit(1);}
