import process from 'node:process';
import { runGatewayProcess } from '../dist/node-server.js';

await runGatewayProcess(process.env, process);
