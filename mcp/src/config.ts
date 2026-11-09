import { lstat, readFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { z } from 'zod';
import { canonicalOrigin } from './console';
const absolute=z.string().refine(isAbsolute,'Owner path must be absolute');
export const configSchema=z.strictObject({
  console:z.strictObject({endpoint:z.string(),accessKey:z.string().min(1),secretKey:z.string().min(1)}),
  fabric:z.strictObject({binary:absolute,config:absolute}).optional(),
  service:z.strictObject({command:absolute,args:z.array(z.string()).max(100),cwd:absolute,autoStart:z.boolean().optional()}).optional(),
});
export type Config=z.infer<typeof configSchema>;
export async function readConfig(path=process.env.MAXIO_MCP_CONFIG):Promise<Config>{
  if(!path || !isAbsolute(path)) throw new Error('MAXIO_MCP_CONFIG must name an absolute owner-local JSON file');
  const stat=await lstat(path); if(!stat.isFile() || stat.size>65536 || (stat.mode&0o077)!==0 || stat.uid!==process.getuid?.()) throw new Error('MCP config must be an owner-owned regular file with mode 0600');
  const config=configSchema.parse(JSON.parse(await readFile(path,'utf8'))); canonicalOrigin(config.console.endpoint); return config;
}
