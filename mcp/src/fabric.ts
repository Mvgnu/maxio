import { mkdtemp, writeFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Config } from './config';
import { boundedBody, MAX_BYTES } from './console';
// Only concrete registered tool builders call this adapter, never arbitrary RPC input.
export class FabricClient {
  constructor(private config:Config['fabric']){}
  async control(request:Record<string,unknown>):Promise<unknown>{
    if(!this.config) throw new Error('Managed fabric unavailable: owner has not configured fabric');
    const dir=await mkdtemp(join(tmpdir(),'maxio-mcp-')); await chmod(dir,0o700);
    let child:Bun.Subprocess<'ignore','pipe','pipe'>|undefined;
    try{
      const path=join(dir,'request.json'); await writeFile(path,JSON.stringify(request),{mode:0o600,flag:'wx'});
      child=Bun.spawn([this.config.binary,'--config',this.config.config,'rpc','--request',path],{stdin:'ignore',stdout:'pipe',stderr:'pipe'});
      const timer=setTimeout(()=>child?.kill(),20000);
      try{
        const [stdout,stderr,code]=await Promise.all([boundedBody(new Response(child.stdout),MAX_BYTES),boundedBody(new Response(child.stderr),65536),child.exited]);
        void stderr; if(code!==0) throw new Error('Fabric RPC failed; inspect authority state before replaying the same request ID');
        return JSON.parse(new TextDecoder().decode(stdout));
      } finally {clearTimeout(timer);}
    }catch(error){child?.kill(); throw error;}finally{await rm(dir,{recursive:true,force:true});}
  }
}
