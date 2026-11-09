import type { Config } from './config';
export class Service {
 private child?:Bun.Subprocess<'ignore','pipe','pipe'>;private logs='';private busy=false;
 constructor(private config:Config['service'],private consoleConfig:Config['console']){}
 private async external(){try{const response=await fetch(new URL('/api/auth/check',this.consoleConfig.endpoint),{redirect:'manual',signal:AbortSignal.timeout(1000)});await response.body?.cancel();return true;}catch{return false;}}
 status(){return {configured:!!this.config,owned:!!this.child&&this.child.exitCode===null,running:this.child?.exitCode===null,exitCode:this.child?.exitCode??null};}
 tail(){return {logs:this.logs.split(this.consoleConfig.secretKey).join('[REDACTED]').split(this.consoleConfig.accessKey).join('[REDACTED]'),...this.status()};}
 private async drain(stream:ReadableStream<Uint8Array>){const reader=stream.getReader();for(;;){const {done,value}=await reader.read();if(done)break;this.logs=(this.logs+new TextDecoder().decode(value)).slice(-16384);}}
 async start(){if(!this.config)throw new Error('Service unavailable: no owner-configured command');if(this.busy)throw new Error('Service transition in progress');if(this.child?.exitCode===null)return this.status();if(await this.external())return {...this.status(),external:true,running:true};this.child=Bun.spawn([this.config.command,...this.config.args],{cwd:this.config.cwd,stdin:'ignore',stdout:'pipe',stderr:'pipe'});void this.drain(this.child.stdout);void this.drain(this.child.stderr);return this.status();}
 async stop(){if(this.busy)throw new Error('Service transition in progress');const child=this.child;if(!child||child.exitCode!==null){if(await this.external())throw new Error('External server is not owned by this MCP session; stop/restart refused');return this.status();}this.busy=true;try{child.kill('SIGTERM');await Promise.race([child.exited,Bun.sleep(3000)]);if(child.exitCode===null){child.kill('SIGKILL');await child.exited;}return this.status();}finally{this.busy=false;}}
 async restart(){await this.stop();return this.start();}
}
