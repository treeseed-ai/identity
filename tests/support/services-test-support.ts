import {test,expect} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {CordisComposition,type CompositionHandle} from '@treeseed-cordis/sdk/composition';
import {ServiceTokens,PluginManagementSchemas,ProviderV4Schemas,type ProbeContext} from '@treeseed-cordis/sdk';
export class DiscoveryFixture implements ProbeContext {
 readonly serviceId='selected-identity';readonly expected={installationId:'fixture',compositionGeneration:'a'.repeat(64),serviceGeneration:'b'.repeat(64),assetDigest:'c'.repeat(64)};readonly credentialReferences:string[]=[];readonly authorityIds:string[]=[];readonly signal=new AbortController().signal;readonly deadline=Date.now()+10000;readonly issuer='https://localhost:8443/identity/realms/cordis';readonly server=Bun.serve({hostname:'127.0.0.1',port:0,fetch:this.respond.bind(this)});readonly endpoint='http://127.0.0.1:'+this.server.port;
 requests=0;privateReads=0;invalid=false;redirect=false;oversized=false;
 private respond(request:Request):Response{this.requests++;if(new URL(request.url).pathname!=='/identity/realms/cordis/.well-known/openid-configuration')return new Response(null,{status:404});if(this.redirect)return Response.redirect('https://credential-canary.invalid');if(this.oversized)return new Response('x'.repeat(131072));return Response.json({issuer:this.invalid?'https://secret-canary.invalid':this.issuer,authorization_endpoint:this.issuer+'/protocol/openid-connect/auth',token_endpoint:this.issuer+'/protocol/openid-connect/token',jwks_uri:this.issuer+'/protocol/openid-connect/certs',code_challenge_methods_supported:['S256'],response_types_supported:['code']});}
 credential(_reference:string):Promise<Uint8Array>{this.privateReads++;return Promise.reject(new Error('forbidden-secret-canary'));}
 authority(_id:string):Promise<Uint8Array>{this.privateReads++;return Promise.reject(new Error('forbidden-authority-canary'));}
 close():void{this.server.stop(true);}
}
import type {Context} from '@treeseed-cordis/sdk/composition';
export class ProbeReceiver{context:Context|null=null;}
export class ProbeConsumer{static readonly inject=['cordis.composition','probe.service'];constructor(context:Context,receiver:ProbeReceiver){receiver.context=context;}}
