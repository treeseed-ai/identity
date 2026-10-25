import {KeycloakServicePlugin,KeycloakReadinessPlugin,IdentityProviderPolicy} from './services.js';
import postgres,{type Sql} from 'postgres';
import * as oidc from 'openid-client';
import {Service} from 'cordis';
import {randomBytes} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {PackageDefinition,ProviderV4Schemas,type NativeProviderDeclaration,InstalledSchemas,InstalledDeclarations,InstalledTokens,PlatformSchemas,ProviderSchemas,CapabilityToken,CanonicalJson,type ContainerEngine,type ReadyContainer,type ServerConfiguration,type TrustedPrincipal,type ProviderArtifact,type ProviderDeclaration} from '@treeseed-cordis/sdk';
import {Context,type ProviderRegistration} from '@treeseed-cordis/sdk/runtime';

export interface IdentitySessions {
  login():Promise<{location:string;state:string}>;
  callback(url:URL,cookie:string):Promise<string>;
  principal(cookie:string):Promise<TrustedPrincipal|null>;
  logout(cookie:string):Promise<void>;
  ready():Promise<boolean>;
}
export interface IdentityPersistence {
 ready():Promise<boolean>;pending(state:string,nonce:string,verifier:string):Promise<void>;consume(state:string):Promise<{nonce:string;verifier:string}>;session(subject:string):Promise<string>;principal(cookie:string):Promise<TrustedPrincipal|null>;logout(cookie:string):Promise<void>;
}
export interface IdentityProtocolAdapter {ready():Promise<boolean>;login(state:string,nonce:string,verifier:string):Promise<string>;exchange(url:URL,state:string,nonce:string,verifier:string):Promise<string>;}
class Adapter<T extends object> {constructor(private readonly methods:string[]){}parse(value:unknown):T {if(!value||typeof value!=='object')throw new Error('Identity adapter unavailable');for(const method of this.methods)if(typeof Reflect.get(value,method)!=='function')throw new Error('Identity adapter unavailable');return value as T;}}
export const IdentitySessionsToken=new CapabilityToken<IdentitySessions>('identity.sessions',ProviderV4Schemas.version,new Adapter(['login','callback','principal','logout','ready']));
export const IdentityPersistenceToken=new CapabilityToken<IdentityPersistence>('identity.store',ProviderV4Schemas.version,new Adapter(['pending','consume','session','principal','logout','ready']));
export const IdentityProtocolToken=new CapabilityToken<IdentityProtocolAdapter>('identity.oidc',ProviderV4Schemas.version,new Adapter(['login','exchange','ready']));
const StoreToken=IdentityPersistenceToken,ProtocolToken=IdentityProtocolToken;
class Declaration {static server(id:string,capability:string,inject:string[]):NativeProviderDeclaration{return ProviderV4Schemas.declaration.parse({id,pluginId:'identity',capability,contractVersion:ProviderV4Schemas.version,target:'api',provide:[capability],inject});}}

export class KeycloakContainerPlugin implements ReadyContainer {
  static readonly declaration=InstalledDeclarations.service('keycloak','container.identity',['deployment.engine','container.database']);
  static readonly definition=InstalledSchemas.definition.parse({role:'identity',service:{command:['start','--import-realm'],environment:{JAVA_OPTS_KC_HEAP:'-Xms128m -Xmx512m'},user:'installation-owner',workerSocket:false,volumes:[],secrets:[{source:'identity-config',target:'/opt/keycloak/conf/keycloak.conf'},{source:'identity-realm',target:'/opt/keycloak/data/import/cordis-realm.json'}],portTarget:null},slots:{
    'oidc-client':{kind:'random'},'bootstrap-password':{kind:'random'},'bootstrap-subject':{kind:'uuid'},
    'identity-config':{kind:'properties',value:{db:'postgres','db-url':'jdbc:postgresql://database:5432/cordis','db-username':'cordis','db-password':{$secret:'database-password'},'http-enabled':'true','http-relative-path':'/identity',hostname:{$origin:'/identity'},'proxy-headers':'xforwarded','health-enabled':'true'}},
    'identity-realm':{kind:'json',value:{realm:'cordis',enabled:true,sslRequired:'external',registrationAllowed:false,loginWithEmailAllowed:false,resetPasswordAllowed:false,clients:[{clientId:'cordis-admin',enabled:true,protocol:'openid-connect',publicClient:false,secret:{$secret:'oidc-client'},standardFlowEnabled:true,directAccessGrantsEnabled:false,redirectUris:[{$origin:'/admin/callback'}],attributes:{'pkce.code.challenge.method':'S256'}}],users:[{id:{$secret:'bootstrap-subject'},username:'admin',enabled:true,emailVerified:true,email:'admin@localhost',firstName:'Installation',lastName:'Owner',requiredActions:[],credentials:[{type:'password',value:{$secret:'bootstrap-password'},temporary:false}]}]}},
    bootstrap:{kind:'json',value:{username:'admin',password:{$secret:'bootstrap-password'}}}
  },readiness:{kind:'http-json',path:'/identity/realms/cordis/.well-known/openid-configuration',expected:{issuer:{$origin:'/identity/realms/cordis'}}}});
  static readonly provide=this.declaration.provide;static readonly inject=this.declaration.inject;static readonly Config=PlatformSchemas.empty;
  private readonly engine:ContainerEngine;
  constructor(private readonly context:Context){this.engine=InstalledTokens.engine.parse(Reflect.get(context,InstalledTokens.engine.id));}
  async [Service.init]():Promise<void>{await this.engine.start('identity',KeycloakContainerPlugin.definition);if(!await this.ready())throw new Error('Identity readiness failed');this.context.provide(InstalledTokens.identity.id,this);}
  ready():Promise<boolean>{return this.engine.ready('identity');}
  identity():Readonly<{installationId:string;composition:string}>{return this.engine.identity();}
}
export {KeycloakContainerPlugin as Provider};

/** The only network adapter is the pinned internal route to the configured public issuer. */
export class IdentityProtocol {
  private configuration:oidc.Configuration|null=null;
  readonly settings:ServerConfiguration;
  constructor(settings:unknown){this.settings=IdentityProtocol.validateConfiguration(settings);}
  static validateConfiguration(value:unknown):ServerConfiguration {
    const settings=InstalledSchemas.serverConfiguration.parse(value),issuer=new URL(settings.issuer),internal=new URL(settings.identityInternalOrigin);
    if(issuer.origin!==settings.origin||issuer.pathname!=='/identity/realms/cordis'||internal.protocol!=='http:'||internal.hostname!=='identity'||internal.port!=='8080'||internal.pathname!=='/')throw new Error('Invalid identity route');return settings;
  }
  private proxyHeaders():Record<string,string>{const origin=new URL(this.settings.origin);return {'x-forwarded-proto':'https','x-forwarded-host':origin.host,'x-forwarded-port':origin.port||'443'};}
  async initialize():Promise<void>{this.configuration=await oidc.discovery(new URL(this.settings.issuer),this.settings.clientId,{client_secret:this.settings.clientSecret,token_endpoint_auth_method:'client_secret_post'},undefined,{[oidc.customFetch]:this.fetch.bind(this)});}
  private async fetch(input:Parameters<oidc.CustomFetch>[0],options:Parameters<oidc.CustomFetch>[1]):Promise<Response>{const requested=new URL(String(input));if(requested.origin!==this.settings.origin||!requested.pathname.startsWith('/identity/realms/cordis/'))throw new Error('Identity endpoint refused');const target=new URL(requested.pathname+requested.search,this.settings.identityInternalOrigin);return fetch(target,{...options,headers:{...options.headers,...this.proxyHeaders()},body:options.body instanceof Uint8Array?new Uint8Array(options.body):options.body,redirect:'error',signal:AbortSignal.timeout(10000)});}
  async ready():Promise<boolean>{try{const response=await fetch(new URL('/identity/realms/cordis/.well-known/openid-configuration',this.settings.identityInternalOrigin),{headers:this.proxyHeaders(),redirect:'error',signal:AbortSignal.timeout(3000)});if(!response.ok)return false;const document=await response.json() as {issuer?:unknown};return document.issuer===this.settings.issuer;}catch{return false;}}
  async login(state:string,nonce:string,verifier:string):Promise<string>{if(!this.configuration)throw new Error('Identity unavailable');return oidc.buildAuthorizationUrl(this.configuration,{redirect_uri:this.settings.origin+'/admin/callback',scope:'openid profile',response_type:'code',state,nonce,code_challenge:await oidc.calculatePKCECodeChallenge(verifier),code_challenge_method:'S256'}).href;}
  async exchange(url:URL,state:string,nonce:string,verifier:string):Promise<string>{if(!this.configuration||url.origin!==this.settings.origin||url.pathname!=='/admin/callback')throw new Error('Identity callback refused');const tokens=await oidc.authorizationCodeGrant(this.configuration,url,{expectedState:state,expectedNonce:nonce,pkceCodeVerifier:verifier,idTokenExpected:true});const claims=tokens.claims();if(!claims||typeof claims.sub!=='string'||claims.iss!==this.settings.issuer)throw new Error('Identity claims refused');return claims.sub;}
}
class DatabaseConnection {
 private readonly sql:Sql;
 constructor(connectionString:string){this.sql=postgres(connectionString,{max:4,connect_timeout:5,connection:{statement_timeout:5000},onnotice:DatabaseConnection.ignore});}
 private static ignore():void {}
 async query<T extends Record<string,unknown>=Record<string,unknown>>(statement:string,parameters:string[]=[]):Promise<{rows:T[]}>{const rows=await this.sql.unsafe<T[]>(statement,parameters);return {rows};}
 async end():Promise<void>{await this.sql.end({timeout:5});}
}
class IdentityStore {
  private readonly pool:DatabaseConnection;
  constructor(private readonly settings:ServerConfiguration){this.pool=new DatabaseConnection(settings.databaseUrl);}
  async initialize():Promise<void>{await this.pool.query('CREATE TABLE IF NOT EXISTS cordis_principals (id text PRIMARY KEY, issuer text NOT NULL, subject text NOT NULL, UNIQUE(issuer,subject)); CREATE TABLE IF NOT EXISTS cordis_sessions (id text PRIMARY KEY, principal text NOT NULL REFERENCES cordis_principals(id), expires timestamptz NOT NULL); CREATE TABLE IF NOT EXISTS cordis_pending (id text PRIMARY KEY, nonce text NOT NULL, verifier text NOT NULL, expires timestamptz NOT NULL)');}
  async ready():Promise<boolean>{try{const result=await this.pool.query('SELECT 1 AS ready');return result.rows[0]?.ready===1;}catch{return false;}}
  async close():Promise<void>{await this.pool.end();}
  async pending(state:string,nonce:string,verifier:string):Promise<void>{await this.pool.query('DELETE FROM cordis_pending WHERE expires < now()');await this.pool.query('INSERT INTO cordis_pending VALUES($1,$2,$3,now()+interval \'5 minutes\')',[CanonicalJson.digest(state),nonce,verifier]);}
  async consume(state:string):Promise<{nonce:string;verifier:string}>{const result=await this.pool.query<{nonce:string;verifier:string}>('DELETE FROM cordis_pending WHERE id=$1 AND expires>now() RETURNING nonce,verifier',[CanonicalJson.digest(state)]);if(result.rows.length!==1)throw new Error('Identity state expired');return result.rows[0]!;}
  async session(subject:string):Promise<string>{const principalId=CanonicalJson.digest({issuer:this.settings.issuer,subject}),cookie=randomBytes(32).toString('base64url');await this.pool.query('INSERT INTO cordis_principals VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING',[principalId,this.settings.issuer,subject]);await this.pool.query('DELETE FROM cordis_sessions WHERE expires<now()');await this.pool.query('INSERT INTO cordis_sessions VALUES($1,$2,now()+interval \'8 hours\')',[CanonicalJson.digest(cookie),principalId]);return cookie;}
  async principal(cookie:string):Promise<TrustedPrincipal|null>{if(!/^[A-Za-z0-9_-]{43}$/.test(cookie))return null;const result=await this.pool.query<{id:string;issuer:string;subject:string}>('SELECT p.* FROM cordis_sessions s JOIN cordis_principals p ON p.id=s.principal WHERE s.id=$1 AND s.expires>now()',[CanonicalJson.digest(cookie)]);if(result.rows.length!==1)return null;const row=result.rows[0]!;return InstalledSchemas.principal.parse({principalId:row.id,issuer:row.issuer,subject:row.subject,scopes:row.subject===this.settings.bootstrapSubject&&row.issuer===this.settings.issuer?['platform.read','platform.manage']:[]});}
  async logout(cookie:string):Promise<void>{if(/^[A-Za-z0-9_-]{43}$/.test(cookie))await this.pool.query('DELETE FROM cordis_sessions WHERE id=$1',[CanonicalJson.digest(cookie)]);}
}
class SessionService implements IdentitySessions {
  constructor(private readonly store:IdentityPersistence,private readonly protocol:IdentityProtocolAdapter){}
  async ready():Promise<boolean>{return await this.store.ready()&&await this.protocol.ready();}
  async login():Promise<{location:string;state:string}>{const state=randomBytes(32).toString('base64url'),nonce=randomBytes(32).toString('base64url'),verifier=randomBytes(32).toString('base64url');await this.store.pending(state,nonce,verifier);return {state,location:await this.protocol.login(state,nonce,verifier)};}
  async callback(url:URL,cookie:string):Promise<string>{const state=url.searchParams.get('state');if(!state||!cookie||state!==cookie||!/^[A-Za-z0-9_-]{43}$/.test(state))throw new Error('Identity state refused');const pending=await this.store.consume(state);const subject=await this.protocol.exchange(url,state,pending.nonce,pending.verifier);return this.store.session(subject);}
  principal(cookie:string):Promise<TrustedPrincipal|null>{return this.store.principal(cookie);}
  logout(cookie:string):Promise<void>{return this.store.logout(cookie);}
}
export class StorePlugin {
  static readonly replacement=IdentityProviderPolicy.replacement;
  static readonly declaration=Declaration.server('postgres-principals',StoreToken.id,[]);static readonly provide=this.declaration.provide;static readonly inject=this.declaration.inject;static readonly Config=InstalledSchemas.serverConfiguration;
  private readonly store:IdentityStore;
  constructor(private readonly context:Context,settings:ServerConfiguration){this.store=new IdentityStore(settings);}
  async [Service.init]():Promise<()=>Promise<void>>{try{await this.store.initialize();this.context.provide(StoreToken.id,this.store);}catch{await this.store.close();throw new Error('Identity store unavailable');}return this.store.close.bind(this.store);}
}
export class OidcPlugin {
  static readonly replacement=IdentityProviderPolicy.replacement;
  static readonly declaration=Declaration.server('configured-oidc',ProtocolToken.id,[]);static readonly provide=this.declaration.provide;static readonly inject=this.declaration.inject;static readonly Config=InstalledSchemas.serverConfiguration;
  private readonly protocol:IdentityProtocol;
  constructor(private readonly context:Context,settings:ServerConfiguration){this.protocol=new IdentityProtocol(settings);}
  async [Service.init]():Promise<void>{await this.protocol.initialize();this.context.provide(ProtocolToken.id,this.protocol);}
}
export class SessionPlugin {
  static readonly replacement=IdentityProviderPolicy.replacement;
  static readonly declaration=Declaration.server('database-session',IdentitySessionsToken.id,[StoreToken.id,ProtocolToken.id]);static readonly provide=this.declaration.provide;static readonly inject=this.declaration.inject;static readonly Config=PlatformSchemas.empty;
  constructor(context:Context){context.provide(IdentitySessionsToken.id,new SessionService(StoreToken.parse(Reflect.get(context,StoreToken.id)),ProtocolToken.parse(Reflect.get(context,ProtocolToken.id))));}
}
export class IdentityComposition {
  static registrations(settings:ServerConfiguration,artifact:ProviderArtifact):ProviderRegistration[]{return [{token:StoreToken,plugin:StorePlugin,declaration:StorePlugin.declaration,configuration:settings,artifact},{token:ProtocolToken,plugin:OidcPlugin,declaration:OidcPlugin.declaration,configuration:settings,artifact},{token:IdentitySessionsToken,plugin:SessionPlugin,declaration:SessionPlugin.declaration,configuration:{},artifact}];}
  static selections(scopeId:string):Array<{scopeId:string;capability:string;providerId:string}>{return [{scopeId,capability:StoreToken.id,providerId:StorePlugin.declaration.id},{scopeId,capability:ProtocolToken.id,providerId:OidcPlugin.declaration.id},{scopeId,capability:IdentitySessionsToken.id,providerId:SessionPlugin.declaration.id}];}
}
export class IdentityBuild {
  static metadata():ProviderDeclaration{return KeycloakContainerPlugin.declaration;}
  static providers():NativeProviderDeclaration[]{return [StorePlugin.declaration,OidcPlugin.declaration,SessionPlugin.declaration];}
  static package(){return PackageDefinition.define('@treeseed-cordis/identity','0.0.0-cordis.3','identity',[PackageDefinition.export(KeycloakServicePlugin,'dist/src/services.js','KeycloakServicePlugin'),PackageDefinition.export(KeycloakReadinessPlugin,'dist/src/services.js','KeycloakReadinessPlugin'),PackageDefinition.export(StorePlugin,'dist/src/identity.js','StorePlugin'),PackageDefinition.export(OidcPlugin,'dist/src/identity.js','OidcPlugin'),PackageDefinition.export(SessionPlugin,'dist/src/identity.js','SessionPlugin')],[],[KeycloakServicePlugin.image]);}
  static run():void{if(!import.meta.main)return;if(process.argv[2]==='--metadata'){const metadata=JSON.parse(readFileSync('package.json','utf8')) as Record<string,unknown>;metadata.cordis=this.metadata();metadata.cordisService=KeycloakContainerPlugin.definition;metadata.cordisProviders=this.providers();metadata.cordisPackage=this.package();writeFileSync('package.json',JSON.stringify(metadata,null,2)+'\n');}else if(process.argv[2]==='--describe-services')process.stdout.write(JSON.stringify(this.package())+'\n');else if(process.argv[2]==='--describe')process.stdout.write(JSON.stringify(this.metadata())+'\n');else {process.stderr.write('Unsupported identity program invocation.\n');process.exitCode=2;}}
}
IdentityBuild.run();
