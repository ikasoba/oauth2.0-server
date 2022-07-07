import { Request, Router,urlencoded } from "express"
import _cors from "cors"
import _AuthDB, { AuthorizationError, ClientTypes, TokenRequestErrorTypes } from "./authDB.js"
import { nullableEqual, splitBasicAuth } from "../util.js"

export * from "./authDB.js"
export type AuthDB = _AuthDB


const cors = ()=>(_cors as Function)()

const htmlEscape = (s:string) => s.replace(/[<>/="'`&]/g,([c])=>"&#x"+c.charCodeAt(0).toString(16)+";");
interface HTMLObj {
  tag:string,
  attrs: Record<string,string>|null,
  children: (HTMLObj|string)[]|null,
  toString(): string
}
const h = (tag:string,attrs?:Record<string,string>|null,children?:(HTMLObj|string)[]|null): HTMLObj => ({
  tag: tag,
  attrs: attrs || null,
  children: children || null,
  toString(){
    return `<${this.tag}${this.attrs ? " "+Object.entries(this.attrs).map(([k,v])=>`${k}="${htmlEscape(v)}"`).join(" ") : ""}${!this.children ? "/" : ""}>${this.children ? this.children.map(x=>typeof x === "string" ? htmlEscape(x) : x.toString()).join("") + `</${this.tag}>` : ""}`
  }
})

const typeFilter = <T = unknown>(d:unknown,t:string|((d:unknown)=>boolean)): T|undefined => typeof t === "string"
  ? typeof d === t
    ? d as T
    : undefined
  : t(d)
    ? d as T
    : undefined
  ;

const requestTypeIs = <B, Q extends qs.ParsedQs>(x:string,req:Request,f?:(req:Request) => boolean): req is Request<{},any,B,Q> => f ? f(req) : (
      req.query.request_type === x
  &&  typeof req.query.client_id === "string"
  &&  (req.query.redirect_uri==undefined || typeof req.query.redirect_uri === "string")
  &&  (req.query.scope==undefined || typeof req.query.scope === "string")
  &&  (req.query.state==undefined || typeof req.query.state === "string")
  &&  typeof req.body.username === "string"
  &&  typeof req.body.password === "string"
)


export default (authDB:AuthDB)=>{
  const r = Router()

  r.get("/authorize",(req,res)=>{
    if (authDB.authorizePage){
      let isLocalPath = false
      const pageURL = authDB.authorizePage[0]=="/" ? (isLocalPath=true,new URL(authDB.authorizePage,"https://dummy.example.com")) : new URL(authDB.authorizePage)
      new URL(req.url,`${req.protocol}://${authDB.host||req.headers.host}`).searchParams.forEach((v,k)=>
        pageURL.searchParams.set(k,v)
      )
      res.redirect(isLocalPath ? `${pageURL.pathname}${pageURL.search}${pageURL.hash}` : pageURL.toString());
      return res.end();
    }
    const url = new URL(req.url,`${req.protocol}://${authDB.host||req.headers.host}`).toString()
    return res.type("html").end("<!doctype html>" +
      h("html",null,[
        h("body",null,[
          h("form",{method: "POST",action: url, style: "display: flex; flex-direction: column;"},[
            h("input",{name: "username", type: "text", placeholder: "username"}),
            h("input",{name: "password", type: "text", placeholder: "password"}),
            h("button",null,["submit"])
          ])
        ])
      ])
    )
  })

  // TODO: もうすこし /token と同様になるように整える
  r.post("/authorize",urlencoded(),async(req,res)=>{
    type query = {
      request_type:string
      client_id:string
      redirect_uri:string
      scope?:string
      state?:string
    }
    type body = {
      username:string
      password:string
    }

    const responseTypeIs = (x:string,req:Request):req is Request<{},any,body,query> => requestTypeIs<body,query>(x,req,req => (
      req.query.response_type === x
      &&  typeof req.query.client_id === "string"
      &&  (req.query.redirect_uri==undefined || typeof req.query.redirect_uri === "string")
      &&  (req.query.scope==undefined || typeof req.query.scope === "string")
      &&  (req.query.state==undefined || typeof req.query.state === "string")
      &&  typeof req.body.username === "string"
      &&  typeof req.body.password === "string"
    ))

    // redirect_uriは明示的に指定してもらう。(仕様に準拠していない)

    if (responseTypeIs("code",req)){
      if (!await authDB.isValidClientId(req.query.client_id)){
        return res.redirect(new AuthorizationError(req.query.redirect_uri,"invalid_request").toString())
      }
      if (req.query.redirect_uri && !await authDB.isRedirectIdFromClient(req.query.client_id,req.query.redirect_uri)){
        return res.redirect(new AuthorizationError(req.query.redirect_uri,"invalid_request").toString())
      }
      try {
        return res.redirect(await authDB.authorizeFromAuthorizationCode(
          req.query.request_type,req.query.client_id,req.query.redirect_uri,req.query.scope?.split(" ") || [],req.query.state,req.body.username,req.body.password
        ).toString())
      }catch(e:unknown){
        console.error(e)
        return res.redirect((e as AuthorizationError).toString())
      }
    }

    if (responseTypeIs("token",req)){
      if (!await authDB.isValidClientId(req.query.client_id)){
        return res.redirect(new AuthorizationError(req.query.redirect_uri,"invalid_request").toString())
      }
      if (!await authDB.isRedirectIdFromClient(req.query.client_id,req.query.redirect_uri)){
        return res.redirect(new AuthorizationError(req.query.redirect_uri,"invalid_request").toString())
      }
      try {
        return res.redirect(await authDB.authorizeFromImplicit(
          req.query.request_type,req.query.client_id,req.query.redirect_uri,req.query.scope?.split(" ") || [],req.query.state,req.body.username,req.body.password
        ).toString())
      }catch(e:unknown){
        console.error(e)
        return res.redirect((e as AuthorizationError).toString())
      }
    }

    if (typeof req.query.redirect_uri === "string")return res.redirect(new AuthorizationError(req.query.redirect_uri,"unsupported_response_type").toString())
    else return res.status(400).end()
  })

  /**
   * RFC6749 4.1.3
   */
  r.post("/token",cors(),urlencoded(),async(req,res)=>{
    type body = {
      grant_type: "authorization_code",
      code: string,
      redirect_uri?: string,
      client_id: string
    }
    type PasswordBody = {
      grant_type: "password"
      username: string
      password: string
      scope?: string
    }

    res.header("Cache-Control","no-store")
    res.header("Pragma","no-cache")
    const [client_id,client_secret] = req.headers["authorization"] ? splitBasicAuth(req.headers["authorization"].split(" ")[1] || "") : [typeFilter<string>(req.body.client_id,"string")]
    if (requestTypeIs<body, {}>("authorization_code",req,req =>
          req.body.grant_type === "authorization_code"
      &&  typeof req.body.code === "string"
      &&  typeof req.body.client_id === "string"
      &&  (req.body.redirect_uri==undefined || typeof req.body.redirect_uri === "string")
    )){
      if (client_id == null){
        return res.status(401).json({error:TokenRequestErrorTypes.INVALID_CLIENT})
      }
      if (await authDB.getClientIdFromAuthorizationCode(req.body.code) != client_id){
        return res.status(401).json({error:TokenRequestErrorTypes.INVALID_GRANT})
      }
      if (
            await authDB.getClientTypeFromId(client_id) == ClientTypes.CONFIDENTIAL && (client_secret==null || ! await authDB.authenticateClient(client_id,client_secret))
        ||  client_secret!=null && ! await authDB.authenticateClient(client_id,client_secret)
      ){
        res.header("WWW-Authenticate","Basic")
        return res.status(401).json({error:TokenRequestErrorTypes.INVALID_CLIENT})
      }
      if (!nullableEqual(await authDB.getRedirectUriFromAuthorizationCode(req.body.code),req.body.redirect_uri,true)){
        return res.status(401).json({error:TokenRequestErrorTypes.INVALID_REQUEST})
      }

      return res.json(
        authDB.requestTokenFromAuthorizationCode(
          req.body.grant_type,
          req.body.code,
          typeFilter<string>(req.body.redirect_uri, "string"),
          client_id
        )
      )
    }else if (requestTypeIs<PasswordBody, {}>("password",req,req =>
          req.body.grant_type === "password"
      &&  typeof req.body.username === "string"
      &&  typeof req.body.password === "string"
      &&  (req.body.scope==undefined || typeof req.body.scope === "string")
    )){
      if (client_id==null){
        return res.status(401).json({error:TokenRequestErrorTypes.INVALID_CLIENT})
      }
      if (
              await authDB.getClientTypeFromId(client_id) == ClientTypes.CONFIDENTIAL && (client_secret==null || ! await authDB.authenticateClient(client_id,client_secret))
          ||  client_secret!=null && ! await authDB.authenticateClient(client_id,client_secret)
      ){
        res.header("WWW-Authenticate","Basic")
        return res.status(401).json({error:TokenRequestErrorTypes.INVALID_CLIENT})
      }
      if (!await authDB.authenticateUser(req.body.username,req.body.password)){
        return res.status(401).json({error: TokenRequestErrorTypes.INVALID_GRANT})
      }
      try {
        return await authDB.requestTokenFromOwnerPasswordCredential(
          req.body.grant_type, req.body.username, req.body.password, req.body.scope?.split(" ") || []
        )
      }catch(e:unknown){
        console.error(e)
        return res.redirect((e as AuthorizationError).toString())
      }
    }else if (requestTypeIs<{grant_type: "client_credentials", scope?: string}, {}>("client_credentials",req,req =>
          req.body.grant_type === "client_Credentials"
      &&  (req.body.scope==undefined || typeof req.body.scope === "string")
    )){
      if (client_id==null){
        return res.status(401).json({error:TokenRequestErrorTypes.INVALID_CLIENT})
      }
      if (client_secret==null || ! await authDB.authenticateClient(client_id,client_secret)){
        res.header("WWW-Authenticate","Basic")
        return res.status(401).json({error:TokenRequestErrorTypes.INVALID_CLIENT})
      }
      return await authDB.requestTokenFromClientCredential(
        req.body.grant_type, client_id, req.body.scope?.split(" ") || []
      )
    }else if (requestTypeIs<{grant_type: "refresh_token", refresh_token: string, scope?: string}, {}>("refresh_token",req,req =>
          req.body.grant_type === "client_Credentials"
      &&  typeof req.body.refresh_token === "string"
      &&  (req.body.scope==undefined || typeof req.body.scope === "string")
    )){
      if (client_id==null){
        return res.status(401).json({error:TokenRequestErrorTypes.INVALID_CLIENT})
      }
      if (client_secret==null || ! await authDB.authenticateClient(client_id,client_secret)){
        res.header("WWW-Authenticate","Basic")
        return res.status(401).json({error:TokenRequestErrorTypes.INVALID_CLIENT})
      }
      return await authDB.updateToken(
        client_id, req.body.refresh_token, req.body.scope?.split(" ") || []
      )
    }

    return res.status(400).json({error: TokenRequestErrorTypes.UNSUPPORTED_GRANT_TYPE})
  })

  return r
}