import { Router,urlencoded } from "express"
import createBasicAuthFunc from "../basicAuth"
import cors from "cors"
import AuthDB from "./authDB"
import { SplitBasicAuth } from "../util"

export default (authDB:AuthDB)=>{
  const r = Router()

  r.get("/authorize",(req,res)=>{
    if (authDB.authorizePage){
      const pageURL = new URL(authDB.authorizePage)
      Array.from(new URL(req.url).searchParams).forEach(([k,v])=>
        pageURL.searchParams.append(k,v)
      )
      res.redirect(pageURL.toString());
      return res.end();
    }
    return res.type("html").end(
`<!doctype html>
<form method="POST">
    <input name="username" type="text" placeholder="username" />
    <input name="password" type="password" placeholder="password" />
    <button>submit</button>
</form>`
    )
  })

  r.post("/authorize",async(req,res)=>{
    type query = {
      request_type:string
      client_id:string
      redirect_uri:string
      scope:string
    }
    type body = {
      username:string
      password:string
    }

    if ( typeof req.query.request_type !== "string"
      || typeof req.query.client_id !== "string"
      || typeof req.query.redirect_uri !== "string"
      || typeof req.query.scope !== "string"
    ){
      return res.status(400).end();
    }
    await authDB.authRequest(
      req.query.request_type,
      req.query.client_id,
      req.query.redirect_uri,
      req.query.scope.split(" "),
      req.body.username,
      req.body.password
    )
  })

  r.post("/token",cors,urlencoded(),async(req,res)=>{
    res.header("WWW-Authenticate","Basic")
    res.header("Cache-Control","no-store")
    res.header("Pragma","no-cache")
    const authHeader:string[] = req.headers["authorization"]?.split(" ") || []
    const [client_id,client_secret] = SplitBasicAuth(authHeader[1])
    if ( authHeader[0]!="Basic"
      || client_id==null
      || client_secret==null
      || await authDB.authenticateClient(client_id,client_secret)
    ){
      return res.status(401).send();
    }
    if ( req.body.grant_type!="refresh_token"
      || req.body.refresh_token==null
      || req.body.scope==null
    ){
      return res.status(400).send();
    }
    const scope = req.body.scope.split(" ")
    return res.status(200).json(authDB.updateToken(req.body.refresh_token,client_id,scope));
  })

  return r
}