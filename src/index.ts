import express from "express"
import AuthDB, { AuthorizationError, ClientTypes, TokenRequestError, TokenResponse } from "./routes/authDB.js";
import route from "./routes/index.js"
import crypto from "crypto"

const app = express();
app.use(express.json());
app.disable("X-Powered-By");

interface Client {
  id: string
  secret: string
  type: ClientTypes
  redirectUris: Set<string>
}

interface User {
  username: string
  password: string
  posts: Post[]
}

interface Post {
  date: Date
  content: string
}

interface authorizationCode {
  clientId: string
  createdAt: number
  code: string
  expiresIn: number
  token: Token
  redirect_uri?: string
}

interface Token {
  refreshToken?: string
  token: string
  scope: string[]
  defaultScope: string[]
  clientID: string
  expiresIn: number
  createdAt: number
}

const genRandomID = () => [...crypto.randomBytes(8)].map(x => x.toString(16).padStart(2,"0")).join("")
const genRandomToken = () => genRandomID()+"."+genRandomID()

const db = {
  clients: [{
    id: "dbg_0",
    redirectUris: new Set(["http://localhost:8080/redirect"]),
    secret: "dbg_0_secret",
    type: ClientTypes.CONFIDENTIAL
  }] as Client[],
  users: [{
    password: "1234",
    username: "hoge",
    posts: []
  }] as Array<User>,
  authorizationCode: new Set<authorizationCode>(),
  tokens: new Map<string,Token>()
}

console.log(db.users)

const a:AuthDB = {
  authenticateClient(clientId,clientSecret): boolean {
    return db.clients.some(x => x.id === clientId && x.secret === clientSecret)
  },
  authenticateUser(username,password): boolean {
    return db.users.some(x => x.username === username && x.password === password)
  },
  authorizeFromAuthorizationCode(request_type,client_id,redirect_uri,scope,state,username,password): URL {
    const user = db.users.find(x => x.username == username && x.password == password)
    if (!user){
      return new AuthorizationError(redirect_uri || "/error","invalid_request",undefined,undefined,state||undefined)
    }
    const createdAt = Date.now()
    const authcode:authorizationCode = {
      clientId: client_id,
      createdAt: createdAt,
      code: genRandomID(),
      expiresIn: 60*10,
      redirect_uri: redirect_uri,
      token: {
        refreshToken: genRandomID(),
        token: genRandomToken(),
        clientID: client_id,
        scope: scope,
        defaultScope: scope,
        expiresIn: 60*30,
        createdAt: createdAt
      }, // 見分けがつかないのでちょっと手を加えた
    }
    db.authorizationCode.add(authcode)
    db.tokens.set(authcode.token.token,authcode.token)
    const params = new URLSearchParams({
      code: authcode.code,
      ...(state ? {state} : {})
    })
    return new URL(redirect_uri+"?"+params.toString())
  },
  authorizeFromImplicit(request_type,client_id,redirect_uri,scope,state,username,password): URL {
    const user = db.users.find(x => x.username == username && x.password == password)
    if (!user){
      return new AuthorizationError(redirect_uri || "/error","invalid_request",undefined,undefined,state||undefined)
    }
    const token:Token = {
      token: genRandomToken(),
      refreshToken: genRandomID(),
      clientID: client_id,
      scope: scope,
      defaultScope: scope,
      expiresIn: 60*30,
      createdAt: Date.now()
    }
    db.tokens.set(token.token,token)
    const params = new URLSearchParams({
      access_token: token.token,
      token_type: "bearer",
      expires_in: token.expiresIn.toString(10),
      ...(scope ? {scope: token.scope.join(" ")} : {}),
      ...(state ? {state} : {})
    })
    return new URL(redirect_uri+"?"+params.toString())
  },
  getClientIdFromAuthorizationCode(code) {
    return [...db.authorizationCode].find(x => x.code == code)?.clientId
  },
  getClientTypeFromId(client_id) {
    return db.clients.find(x => x.id == client_id)?.type
  },
  getRedirectUriFromAuthorizationCode(code) {
    return [...db.authorizationCode].find(x => x.code == code)?.redirect_uri
  },
  isAuthorizationCode(code) {
    return [...db.authorizationCode].some(x => x.code == code)
  },
  isRedirectIdFromClient(client_id, redirect_uri) {
    return db.clients.some(x => {
      return x.id == client_id && x.redirectUris.has(redirect_uri)
    })
  },
  isValidClientId(client_id) {
    return db.clients.some(x => x.id == client_id)
  },
  requestTokenFromAuthorizationCode(grant_type, code, redirect_uri, client_id) {
    const authcode = [...db.authorizationCode].find(x => x.code == code)
    if (!authcode || authcode.redirect_uri != redirect_uri){
      return new TokenRequestError("invalid_request")
    }
    try {
      return {
        access_token: authcode.token.token,
        expires_in: authcode.token.expiresIn,
        token_type: "Bearer",
        refresh_token: authcode.token.refreshToken
      } as TokenResponse
    }finally{
      db.authorizationCode.delete(authcode)
    }
  },
  requestTokenFromClientCredential(grant_type, client_id, scope) {
    return new TokenRequestError("unsupported_grant_type")
  },
  requestTokenFromOwnerPasswordCredential(grant_type, username, password, scope) {
    return new TokenRequestError("unsupported_grant_type")
  },
  updateToken(refresh_token, client_id, scope) {
    let token = [...db.tokens.values()].find(x => x.refreshToken == refresh_token && x.clientID == client_id)
    if (!token){
      return new TokenRequestError("invalid_grant")
    }
    const newToken:Token = {
      expiresIn: 60*30,
      createdAt: Date.now(),
      clientID: client_id,
      defaultScope: token.defaultScope,
      scope: scope,
      token: genRandomToken(),
      refreshToken: genRandomID()
    }
    db.tokens.set(newToken.token,newToken)
    db.tokens.delete(token.token)
    return {
      access_token: newToken.token,
      expires_in: newToken.expiresIn,
      token_type: "Bearer",
      refresh_token: newToken.refreshToken
    } as TokenResponse
  },
  authorizePage: null,
  host: "localhost:8080"
}

app.use(route(a))

app.listen(8080);