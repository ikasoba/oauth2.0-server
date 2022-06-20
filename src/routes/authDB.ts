import {TokenRequestError, AuthorizationError} from "../../types/errors.js"

export * from "../../types/errors.js"

type Nullable<T> = T|null|undefined

/**
 * @throws {AuthorizationError}
 */
// req.query.request_type,req.query.client_id,req.query.redirect_uri,req.query.scope?.split(" ") || [],req.query.state,req.body.username,req.body.password
export type AuthorizationFunction = (request_type:string, client_id:string, redirect_uri: string|undefined, scope: string[], state: Nullable<string>, username: string, password: string) => Awaitable<URL>

export interface TokenResponse {
  access_token:string,
  token_type:string,
  expires_in:number,
  refresh_token?:string
}

export enum ClientTypes {
  CONFIDENTIAL,
  PUBLIC
}

export type Awaitable<T> = T | PromiseLike<T>

export default interface AuthDB {
  /**
   * `url` | `null`
   */
  authorizePage?:string|null|undefined
  host?: string

  /**
   * クライアントパスワード方式での認証 (RFC6749 2.3.1)
   */
  authenticateClient(client_id:string,client_secret:string): Awaitable<boolean>
  /**
   * クライアントタイプをクライアントIDから取得します
   */
  getClientTypeFromId(client_id:string): Awaitable<ClientTypes|undefined>
  getClientIdFromAuthorizationCode(code:string): Awaitable<string|undefined>
  isAuthorizationCode(code:string): Awaitable<boolean>
  getRedirectUriFromAuthorizationCode(code:string): Awaitable<string|undefined>
  isValidClientId(client_id:string): Awaitable<boolean>
  isRedirectIdFromClient(client_id:string,redirect_uri:string): Awaitable<boolean>
  /**
   * トークンをアップデートします
   * リフレッシュトークンがこのクライアントのために正しく発行されたかバリデーションできますがどっちでも良いと仕様(RFC6749)にはあります。(たぶん)
   */
  updateToken(refresh_token:string,client_id:string,scope:string[]): Awaitable<TokenResponse|TokenRequestError>
  /**
   * ユーザー名とパスワードでユーザーを認証
   */
  authenticateUser(user:string,password:string): boolean | Awaitable<boolean>

  /**
   * トークンのリクエスト
   * RFC6749の4.1.3の実装
   */
  requestTokenFromAuthorizationCode(grant_type:string,code:string,redirect_uri:string|undefined,client_id:string): Awaitable<TokenResponse|TokenRequestError>
  authorizeFromAuthorizationCode: AuthorizationFunction
  authorizeFromImplicit: AuthorizationFunction
  requestTokenFromOwnerPasswordCredential(grant_type: "password", username: string, password: string, scope: string[]): Awaitable<TokenResponse|TokenRequestError>
  requestTokenFromClientCredential(grant_type: "client_credentials", client_id: string, scope: string[]): Awaitable<TokenResponse|TokenRequestError>
}