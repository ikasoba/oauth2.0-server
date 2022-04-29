export interface TokenResponse {
  access_token:string,
  token_type:string,
  expires_in:number,
  refresh_token:string,
  scope:string,
}

export default interface AuthDB {
  /**
   * `url` | `null`
   */
  authorizePage:string|null

  authenticateClient(client_id:string,client_secret:string): boolean | Promise<boolean>
  /**
   * ﾄｸｰﾝをｳﾌﾟﾀﾞﾃします
   * リフレッシュトークンがこのクライアントのために正しく発行されたかバリデーションできますがどっちでも良いと仕様(RFC6749)にはあります。(たぶん)
   */
  updateToken(refresh_token:string,client_id:string,scope:string[]): TokenResponse | Promise<TokenResponse>
  /**
   * ユーザー名とパスワードでユーザーを認証
   */
  authenticateUser(user:string,password:string): boolean | Promise<boolean>
  /**
   * oauth2.0のトークンリクエスト
   */
  authRequest(request_type:string,client_id:string,redirect_uri:string,scope:string[],username:string,password:string): void | Promise<void>
}