type Nullable<T> = T|null|undefined

export type Throws<T,E extends any[] = null> = T;

export const ErrorType = {
  INVALID_REQUEST:          "invalid_request",
  UNAUTHORIZED_CLIENT:      "unauthorized_client",
  ACCESS_DENIED:            "access_denied",
  UNSUPPORTED_RESPONSE_TYPE:"unsupported_response_type",
  INVALID_SCOPE:            "invalid_scope",
  SERVER_ERROR:             "server_error",
  TEMPORARILY_UNAVAILABLE:  "temporarily_unavailable"
} as const
export type ErrorType = typeof ErrorType[keyof typeof ErrorType]

export class AuthorizationError extends URL {
  public type: ErrorType
  public description?:string
  public error_url?:string
  
  constructor(errorType: ErrorType,error_url?:string,description?:string){
    super()
    this.type = errorType
    this.error_url = error_url
    this.description = description
  }
}

export interface TokenResponse {
  access_token:string,
  token_type:string,
  expires_in:number,
  refresh_token:string,
  scope:string
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
   * @returns リダイレクト先
   * @throws {AuthorizationError}
   */
  authRequest(request_type:string,client_id:string,redirect_uri:string,scope:string[],state:Nullable<string>,username:string,password:string): Throws<URL | Promise<URL>, AuthorizationError>
}