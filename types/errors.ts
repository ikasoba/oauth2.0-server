export const AuthorizationErrorTypes = {
  INVALID_REQUEST:          "invalid_request",
  UNAUTHORIZED_CLIENT:      "unauthorized_client",
  ACCESS_DENIED:            "access_denied",
  UNSUPPORTED_RESPONSE_TYPE:"unsupported_response_type",
  INVALID_SCOPE:            "invalid_scope",
  SERVER_ERROR:             "server_error",
  TEMPORARILY_UNAVAILABLE:  "temporarily_unavailable"
} as const
export type AuthorizationErrorTypes = typeof AuthorizationErrorTypes[keyof typeof AuthorizationErrorTypes]

export class AuthorizationError extends URL {
  public type: AuthorizationErrorTypes
  public description?:string
  public error_uri?:string
  public state?:string
  
  constructor(redirect_uri:string,errorType: AuthorizationErrorTypes,error_uri?:string,description?:string,state?:string){
    super(redirect_uri)
    
    this.searchParams.set("error",errorType)
    if (error_uri)    this.searchParams.set("error_url",error_uri);
    if (description)  this.searchParams.set("error_description",description);
    if (state)        this.searchParams.set("state",state);

    this.type = errorType
    this.error_uri = error_uri
    this.description = description
    this.state = state
  }
}



export const TokenRequestErrorTypes = {
  INVALID_REQUEST:        "invalid_request",
  INVALID_CLIENT:         "invalid_client",
  INVALID_GRANT:          "invalid_grant",
  UNAUTHORIZED_CLIENT:    "unauthorized_client",
  UNSUPPORTED_GRANT_TYPE: "unsupported_grant_type",
  INVALID_SCOPE:          "invalid_scope"
} as const

export type TokenRequestErrorTypes = typeof TokenRequestErrorTypes[keyof typeof TokenRequestErrorTypes]

export class TokenRequestError {
  constructor(public error:TokenRequestErrorTypes,public error_description?:string,public error_uri?:string){}
}