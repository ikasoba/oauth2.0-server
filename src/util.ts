// TODO: 型をもうちょいつけたい
const arrayPadding = (pad:any,padLen:number,a:any[]) => Array.from({length:padLen<a.length ? padLen : a.length},(_,i)=>a[i]||pad)

export function splitBasicAuth(credential:string): [string|undefined,string|undefined] {
  return arrayPadding(
    undefined,
    2,
    Buffer.from(credential,"base64").toString("ascii").split(":",2)
  ) as [string|undefined,string|undefined]
}

export const nullableEqual = (x:unknown|undefined,y:unknown,isNullReturnValue = false): boolean|typeof isNullReturnValue  => x!=undefined ? x == y : isNullReturnValue
export const strictNullableEqual = (x:unknown|undefined,y:unknown,isNullReturnValue = false): boolean|typeof isNullReturnValue  => x!=undefined ? x === y : isNullReturnValue