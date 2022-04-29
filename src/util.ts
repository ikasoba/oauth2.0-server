// TODO: 型をもうちょいつけたい
const arrayPadding = (pad:any,padLen:number,a:any[]) => Array.from({length:padLen<a.length ? padLen : a.length},(_,i)=>a[i]||pad)

export function SplitBasicAuth(credential:string): [string|undefined,string|undefined] {
  return arrayPadding(undefined,2,Buffer.from(credential,"base64").toString("utf-8").split(":",2)) as [string|undefined,string|undefined]
}