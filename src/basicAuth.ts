export function split(content:string): [string,string] | null {
  const [user,pass] = Buffer.from(content,"base64").toString("utf-8").split(":");
  if (user==null || pass==null)return null;
  return [user,pass]
}

export default function createBasicAuthFunc<T=any>(func:(u:string,p:string)=>T): ((h:string)=>T | null) {
  return (h)=>{
    const tmp = h.split(" ");
    if (tmp[0]!="Basic")return null;
    if (tmp[1]==null)return null;
    const res = split(tmp[1]);
    if (res==null)return null;
    return func(...res);
  }
}