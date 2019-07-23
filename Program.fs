// Learn more about F# at http://fsharp.org
open System
open Paillier
open Org.BouncyCastle

[<EntryPoint>]
let main argv =
    printfn "Hello World from F#!"
    let pub, priv =
        match genkeypair 1024 with
        | None -> emtpyPubkey, emptyPrivateKey
        | Some(a, b) -> a, b

    let m = Math.BigInteger.ValueOf 9132L

    let encM =
        match encrypt pub (m.ToByteArray()) with
        | None -> [| 0uy |]
        | Some(b) -> b
    printfn "%A" (bigint encM)
    let decM =
        match decrypt priv encM with
        | None -> [| 0uy |]
        | Some(b) -> b
    printfn "%A" (Math.BigInteger decM)
    0 // return an integer exit code
