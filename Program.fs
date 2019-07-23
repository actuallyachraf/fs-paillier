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

    let m1 = Math.BigInteger.ValueOf 77234725L
    let m2 = Math.BigInteger.ValueOf 32234L

    let a =
        match encrypt pub (m1.ToByteArray()) with
        | None -> [| 0uy |]
        | Some(b) -> b
    printfn "%A" (bigint a)
    let b =
        match encrypt pub (m2.ToByteArray()) with
        | None -> [| 0uy |]
        | Some(b) -> b
    printfn "%A" (Math.BigInteger b)
    let sum = add pub (a, b)
    printfn "%A" (Math.BigInteger sum)
    let sumC = addConstant pub (a, one.ToByteArray())

    let decSum =
        match decrypt priv sum with
        | None -> [| 0uy |]
        | Some(b) -> b
    printfn "%A" (Math.BigInteger decSum)
    let decSumC =
        match decrypt priv sumC with
        | None -> [| 0uy |]
        | Some(b) -> b
    printfn "%A + %A = %A" (m1) one (Math.BigInteger decSumC)
    printfn "decrypted equal to their sum : %A"
        (decSum = (m1.Add m2).ToByteArray())
    0 // return an integer exit code
