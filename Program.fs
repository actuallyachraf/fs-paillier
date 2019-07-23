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
        match encrypt pub (m1) with
        | None -> Math.BigInteger.Zero
        | Some(b) -> b
    printfn "%A" a
    let b =
        match encrypt pub (m2) with
        | None -> Math.BigInteger.Zero
        | Some(b) -> b
    printfn "%A" ( b)
    let sum = add pub (a, b)
    printfn "%A" (sum)
    let sumC = addConstant pub (a, one)

    let decSum =
        match decrypt priv sum with
        | None -> Math.BigInteger.Zero
        | Some(b) -> b
    printfn "%A" (decSum)
    let decSumC =
        match decrypt priv sumC with
        | None -> Math.BigInteger.Zero
        | Some(b) -> b
    printfn "%A + %A = %A" (m1) one decSumC
    printfn "decrypted equal to their sum : %A"
        (decSum = m1.Add m2)

    let mulC = mul pub (a,Math.BigInteger.Two)
    let decMulC =
        match decrypt priv mulC with
        | None -> Math.BigInteger.Zero
        | Some(b) -> b
    printfn "%A + %A = %A" (m1) Math.BigInteger.Two decMulC

    0 // return an integer exit code
