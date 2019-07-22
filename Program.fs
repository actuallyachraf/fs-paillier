// Learn more about F# at http://fsharp.org

open System
open Paillier

[<EntryPoint>]
let main argv =
    printfn "Hello World from F#!"

    match genkeypair 1024 with
    | None -> printfn "failed to generate primes"
    | Some(a,b) -> (printfn "Public Key : %A \n PrivateKey : %A "  a b)
    0 // return an integer exit code