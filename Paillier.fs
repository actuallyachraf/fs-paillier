module Paillier

open Org.BouncyCastle


let one = Math.BigInteger.One

type Publickey =
    {
        Length : int // length in bits
        N : Math.BigInteger
        G : Math.BigInteger
        Nsquared : Math.BigInteger }

type PrivateKey =
    {
        Length : int // length in bits
        Pubkey : Publickey
        L : Math.BigInteger
        U : Math.BigInteger }



// isPrime
let private isprime p =
    let rand = Org.BouncyCastle.Security.SecureRandom ()
    Math.Primes.IsMRProbablePrime (p,rand,100)

let urandom = Security.SecureRandom ()

let private randomPrime bits = Math.BigInteger.ProbablePrime (bits/2 ,Security.SecureRandom ())
// genkeypair
let genkeypair bits =

    let p = Math.BigInteger.ProbablePrime (bits/2 ,urandom)
    let q = Math.BigInteger.ProbablePrime (bits/2 ,urandom)

    if (isprime p || isprime q)
        then

        let n = p.Multiply q
        let nsquare = n.Multiply n

        let g = n.Add one
        let pMinus = p.Subtract one
        let qMinus = q.Subtract one
        let l = pMinus.Multiply qMinus
        let u = l.ModInverse n

        let pk = {Length = bits;N=n;Nsquared=nsquare;G=g}
        let sk = {Length = bits;Pubkey=pk;L=l;U=u}
        Some(pk,sk)
        else
        None
