module Paillier

open Org.BouncyCastle

let one = Math.BigInteger.One

type Publickey =
    { Len : int // length in bits
      N : Math.BigInteger
      G : Math.BigInteger
      Nsquared : Math.BigInteger }

type PrivateKey =
    { Length : int // length in bits
      Pubkey : Publickey
      L : Math.BigInteger
      U : Math.BigInteger }

let urandom = Security.SecureRandom()

let emtpyPubkey =
    { Len = 0
      N = one
      G = one
      Nsquared = one }

let emptyPrivateKey =
    { Length = 0
      Pubkey = emtpyPubkey
      L = one
      U = one }

let private isprime p = Math.Primes.IsMRProbablePrime(p, urandom, 100)
let private randomPrime bits = Math.BigInteger.ProbablePrime(bits, urandom)

// genkeypair
let genkeypair bits =
    let p = randomPrime (bits / 2)
    let q = randomPrime (bits / 2)
    if (isprime p && isprime q) then
        let n = p.Multiply q
        let nsquare = n.Multiply n
        let g = n.Add one
        let pMinus = p.Subtract one
        let qMinus = q.Subtract one
        let l = pMinus.Multiply qMinus
        let u = l.ModInverse n

        let pk =
            { Len = bits
              N = n
              Nsquared = nsquare
              G = g }

        let sk =
            { Length = bits
              Pubkey = pk
              L = l
              U = u }

        Some(pk, sk)
    else None

let encrypt pubkey (message : Math.BigInteger) =
    let r = randomPrime pubkey.Len
    let m = message
    if pubkey.N.CompareTo(m) < 1 then None
    else
        let gm = pubkey.G.ModPow(m, pubkey.Nsquared)
        let rn = r.ModPow(pubkey.N, pubkey.Nsquared)
        let prod = (gm.Multiply rn).Mod pubkey.Nsquared
        Some(prod)

let decrypt privatekey (cipher : Math.BigInteger) =
    let c = cipher
    if privatekey.Pubkey.Nsquared.CompareTo c < 1 then None
    else
        let a = c.ModPow(privatekey.L, privatekey.Pubkey.Nsquared).Subtract one
        let l = a.Divide privatekey.Pubkey.N
        let m = (l.Multiply privatekey.U).Mod privatekey.Pubkey.N
        Some(m)

let add pubkey (cipher1 : Math.BigInteger, cipher2 : Math.BigInteger) =
    (cipher1.Multiply cipher2).Mod pubkey.Nsquared
let addConstant pubkey (cipher : Math.BigInteger, constant : Math.BigInteger) =
    (cipher.Multiply(pubkey.G.ModPow(constant, pubkey.Nsquared)))
        .Mod pubkey.Nsquared
let mul pubkey (cipher : Math.BigInteger, constant : Math.BigInteger) =
    cipher.ModPow(constant, pubkey.Nsquared)
