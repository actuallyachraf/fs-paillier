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

let encrypt pubkey (message : byte []) =
    let r = randomPrime pubkey.Len
    let m = Math.BigInteger message
    if pubkey.N.CompareTo(m) < 1 then None
    else
        let gm = pubkey.G.ModPow(m, pubkey.Nsquared)
        let rn = r.ModPow(pubkey.N, pubkey.Nsquared)
        let prod = gm.Multiply rn
        let c = prod.Mod pubkey.Nsquared
        Some(c.ToByteArray())

let decrypt privatekey (cipher : byte []) =
    let c = Math.BigInteger cipher
    if privatekey.Pubkey.Nsquared.CompareTo c < 1 then None
    else
        let a = c.ModPow(privatekey.L, privatekey.Pubkey.Nsquared)
        let l = a.Subtract one
        let l = l.Divide privatekey.Pubkey.N
        let m = l.Multiply privatekey.U
        let m = m.Mod privatekey.Pubkey.N
        Some(m.ToByteArray())

let add pubkey (msg1 : byte [], msg2 : byte []) =
    let m1 = Math.BigInteger msg1
    let m2 = Math.BigInteger msg2
    let res = (m1.Multiply m2).Mod pubkey.Nsquared
    res.ToByteArray()

let addConstant pubkey (cipher : byte [], constant : byte []) =
    let cipher = Math.BigInteger cipher
    let constant = Math.BigInteger constant
    let res =
        (cipher.Multiply(pubkey.G.ModPow(constant, pubkey.Nsquared)))
            .Mod pubkey.Nsquared
    res.ToByteArray()
