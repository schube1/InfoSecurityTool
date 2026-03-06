import { useState } from "react";

const concepts = [
  {
    id: 1,
    title: "Kerckhoff's Principle & CIA Triad",
    tag: "Foundations",
    summary: "Security relies on key secrecy, not algorithm secrecy. CIA = Confidentiality, Integrity, Availability.",
    content: [
      {
        heading: "Kerckhoff's Principle",
        body: "A cryptosystem should be secure even if everything about the system — except the key — is public knowledge. Assume the attacker knows the algorithm. Only the key must remain secret."
      },
      {
        heading: "Confidentiality",
        body: "Preventing unauthorized reading of information. Only intended parties can view the data. Example: encrypted messages in transit."
      },
      {
        heading: "Integrity",
        body: "Detecting (and if possible preventing) unauthorized modification of information. If data is changed, the recipient should know. Example: MACs, digital signatures, hashes."
      },
      {
        heading: "Availability",
        body: "Ensuring access to data when it's needed. DoS attacks threaten availability. Example: an ER system needs availability most critically — doctors need patient data NOW."
      },
      {
        heading: "Exam Tip",
        body: "Q1 on the midterm asks you to define all three. For Kerckhoff's: emphasize 'security through obscurity is bad.' A password manager needs both C and I; a social network may prioritize I over C; an ER system needs A most critically."
      }
    ]
  },
  {
    id: 2,
    title: "CBC Mode & Block Cipher Modes",
    tag: "Symmetric Crypto",
    summary: "CBC chains blocks using XOR with the previous ciphertext. The IV plays the role of the 'additive' in a codebook cipher.",
    content: [
      {
        heading: "Codebook Cipher Additive",
        body: "In a classic codebook cipher, an 'additive' is a sequence of numbers added to each codeword before transmission. Its purpose: prevent identical plaintexts from producing identical ciphertexts, hiding patterns from attackers."
      },
      {
        heading: "CBC Encryption Formula",
        body: "C₀ = E(P₀ ⊕ IV, K)\nCᵢ = E(Pᵢ ⊕ Cᵢ₋₁, K)\n\nThe IV plays the role of the additive — it randomizes the first block so identical plaintext blocks produce different ciphertexts. Always use a random IV!"
      },
      {
        heading: "CBC Decryption Formula",
        body: "P₀ = D(C₀, K) ⊕ IV\nPᵢ = D(Cᵢ, K) ⊕ Cᵢ₋₁\n\nRandom access: to decrypt block i you only need Cᵢ and Cᵢ₋₁. Decryption can be parallelized; encryption cannot."
      },
      {
        heading: "Fixed IV Problem",
        body: "If IV is fixed and two messages share the same first plaintext block, C₀ will be identical — leaking information. Also opens up chosen-plaintext attacks."
      },
      {
        heading: "CTR Mode vs CBC",
        body: "CTR: Pᵢ = Cᵢ ⊕ E(IV+i, K)\nAllows full parallel encryption AND decryption, and true random access (no dependency on previous block). CBC cannot parallelize encryption."
      },
      {
        heading: "ECB Weaknesses (vs CBC)",
        body: "ECB: Cᵢ = E(Pᵢ, K) — no chaining. Same plaintext → same ciphertext always. Patterns are visible. Two weaknesses vs CBC: (1) identical plaintext blocks = identical ciphertexts, (2) blocks can be rearranged/substituted by an attacker without detection."
      }
    ]
  },
  {
    id: 3,
    title: "MAC (Message Authentication Code)",
    tag: "Integrity",
    summary: "MAC = final CBC ciphertext block. Proves integrity. Trudy can't forge it without the symmetric key K.",
    content: [
      {
        heading: "MAC Formula",
        body: "Using CBC mode:\nC₀ = E(IV ⊕ P₀, K)\nC₁ = E(C₀ ⊕ P₁, K)  ...  MAC = Cₙ\n\nAlice sends: (IV, P₀, P₁, ..., Pₙ, MAC)"
      },
      {
        heading: "Why Bob Detects Tampering (Midterm Q3b)",
        body: "If Trudy changes P₁ to X:\nBob recomputes C₁' = E(C₀ ⊕ X, K) ≠ C₁\nThis cascades — C₂', C₃', ... all differ.\nFinal MAC' ≠ original MAC → Bob detects the tampering."
      },
      {
        heading: "Why Trudy Can't Forge a MAC (Q3c)",
        body: "To produce a valid MAC, Trudy must encrypt using key K. Without K she cannot compute a MAC that Bob will accept. The symmetric key K is the secret that protects the MAC."
      },
      {
        heading: "HMAC",
        body: "HMAC(M, K) = h(K ⊕ opad || h(K ⊕ ipad || M))\nUses a hash function instead of a block cipher. More efficient and avoids length-extension attacks. Still requires shared key K → still no non-repudiation."
      },
      {
        heading: "MAC vs Digital Signature",
        body: "MAC: both Alice and Bob share K → either could have computed it → no non-repudiation.\nDigital signature: only Alice has her private key → she cannot deny signing → non-repudiation ✓"
      }
    ]
  },
  {
    id: 4,
    title: "RSA Cryptosystem",
    tag: "Public Key",
    summary: "N=p×q, φ(N)=(p-1)(q-1), choose e coprime to φ(N), find d=e⁻¹ mod φ(N). Encrypt: Mᵉ mod N.",
    content: [
      {
        heading: "Key Generation Steps",
        body: "1. Choose large primes p and q\n2. N = p × q\n3. φ(N) = (p−1)(q−1)\n4. Choose e such that gcd(e, φ(N)) = 1\n5. Find d = e⁻¹ mod φ(N)\n6. Public key: (N, e)   Private key: d"
      },
      {
        heading: "Midterm Q4 Example: p=7, q=13, e=5",
        body: "N = 7 × 13 = 91\nφ(N) = 6 × 12 = 72\nPublic key: (91, 5)\n\nEncrypt M=3:  C = 3⁵ mod 91 = 243 mod 91 = 61\n\nFind d:  5d ≡ 1 (mod 72)\n5 × 29 = 145 = 2×72 + 1  →  d = 29"
      },
      {
        heading: "Encryption & Decryption",
        body: "Encrypt: C = Mᵉ mod N\nDecrypt: M = Cᵈ mod N\n\nDigital signatures:\nSign (Alice): S = Mᵈ mod N  (private key)\nVerify (Bob): Sᵉ mod N = M  (public key)"
      },
      {
        heading: "Cube Root Attack (e=3)",
        body: "If M < N^(1/3), then C = M³ with no mod reduction. Attacker just computes ∛C.\n\nExample: N=33, e=3\nM=3: 3 < 33^(1/3) ≈ 3.21 → attack works, C=27, ∛27=3 ✓\nM=4: 4 > 3.21 → attack fails, 4³ mod 33 = 31 ≠ 4\n\nFix: pad M so M ≥ N^(1/3)."
      },
      {
        heading: "Security & Key Sizes",
        body: "RSA security = hardness of factoring N.\n1024-bit modulus ≈ 90-bit symmetric key strength\n2048-bit modulus ≈ 121-bit symmetric key strength\nNeed ~16384-bit modulus to match 256-bit symmetric key\n\nShor's quantum algorithm can factor in polynomial time — RSA would be broken."
      }
    ]
  },
  {
    id: 5,
    title: "Digital Signatures & Certificates",
    tag: "Public Key",
    summary: "Sign with private key, verify with public key. Certificate = (name, public key) signed by a CA.",
    content: [
      {
        heading: "Digital Signature Process",
        body: "Alice signs: S = [h(M)]Alice = h(M)ᵈ mod N\n\nBob verifies:\n1. Compute h(M) from the received message\n2. Compute Sᵉ mod N using Alice's public key\n3. If they match → valid signature"
      },
      {
        heading: "What Signatures Provide",
        body: "✓ Integrity — any tampering with M changes h(M), making the signature check fail\n✓ Non-repudiation — only Alice has her private key, she can't deny signing\n✗ MAC does NOT provide non-repudiation (symmetric key, either party could have made it)"
      },
      {
        heading: "Digital Certificate Contents",
        body: "Required: (1) user's name, (2) user's public key\nSigned by a Certificate Authority (CA): S = [h(M)]CA\n\nKeep it minimal — any change invalidates the cert. If you add an employee's organization and they leave the company, the cert becomes invalid."
      },
      {
        heading: "Midterm Q7: What Does Bob Know?",
        body: "Before verifying: Bob knows NOTHING about who sent the cert.\n\nAfter verifying:\n(a) Bob computes {S}CA and checks it equals h(M)\n(b) Bob knows: the public key truly belongs to Alice (CA vouches)\n(c) Bob still knows NOTHING about who sent the certificate — certs are public, anyone could have forwarded it"
      },
      {
        heading: "Integrity vs Non-Repudiation Table (Q5)",
        body: "MAC:               Integrity=YES  Non-repudiation=NO\nHMAC:              Integrity=YES  Non-repudiation=NO\nCRC:               Integrity=NO   Non-repudiation=NO\nDigital Signature: Integrity=YES  Non-repudiation=YES\n\nCRC is NOT cryptographic — an attacker can recompute a valid CRC for any modified message."
      }
    ]
  },
  {
    id: 6,
    title: "Knapsack Cryptosystem",
    tag: "Public Key",
    summary: "Superincreasing knapsack × m mod n → public key. Decrypt with m⁻¹ mod n then greedy solve.",
    content: [
      {
        heading: "Key Generation (Step by Step)",
        body: "1. Start with a superincreasing sequence (private): each element > sum of all previous\n2. Choose n (larger than total sum) and m (coprime to n)\n3. Public key = multiply each element by m mod n\n4. Private key = the superincreasing sequence + m⁻¹ mod n"
      },
      {
        heading: "Encryption",
        body: "Encode message as binary bits. Multiply each bit by the corresponding public key value and sum.\n\nMidterm Q6b: public key = (82,123,287,83,248,373,10,471), n=491\nM = 10010010\nC = 1×82 + 0 + 0 + 1×83 + 0 + 0 + 1×10 + 0 = 175"
      },
      {
        heading: "Decryption",
        body: "1. Compute m⁻¹ mod n\n2. C' = m⁻¹ × C mod n\n3. Solve the superincreasing knapsack greedily for C': go largest to smallest, include element if it fits\n\nHW4 Example: (3,5,12,23), n=47, m=6\nm⁻¹=8 (since 6×8=48≡1 mod 47)\nEncrypt M=1110: C = 18+30+25 = 73\nDecrypt: 8×73 mod 47 = 20 → solve: 12+5+3=20 → 1110 ✓"
      }
    ]
  },
  {
    id: 7,
    title: "Cryptographic Hash Functions",
    tag: "Hashing",
    summary: "5 properties: compression, efficiency, one-way, weak collision resistance, strong collision resistance. Birthday attack = 2^(n/2).",
    content: [
      {
        heading: "The 5 Required Properties",
        body: "1. Compression: maps arbitrary-length input to fixed n-bit output\n2. Efficiency: fast to compute h(x)\n3. One-way (preimage resistance): given h(x), infeasible to find x\n4. Weak collision resistance: given x, infeasible to find x'≠x with h(x)=h(x')\n5. Strong collision resistance: infeasible to find ANY pair (x,x') with h(x)=h(x')"
      },
      {
        heading: "Birthday Attack & Work Factors",
        body: "For an n-bit hash:\n• Find 1 collision: ~2^(n/2) hashes\n• Find m collisions: ~√(2m) × 2^(n/2) hashes\n• Preimage attack: ~2^n hashes\n\nFor comparison: breaking a symmetric cipher needs ~2^(n-1) operations — about twice as much work."
      },
      {
        heading: "Truncating Hash Output",
        body: "Safe to use first 128 bits of a 256-bit hash? YES — collision work stays at 2^64.\n\nSafe to XOR the two 128-bit halves? NO — Trudy now has more ways to find collisions (two different halves can cancel each other out when XORed)."
      },
      {
        heading: "MD5 Collision Attack",
        body: "MD5 is broken: collisions can be found in seconds.\nAttack scenario: Trudy creates rec.ps (harmless letter) and auth.ps (bank authorization) with the same MD5 hash. Gets Alice to sign rec.ps → the signature is also valid for auth.ps. This is the birthday attack applied in practice."
      }
    ]
  },
  {
    id: 8,
    title: "Blockchain & Cryptocurrency",
    tag: "Applications",
    summary: "Blocks chain via previous hash. Digital signatures prevent fraud. Miners do proof-of-work. Double-spend probability = p^N.",
    content: [
      {
        heading: "Why Digital Signatures Are Necessary",
        body: "Without signatures, Trudy could create a fake transaction 'Alice pays Trudy $1000.' Signatures prove Alice authorized the transaction — only her private key can produce her signature."
      },
      {
        heading: "Why Transaction Numbers Are Needed",
        body: "Without transaction numbers, Trudy could copy a valid signed transaction and replay it multiple times (replay attack), draining Alice's account. Each transaction number is unique, so duplicates are rejected."
      },
      {
        heading: "Why Are Miners Called Miners?",
        body: "Miners find a nonce Rᵢ such that h(Yᵢ, Bᵢ, Rᵢ) < 2^m — a hard computational puzzle. This work generates new cryptocurrency as a reward, analogous to gold miners doing physical work to extract value from the ground."
      },
      {
        heading: "Block Chaining (why Yᵢ is included)",
        body: "Yᵢ = hash of the previous block. Modifying any block invalidates ALL subsequent blocks — attacker must redo all proof-of-work for every block after the tampered one. Makes fraud computationally infeasible."
      },
      {
        heading: "Double Spending Attack",
        body: "1. Trudy pays Alice (valid transaction T)\n2. Trudy secretly mines a private branch NOT including T\n3. If her private chain grows longer than the public chain, it gets adopted → T erased\n\nProbability of success: p^N\n(p = Trudy's fraction of compute, N = blocks Alice requires)\n\nAt 10% compute, requiring 6 blocks: (0.1)⁶ ≈ 0.000001 — negligible"
      },
      {
        heading: "Pseudonymous vs Anonymous",
        body: "Cash = anonymous: no link between spender and bills.\nCrypto = pseudonymous: all transactions are public on the blockchain, linked to addresses. True identity is unknown but the full transaction history is visible."
      }
    ]
  },
  {
    id: 9,
    title: "Steganography",
    tag: "Information Hiding",
    summary: "Hide data in LSBs of image pixels. Visually undetectable but fragile — zeroing LSBs destroys hidden data.",
    content: [
      {
        heading: "How LSB Steganography Works",
        body: "Uncompressed images store each pixel as RGB values (0–255). The least significant bit(s) of each color channel are replaced with bits of the secret message. A 1-bit change in color is imperceptible to the human eye."
      },
      {
        heading: "Why It's NOT Robust (Midterm Q10b)",
        body: "Trudy can destroy all hidden data without visibly affecting the image by zeroing out the LSB of every pixel's color channels. Each channel changes by at most 1 value (e.g., 201→200) — imperceptible to the eye — but the hidden message is completely destroyed."
      },
      {
        heading: "Detection",
        body: "Statistical attacks: natural images have a characteristic distribution of LSBs. Steganographic images often show unnaturally uniform LSB patterns. Chi-square tests can detect LSB steganography even without recovering the message."
      }
    ]
  },
  {
    id: 10,
    title: "Stream Ciphers & Known-Plaintext Attack",
    tag: "Symmetric Crypto",
    summary: "C = P ⊕ Keystream. If Trudy knows P and C, she recovers the keystream and can substitute any message.",
    content: [
      {
        heading: "Stream Cipher Basics",
        body: "C = P ⊕ Keystream\nP = C ⊕ Keystream\n\nKeystream is generated from key K using a PRNG. Security depends entirely on keystream unpredictability and key secrecy."
      },
      {
        heading: "Known-Plaintext Attack (HW3 Q2)",
        body: "If Trudy knows both P and C:\nKeystream = C ⊕ P  (since C = P ⊕ K, then C ⊕ P = K)\n\nNow she can encrypt any message Q:\nC' = Q ⊕ Keystream\n\nBob decrypts C' and gets Q — believing it came from Alice."
      },
      {
        heading: "A5/1 (GSM Voice Encryption)",
        body: "Three LFSRs clocked by majority rule.\n• Each register steps: 3/4 of the time\n• All three step together: 1/4 of the time\n• Exactly two step: 3/4 of the time\n• Exactly one steps: NEVER\n• None step: NEVER"
      },
      {
        heading: "RC4 Overview",
        body: "RC4 is a software-optimized stream cipher that produces one keystream BYTE per step (vs A5/1 which produces one bit). It's essentially a self-modifying 256-byte lookup table S that always contains a permutation of {0, 1, ..., 255}.\n\nKey can be 1–256 bytes. The 256-byte array K is filled by repeating the key until full."
      },
      {
        heading: "RC4 Initialization (Table 3.1)",
        body: "// Phase 1: fill S and K\nfor i = 0 to 255:\n    S[i] = i\n    K[i] = key[i mod N]\n\n// Phase 2: scramble S using the key\nj = 0\nfor i = 0 to 255:\n    j = (j + S[i] + K[i]) mod 256\n    swap(S[i], S[j])\n\ni = j = 0  // reset for keystream generation"
      },
      {
        heading: "RC4 Keystream Generation (Table 3.2)",
        body: "// Run this once per byte of output needed:\ni = (i + 1) mod 256\nj = (j + S[i]) mod 256\nswap(S[i], S[j])\nt = (S[i] + S[j]) mod 256\nkeystreamByte = S[t]\n\nEncrypt: cipherByte = plaintextByte XOR keystreamByte\nDecrypt: plaintextByte = cipherByte XOR keystreamByte"
      },
      {
        heading: "RC4 Weakness & Fix",
        body: "RC4 has a known practical attack against certain uses (e.g., WEP). The first 256 keystream bytes are statistically biased and can leak key information.\n\nFix: simply discard the first 256 keystream bytes after initialization. This eliminates the practical attack at the cost of 256 extra steps."
      }
    ]
  },
  {
    id: 11,
    title: "Confusion, Diffusion & AES/DES",
    tag: "Symmetric Crypto",
    summary: "Confusion hides P↔C relationship (S-boxes). Diffusion spreads plaintext statistics (permutations). AES uses both.",
    content: [
      {
        heading: "Confusion vs Diffusion",
        body: "Confusion: obscures the relationship between plaintext and ciphertext. Achieved via substitution (S-boxes).\n\nDiffusion: spreads influence of each plaintext bit across many ciphertext bits. Achieved via permutation/transposition."
      },
      {
        heading: "AES Four Operations",
        body: "ByteSub (nonlinear layer) → CONFUSION: nonlinear S-box substitution per byte\nShiftRow (linear mixing layer) → DIFFUSION: rotates rows\nMixColumn (linear mixing layer) → DIFFUSION: mixes columns via GF(2⁸) multiply\nAddRoundKey (key addition layer) → CONFUSION: XOR with round subkey"
      },
      {
        heading: "DES Facts",
        body: "Block size: 64 bits\nKey: 64 bits total, 56 effective (8 parity bits discarded)\nSubkeys: 48 bits\nRounds: 16\nS-boxes: 8\nDES IS a Feistel cipher."
      },
      {
        heading: "Feistel Cipher",
        body: "Each round: Lᵢ = Rᵢ₋₁,  Rᵢ = Lᵢ₋₁ ⊕ F(Rᵢ₋₁, Kᵢ)\nDecryption uses the same structure with subkeys reversed.\n\nAES is NOT Feistel (transforms entire block each round).\nTEA is 'almost' Feistel but uses addition/subtraction instead of XOR."
      }
    ]
  },
  {
    id: 12,
    title: "Classic Ciphers & Cryptanalysis",
    tag: "Foundations",
    summary: "Caesar (shift), Vigenère (keyword shifts), codebook, one-time pad. All broken via frequency analysis.",
    content: [
      {
        heading: "Caesar Cipher",
        body: "Shift each letter by n positions. Only 26 keys — trivially brute-forced.\nExample (shift 3): VSRQJHEREVTXDUHSDQWV → SPONGEBOBSQUAREPANTS"
      },
      {
        heading: "Simple Substitution",
        body: "26! ≈ 4×10²⁶ keys — not brute-forceable, but broken via frequency analysis.\nMost common English letters: E, T, A, O, I, N\nLook for patterns: double letters, common 3-letter words (the, and)"
      },
      {
        heading: "Vigenère Cipher",
        body: "Sequence of Caesar shifts using a keyword. 'KEY' → shifts of 10, 4, 24 cycling.\nBroken by: (1) determining keyword length via Kasiski test, (2) splitting into groups by position, (3) frequency analysis on each group."
      },
      {
        heading: "One-Time Pad",
        body: "Theoretically unbreakable: key is truly random, same length as message, used only ONCE.\nC = P ⊕ K\nWeakness: if key is reused, C₁ ⊕ C₂ = P₁ ⊕ P₂ — leaks plaintext relationships."
      },
      {
        heading: "Brute Force Work Factors",
        body: "At 2⁴⁰ keys/second:\n• 2⁸⁸ keyspace → ~4.5 million years\n• 2¹¹² keyspace → ~75 trillion years\n• 2²⁵⁶ keyspace → 1.67×10⁵⁷ years (never)"
      }
    ]
  },
  {
    id: 13,
    title: "Diffie-Hellman Key Exchange",
    tag: "Public Key",
    summary: "Key agreement over public channel. Security = discrete log problem. Vulnerable to MITM without authentication.",
    content: [
      {
        heading: "DH Protocol",
        body: "Public: g, p (large prime)\nAlice picks secret a, sends gᵃ mod p\nBob picks secret b, sends gᵇ mod p\nShared key: gᵃᵇ mod p\n(Alice: (gᵇ)ᵃ,  Bob: (gᵃ)ᵇ — same result)\n\nSecurity: given gᵃ mod p, finding a requires solving the discrete log — computationally infeasible."
      },
      {
        heading: "Man-in-the-Middle Attack",
        body: "Trudy intercepts and establishes gᵃᵗ with Alice and gᵇᵗ with Bob. Each thinks they share a key with the other, but Trudy reads and re-encrypts everything.\n\nFix: Authenticate public values with digital signatures or certificates."
      },
      {
        heading: "Trudy's Failed Triple-DH (HW4)",
        body: "Trudy wants all three to share gᵃᵇᵗ mod p. She can compute gᵃᵗ and gᵇᵗ, but to get gᵃᵇᵗ she needs gᵃᵇ, which requires solving the DH problem or the discrete log for a or b. Attack fails."
      }
    ]
  },
  {
    id: 14,
    title: "Non-Repudiation & Authentication Factors",
    tag: "Access Control",
    summary: "Non-repudiation = sender can't deny sending. Only digital signatures provide it. MACs do not.",
    content: [
      {
        heading: "Three Authentication Factors",
        body: "Something you KNOW: password, PIN\nSomething you HAVE: phone (SMS/OTP), hardware token, smart card\nSomething you ARE: biometric — fingerprint, iris, face\n\nMFA combines ≥2 (e.g., SJSU: password + Okta push)"
      },
      {
        heading: "Why MAC ≠ Non-Repudiation",
        body: "Alice and Bob share symmetric key K. Either party could compute MAC(M, K). If Alice denies sending a message, Bob cannot prove she did — Bob could have fabricated it himself. A third party has no way to decide."
      },
      {
        heading: "Why Digital Signatures = Non-Repudiation",
        body: "Only Alice has her private key. S = h(M)ᵈ mod N can only be produced by Alice. Even Bob cannot forge it. A third party can verify with Alice's public key and be certain Alice signed it."
      },
      {
        heading: "CRC is Not Cryptographic",
        body: "CRC detects accidental bit errors, NOT malicious tampering. An attacker can easily compute a valid CRC for any modified message. CRC provides NEITHER integrity NOR non-repudiation in a security context."
      }
    ]
  },
  {
    id: 15,
    title: "Post-Quantum Cryptography",
    tag: "Advanced",
    summary: "Shor's algorithm breaks RSA/DH on quantum computers. Post-quantum alternatives: NTRU (lattices), McEliece (codes).",
    content: [
      {
        heading: "Why Quantum Threatens RSA & DH",
        body: "Shor's algorithm factors N in polynomial time — classical factoring is exponential. RSA and DH both collapse.\nWork factor: g(n) = 2log₂n + log₂log₂n + log₂log₂log₂n"
      },
      {
        heading: "NTRU (Lattice-Based)",
        body: "Based on the Shortest Vector Problem (SVP) in a lattice — no known efficient quantum algorithm.\nEncrypt: ct = (b×pk + pt) mod q, where b is a random blinding polynomial.\nDecrypt using secret polynomials f and f_p."
      },
      {
        heading: "McEliece (Code-Based)",
        body: "Based on hardness of decoding a general linear code with errors. Uses Goppa codes with a scrambled permutation as the public key. The private key can remove errors efficiently; without it, decoding is infeasible."
      }
    ]
  }
];

const tagColorMap = {
  "Foundations": "#3b82f6",
  "Symmetric Crypto": "#10b981",
  "Integrity": "#ef4444",
  "Public Key": "#8b5cf6",
  "Hashing": "#f59e0b",
  "Applications": "#06b6d4",
  "Information Hiding": "#f97316",
  "Access Control": "#14b8a6",
  "Advanced": "#ec4899",
};

export default function CS166StudyGuide() {
  const [selected, setSelected] = useState(1);
  const [filter, setFilter] = useState("All");

  const tags = ["All", ...Array.from(new Set(concepts.map(c => c.tag)))];
  const filtered = filter === "All" ? concepts : concepts.filter(c => c.tag === filter);
  const active = concepts.find(c => c.id === selected);

  return (
    <div style={{ fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif", background: "#f9fafb", minHeight: "100vh" }}>
      {/* Header */}
      <div style={{ background: "#fff", borderBottom: "1px solid #e5e7eb", padding: "16px 24px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <h1 style={{ margin: 0, fontSize: 20, fontWeight: 700, color: "#111" }}>CS166 Midterm Study Guide</h1>
          <p style={{ margin: "4px 0 12px", fontSize: 13, color: "#6b7280" }}>15 core concepts — click any topic to study it</p>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {tags.map(t => (
              <button key={t} onClick={() => setFilter(t)} style={{
                padding: "4px 12px", fontSize: 12, borderRadius: 20,
                border: "1px solid " + (filter === t ? (tagColorMap[t] || "#3b82f6") : "#d1d5db"),
                background: filter === t ? (tagColorMap[t] || "#3b82f6") : "#fff",
                color: filter === t ? "#fff" : "#374151",
                cursor: "pointer", fontWeight: filter === t ? 600 : 400,
              }}>{t}</button>
            ))}
          </div>
        </div>
      </div>

      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "24px", display: "flex", gap: 24, alignItems: "flex-start" }}>
        {/* Left list */}
        <div style={{ width: 300, flexShrink: 0, display: "flex", flexDirection: "column", gap: 4 }}>
          {filtered.map(c => {
            const color = tagColorMap[c.tag] || "#6b7280";
            const isActive = selected === c.id;
            return (
              <div key={c.id} onClick={() => setSelected(c.id)} style={{
                padding: "10px 14px", borderRadius: 8, cursor: "pointer",
                background: isActive ? "#fff" : "transparent",
                border: isActive ? "1px solid " + color : "1px solid transparent",
                boxShadow: isActive ? "0 1px 4px rgba(0,0,0,0.08)" : "none",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{
                    width: 6, height: 6, borderRadius: "50%", flexShrink: 0,
                    background: color, display: "inline-block",
                  }} />
                  <span style={{ fontSize: 13, fontWeight: isActive ? 600 : 400, color: isActive ? "#111" : "#374151" }}>
                    {c.id}. {c.title}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right detail */}
        {active && (
          <div style={{ flex: 1, background: "#fff", borderRadius: 10, border: "1px solid #e5e7eb", padding: "28px 32px", boxShadow: "0 1px 4px rgba(0,0,0,0.06)" }}>
            <div style={{ marginBottom: 4 }}>
              <span style={{
                fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: 1,
                color: tagColorMap[active.tag] || "#6b7280",
                background: (tagColorMap[active.tag] || "#6b7280") + "18",
                padding: "2px 8px", borderRadius: 4,
              }}>{active.tag}</span>
            </div>
            <h2 style={{ margin: "8px 0 6px", fontSize: 22, fontWeight: 700, color: "#111" }}>{active.title}</h2>
            <p style={{ margin: "0 0 24px", fontSize: 14, color: "#6b7280", lineHeight: 1.5 }}>{active.summary}</p>

            <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
              {active.content.map((s, i) => (
                <div key={i} style={{ paddingTop: i > 0 ? 20 : 0, borderTop: i > 0 ? "1px solid #f3f4f6" : "none" }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: "#111", marginBottom: 8 }}>{s.heading}</div>
                  <div style={{
                    fontSize: 13, color: "#374151", lineHeight: 1.8, whiteSpace: "pre-line",
                    background: "#f9fafb", borderRadius: 6, padding: "12px 14px",
                  }}>{s.body}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
