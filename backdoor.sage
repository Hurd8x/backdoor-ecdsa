# backdoored ECDSA signatures
#
# https://github.com/oreparaz/backdoor-ecdsa
#
# DO NOT USE - experimental quality software
#

from sage.misc.prandom import randint
import hmac
import itertools

# secp256k1 curve parameters
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
K = GF(p)
a = K(0x0000000000000000000000000000000000000000000000000000000000000000)
b = K(0x0000000000000000000000000000000000000000000000000000000000000007)
E = EllipticCurve(K, (a, b))
G = E(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
curve_order = E.order()

def randscalar():
   return randint(0, curve_order-1)

# backdoor parameters
leaked_bits_per_sig = 19
number_signatures = 13

secret_to_leak = randscalar()
secret_backdoor = randscalar()

def bad_nonce(m):
  return (pick_bits(secret_to_leak, m)+1) * mix(secret_backdoor, m)

def sign(m, priv):
  # this is a joke implementation
  k = bad_nonce(m)
  R = k*G
  r = int(R.xy()[0])
  s = inverse_mod(k, curve_order) * (m + r * priv)
  # not here: canonicalize
  return (r, s)
  
def verify(r, s, m, pub):
  # joke alert
  s1 = int(inverse_mod(s, curve_order))
  u1 = int(m * s1)
  u2 = int(r * s1)
  PP = u1*G + u2*pub
  return PP.xy()[0] == r

def ser(n):
  return n.to_bytes(256, 'little')

def deser(bs):
  return int.from_bytes(bs, 'little')

def mix(s, m):
  h = hmac.new(ser(s), digestmod='SHA256')
  h.update(ser(int(m)))
  return deser(h.digest())

def expand(m, dim1, dim2):
  hh=[]
  for i in range(dim1):
     hh.append(Integer(mix(i, m)).digits(2, padto=dim2)[0:dim2])
  H = matrix(GF(2), hh)
  return H
  
def pick_bits(s, m):
  # pick some bits from s, based on m
  vv = vector(GF(2), Integer(s).digits(2, padto=256)[0:256])
  proj = expand(m, leaked_bits_per_sig, 256) * vv
  picked = Integer(list(proj), 2)
  return picked
  
def extract_backdoor(r, s, m, pub):
   # really dumb strategy of just sequential brute force search
   assert(verify(r, s, m, pub))
   B=mix(secret_backdoor, m)*G
   P=E(0)
   for i in range(1, 2**leaked_bits_per_sig+1):
   	P=P+B
   	if P.xy()[0] == r:
   	   #print("extracted: ", i-1)
   	   return i-1
   raise ValueError('signature does not seem to contain backdoor?')

def self_test():
   for i in range(2):
      m = randscalar()
      priv = randscalar()
      pub = priv*G
      (r,s) = sign(m, priv)
      assert(verify(r, s, m, pub))

      assert(extract_backdoor(r, s, m, pub) == pick_bits(secret_to_leak, m))
   print(" [+] self test passed")

self_test()

sigs = []

###########################################

print(" [ ] step 0: signing %d random messages under random keys" % number_signatures)

for i in range(number_signatures):
   m = randscalar()
   priv = randscalar()
   sigs.append((*sign(m, priv), m, priv*G))

###########################################

print(" [ ] step 1: recovering %d bits per signature"% leaked_bits_per_sig)

extracted_bits = []
MMM = []

flatten = itertools.chain.from_iterable

for i in range(number_signatures):
   ex = extract_backdoor(*sigs[i])
   #ex = pick_bits(secret_to_leak, sigs[i][2]) # shortcut
   print(" [+] extracted %s from signature %d"%("{0:#0{1}x}".format(ex,8), i))
   extracted_bits.append(Integer(ex).digits(2, padto=leaked_bits_per_sig))
   T = expand(sigs[i][2], leaked_bits_per_sig, 256).transpose()
   
   if MMM == []:
   	MMM = T
   else:
   	MMM = MMM.augment(T)

###########################################

print(" [+] step 2: exhaustive search")

extracted_bits = list(flatten(extracted_bits))
MMM = matrix(GF(2), MMM)
kernel = MMM.left_kernel()
kernel_dimension = kernel.dimension()

print(" [+] bits to guess: %d" % kernel_dimension)

if kernel_dimension > 16:
   print(" [-] too much of an effort for brute forcing, bailing...")
   sys.exit(0)

def print_nice(x):
   xx = list(x.list())
   yy = [str(int(z)) for z in xx]
   # return ''.join(yy)
   return hex(int(''.join(yy), 2))

# one possible solution
one_solution = MMM.transpose() \ vector(GF(2), extracted_bits)

target_secret_to_leak = list(Integer(secret_to_leak).digits(2, padto=256))
success = False

# loop over all solutions over GF(2)
for kk in kernel:
   print("  candidate: ", print_nice(kk+one_solution))
   if list(kk + one_solution) == target_secret_to_leak:
      success = True

if success:
   print("[+]")
   print("[+] brute force successful. number_signatures=%d leaked_bits_per_sig=%d dim(ker(A))=%d"%(number_signatures, leaked_bits_per_sig, kernel_dimension))
   print("[+] recovered=%s"%(Integer(secret_to_leak).hex()))
   print("[+]")
else:
   print("[-] brute force did not work (?)")

assert(success)

