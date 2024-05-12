from sage.all import *
from Crypto.Util.number import long_to_bytes

N = 15193992477728078349*x^14 + 20849951573235599290*x^13 + 31626787439292941810*x^12 + 41606030540518542243*x^11 + 51135239778172914618*x^10 + 54839205054373601768*x^9 + 61504808736544546256*x^8 + 69077638236743212818*x^7 + 53980744540731499013*x^6 + 48344582546079800218*x^5 + 37874750456914975063*x^4 + 28415628763501783372*x^3 + 19286832846769454663*x^2 + 13073046561885731511*x + 7807279729190335309 

n = 108467639697839662757675119579277149084242308356218922071090918908615374948181781274150380885272044494446721088127180898926333391217444363867805503733024234462862873998737363236748030712385045260063783565046555205958369142785754700441856622886319553247371639123221105096296162808152357323029673800985543

e = 0x10001

c = 88755015861533943167974559872713361696099145214213848793491838241022886852405120609704167406295045592769591587483471982775519184576012814288576845480957257644075924651736974849836538134802852128574442137122106558275855261092222278387967861419587133198657052818619203674183040801840364877770834201106835


(P, _), (Q, _) = N.factor_list()
r = ((N - n).roots())[0][0]

p, q = P(x=r), Q(x=r)

phi = (p-1)*(q-1)
d = pow(e, -1, phi)

m = pow(c, d, n)
print(long_to_bytes(int(m)))
# 404CTF{L3_JURy_V0u5_4_477ri8u3R_L3_plu5_34u_5C0r3_v0u5_V07r3_P3rf0rm4nc3_34ud4ci3u23}