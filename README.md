![mini-cryptography](https://github.com/antanasbendoraitis/mini-cryptography/blob/master/images/mini-cryptography.png?raw=true)
## mini-cryptography: mini ECDSA cryptography and Mekle tree root calculation
Mini-cryptography is a package that has ECDSA (Elliptic Curve Digital Signature Algorithm) arithmetic operations, including signature formation and verification. It also has a merkle tree root calculation based on the SHA-256 hash algorithm.
## Content
&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[Dependencies](#dependencies)</br>
&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[Installation](#installation)</br>
&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[Uninstallation](#uninstallation)</br>
&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[User guide](#user-guide)</br>
&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[ECDSA](#ecdsa)</br>
&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[Data for ECDSA examples](#data-for-ecdsa-examples)</br>
&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[ECDSA examples](#ecdsa-examples)</br>
&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[Merkle](#merkle)</br>
&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[Data for Merkle examples](#data-for-merkle-examples)</br>
&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[Merkle examples](#merkle-examples)</br>
&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[Development](#development)</br>
&emsp;&emsp;&emsp;φ&nbsp;&nbsp;[License](#license)</br>
## Dependencies
Mini-cryptography supports Python 3.7+.</br>
Installation requires [tinyec](https://pypi.org/project/tinyec/).
### Installation
The package can be installed from PyPI:
```
pip install mini-cryptography
```
### Uninstallation
The package can be uninstalled using:
```
pip uninstall mini-cryptography
```
### User guide
There are 2 main classes:</br>
&emsp;&emsp;&emsp;φ&nbsp;&nbsp;Ecdsa - has ECDSA arithmetic operations, including signature formation and verification;</br>
&emsp;&emsp;&emsp;φ&nbsp;&nbsp;Merkle - wich has merkle tree root calculation based on the SHA-256 hash algorithm.

Required libraries
``` Python
from mini_cryptography import merkle
from mini_cryptography import ecdsa
import hashlib
```
#### ECDSA
Other required classes:</br>
&emsp;&emsp;&emsp;φ&nbsp;&nbsp;Point - ECDSA point that has x and y coordinates;</br>
&emsp;&emsp;&emsp;φ&nbsp;&nbsp;Field - describes the ECDSA field.
##### Data for ECDSA examples
[Secp384r1](https://neuromancer.sk/std/secg/secp384r1) is 384-bit prime field Weierstrass curve. Also known as [P-384](https://neuromancer.sk/std/nist/P-384) [ansip384r1](https://neuromancer.sk/std/x963/ansip384r1):
``` Python
a = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112316
b = 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575
n = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
G = ecdsa.Point(
    26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087,
    8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871
)
secp384r1 = ecdsa.Field(a, b, n, p, G)
curve = ecdsa.Ecdsa(field=secp384r1, name="secp384r1")
```
Points
``` Python
point1 = ecdsa.Point(
    19577993669543055159462232654227477804059834554938749056365059575367343238573934152231932832497698572508881172084304,
    34797297628126597108728033628292920232095535295240081944254459873403593475466847089395925227525676205111687199013609
)
point2 = ecdsa.Point(
    2643888095364097454558349481745047911629089192351741699089972264282318601908091592262966275642198233545325090846186,
    12384549089646028340756024322986515983214437514151244063613237375835994573258040845173892755352541890195338888681840
)
```
##### ECDSA examples
Points sum
``` Python
new_point = sum_points(point1, point2)
```
``` Python
Result:
New point (
    22152009089199730593582524338115427010336291169893373839910753311913746007332469659451755453856401184556487920772225,
    21415530147108271193135517297779083081913015961082356748098427685923206883047231450346172563957532258197936273940105
)
```
Points multiplication
``` Python
multiplier = 9868959070921577617284768940259093768032668379810297735137924030066340321810481073797782613683403119141615137083587
new_point = multiply_points(point1, multiplier)
```
```
Result: Python
New point (
    14103764458811902000156928461250459647654661504776098395816220167714718139473397796549037360732342313833270939242263,
    17395148190829553535748807655250157906889415207238492158034708401150356646081290450883354819984464883347616139045011
)
```
Generate random private key [1, n-1]
``` Python
privateKey = curve.private_key_generator()
```
``` Python
Result: privateKey = 20989443543778090555157442102131049817299902423795685309899862760056430951462397686708870733055917820122718887042439
```
Multiplication of G (base) point from the given multiplier
``` Python
public_key = curve.G_multiplication(privateKey)
```
``` Python
Result: 
G(x, y) (
    30040694804942853208177610713088115928148181688856632998897580287365858436344609590182460206850552050293936278998346,
    17559245262757783022105893899857708160332511010412356224688036071313308531776780869864952047367968387454976435887533
)
```
Generate random k [1, ... n-1]
``` Python
k = curve.k_generator()
```
``` Python
Result: 11000
```
Sign message
``` Python
message = 'Religio, Doctrina, Civilitas, prae omnibus Virtus'
hash = int(hashlib.sha1(message.encode()).hexdigest(),base=16)

r, s = curve.sign_message(privateKey, k, hash=hash)
```
``` Python
Result:
Signature (
	r = 22152009089199730593582524338115427010336291169893373839910753311913746007332469659451755453856401184556487920772225, 
	s = 33247802217962351080804096577524498301009516670239406026864057032340769378746165513387841747729702616554540985061660
)
```
Verify signature validity
``` Python
verification = curve.verify_signature(r, s, hash, public_key)
```
``` Python
Result: True
```
#### Merkle
##### Data for Merkle examples
``` Python
hashList = [
    '01000000295c297aee86096dcf6092',
    '0100000007bdc63ab3e74058a87b92',
    '01000000017b23260463311a4d1936',
    '0100000007bdc63ab3e74058a87b92'
]
```
##### Merkle examples
Merkle root calculation from transactions
``` Python
merkle.Merkle().merkle_root(hashList, 0) #if 0 transactions are hashed, then 1 transactions are not hashed. 
```
``` Python
Result: 'f3b5457f44b0a28a11ced653941ae1f2632b219f5d366a4167945eff0ed068a1'
```
Calculate transaction hash
``` Python
merkle.Merkle().transaction_hash(hashList[0])
```
``` Python
Result: b'3860b826dfc02feed1bbeb908eb0b2c0f5ea32a1b12ef1e8d87d2bf0e3802795'
```
### Development
Mini-cryptography development takes place on [Github](https://github.com/antanasbendoraitis/mini-cryptography.git): https://github.com/antanasbendoraitis/mini-cryptography.git</br>
Please submit bugs that you encounter to the issue tracker with a reproducible example demonstrating the problem.
### License
[MIT](https://github.com/antanasbendoraitis/mini-cryptography/blob/master/LICENSE)