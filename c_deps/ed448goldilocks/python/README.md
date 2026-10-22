Installation
------------

The easiest way to install is to run the command:
```
pip install 'git+https://git.code.sf.net/p/ed448goldilocks/code#egg=edgold&subdirectory=python'
```

After installation, the tests can be run:
```
python -m unittest edgold.ed448
```

This helps ensure that the correct architecture was detected when
compiling, and that the code works.  It include a couple test vectors
from the RFC, along with verifying that the code can properly interact
with the library.

Usage
-----

This wraps the Ed448 code into a simple to use class, EDDSA448.  The
easiest way to geenrate a new key is to use the generate class method.

Example:
```
from edgold.ed448 import EDDSA448

key = EDDSA448.generate()
privkey = key.export(key('raw')
msg = b'This is a message to sign'
sig = key.sign(msg)

pubkey = key.public_key().export_key('raw')
key = EDDSA448(pub=pubkey)
key.verify(sig, msg)
```
