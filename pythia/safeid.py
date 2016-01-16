#!/usr/bin/env python
"""
SafeID interacts with a Pythia PRF service to protect and verify passwords.
"""
import argparse, json, sys
from common import *
from httpJson import ServiceException, fetch, extract
from pyrelic import vpop
import ersatzlib, pyrelic
from passlib import hash
from passlib.hash import pbkdf2_sha1
import timeit, csv

iterations=1000
#w, t, z, p
#["xICvhBzvgCyDZfX7HN5SSnYDQGauOZYF", "bmOZcXJsD7Y2xa9wIcBZG2QJeewcJkC-", "FD7-R0ceKYXsIiZQr4WAtV3AEfR5PweGAn6MWeAa0cAKBrspDZ4HlPL5u9JHFxxi4EtvyAL484qjyYLVs2u9LBdngbBgVyaB2gQX7n9cjZ0C50pQzQjqOlOxRGpfdpJUIVsvVZRpUNTMskIdSlCSQ-R7PXjlfUaZ9aXUa1i2aFkkpXoUzNI355v8l6WU7TdtJJfzY8fa-jn92GebcVbzzgggffa6mmPn7F0vF4gF40kbv3RYIZOEqQf4E3IyajlKG-38L9AnRc-UfnnQE1kXJoyOUnStaBGxO2g0hwI8MswFF0f3odqCeZyXR7H9SKcihDKDSMYBdbvLCJPY7YQJHQ==", "AgjWJ2CawvpDMsP1-RVbbu68wT5_TUTg-6MWdsIURyjD"]

#updated
#delta, t, z, pPrime
#["MHgyMTFjMDcxMjA1MzI2OWJjMGI2NGQ4NWIwYTE0YWYyZGViZTY5OWIwYzM0YjkwNWY0N2Q3ZjVmY2Y0NzVhYTRhTA==", "bmOZcXJsD7Y2xa9wIcBZG2QJeewcJkC-", "FD7-R0ceKYXsIiZQr4WAtV3AEfR5PweGAn6MWeAa0cAKBrspDZ4HlPL5u9JHFxxi4EtvyAL484qjyYLVs2u9LBdngbBgVyaB2gQX7n9cjZ0C50pQzQjqOlOxRGpfdpJUIVsvVZRpUNTMskIdSlCSQ-R7PXjlfUaZ9aXUa1i2aFkkpXoUzNI355v8l6WU7TdtJJfzY8fa-jn92GebcVbzzgggffa6mmPn7F0vF4gF40kbv3RYIZOEqQf4E3IyajlKG-38L9AnRc-UfnnQE1kXJoyOUnStaBGxO2g0hwI8MswFF0f3odqCeZyXR7H9SKcihDKDSMYBdbvLCJPY7YQJHQ==", "IyNqE0LIlnJvXL2lgS3GLOW1OULMdqGV_mVZ6BzPQXgfN2G8whIXyBNz2iitfrK_UUulT_j9KvsB4ZyP7_-4NSC0FQRutcNqtGKjQBdyUupLydnnVwn9W435H5zVKT2VAWemsXJaqKjhkWek1zPXQumFWuLduLERQx_JYW5fbGgcvzo7fXOzIQFYVFIFyeKwbmHlBDPOiJeq8Y39RrFj8xpvPuVwLRZEWpqG1qrCN04Y98NJghR0qfQCrTSX8X7UBw47ki8j83pvUV4hgxiXlKu7y4JxJcZ2xJSJaRj6SIkgZJqL9NWmZVSdRkScz-ZS47VAWKbGQjW987AIiGBUyA=="]
#["MHgyMTFjMDcxMjA1MzI2OWJjMGI2NGQ4NWIwYTE0YWYyZGViZTY5OWIwYzM0YjkwNWY0N2Q3ZjVmY2Y0NzVhYTRhTA==", "bmOZcXJsD7Y2xa9wIcBZG2QJeewcJkC-", IyNqE0LIlnJvXL2lgS3GLOW1OULMdqGV_mVZ6BzPQXgfN2G8whIXyBNz2iitfrK_UUulT_j9KvsB4ZyP7_-4NSC0FQRutcNqtGKjQBdyUupLydnnVwn9W435H5zVKT2VAWemsXJaqKjhkWek1zPXQumFWuLduLERQx_JYW5fbGgcvzo7fXOzIQFYVFIFyeKwbmHlBDPOiJeq8Y39RrFj8xpvPuVwLRZEWpqG1qrCN04Y98NJghR0qfQCrTSX8X7UBw47ki8j83pvUV4hgxiXlKu7y4JxJcZ2xJSJaRj6SIkgZJqL9NWmZVSdRkScz-ZS47VAWKbGQjW987AIiGBUyA==", "AgjWJ2CawvpDMsP1-RVbbu68wT5_TUTg-6MWdsIURyjD"]
#["xICvhBzvgCyDZfX7HN5SSnYDQGauOZYF", "bmOZcXJsD7Y2xa9wIcBZG2QJeewcJkC-", "FD7-R0ceKYXsIiZQr4WAtV3AEfR5PweGAn6MWeAa0cAKBrspDZ4HlPL5u9JHFxxi4EtvyAL484qjyYLVs2u9LBdngbBgVyaB2gQX7n9cjZ0C50pQzQjqOlOxRGpfdpJUIVsvVZRpUNTMskIdSlCSQ-R7PXjlfUaZ9aXUa1i2aFkkpXoUzNI355v8l6WU7TdtJJfzY8fa-jn92GebcVbzzgggffa6mmPn7F0vF4gF40kbv3RYIZOEqQf4E3IyajlKG-38L9AnRc-UfnnQE1kXJoyOUnStaBGxO2g0hwI8MswFF0f3odqCeZyXR7H9SKcihDKDSMYBdbvLCJPY7YQJHQ==", "EF-POS6B68n0KZ7ZKXPiShzgMJmga0CIbqI53ero2VsdhA5S-k_BriZIAf-bgiHi7EQpaTKV_pcxj-NVgZKO7gYSQ1edruWr9vf4brisOrjvecUQhZf4ex-mvnWAdt7fBDV8_zUaqDX3sdTDM56JJ5DyhPXnbc1r6XLqLoZKv90Dzau3g7xksrzkx5I1FIqAP_TMK_s64rYT0ztMbaSJWA_DDwcxTFVdMP3rtnmqlJMxYnN0t48d1sMAoYrkjpQ_Dcdu3C1gjoR2rY0XmS9OrRj-2L2_BS4J83Q0i5sUAg4ErXrkzkJ3gRO1sPaRTc2PEeTYvRnkC08x9IhuKANPBA=="]

defaultServer = "https://remote-crypto.io"
queryUrlTemplate = "{}/pythia/eval?w={}&t={}&x={}"
queryUrlUpdateTemplate = "{}/pythia/updateToken?w={}&wPrime={}"
queryUrlDeleteTemplate = "{}/pythia/delete?w={}&wPrime={}"
usage = \
"""safeid COMMAND [-s/--server https://pythia-server] [args]
Process passwords using the Pythia protocol

COMMANDS
new 'pw'            Protects a password using the Pythia protocol. 
                    Outputs the result as a JSON list.
check 'pw' 'JSON'   Checks a given passphrase against an existing 
                    protected password (JSON list).
"""

ersatzHash = False

        
def new(password, server=defaultServer, clientId=None, username="alice"):
    """
    Encrypts a new @password by interacting with the Pythia service.
    @clientId: If specified, this value is used. If omitted, a suitable 
               value is selected.

    @returns a tuple of required values to verify the password: (w,t,z,p) 
     where:
        @w: client ID (key selector)
        @t: tweak (randomly generated user ID)
        @z: protected passwords
        @p: server public key bound to clientId - used to verify future
            proofs from this server.
    """
    # Set the client ID
    if not clientId:
        w = secureRandom()
    else:
        w = clientId
    
    if ersatzHash == True:
        ersatzPw = "ersatz"
        ersatzHashGen = ersatzlib.ErsatzHashGenerator(hash.pbkdf2_sha1,\
                                                      username, password, \
                                                      ersatzPw, rounds=5000)
        #create ersatz salt
        t = ersatzHashGen._compute_ersatz_salt(password,ersatzPw)
        ersatzHashGen.salt = t
        a = ersatzHashGen._compute_ersatz_hash(password)
        a = passlib.utils.ab64_decode(a)
        
        #create ersatz input
        ersatzInput = ersatzHashGen._ersatzfy_input(password)
        z,p = query(ersatzInput, w, t, server)
        
        z = vpop.wrap(pyrelic.vpop.update(vpop.unwrapY(z), long(a.encode('hex'),16)))
        #do the Z^a nonsense, where a is the pbkdf2
        
    else:
        t = secureRandom()

        hashedPW = pbkdf2_sha1.encrypt(password, salt=t, rounds=5000)
        z,p = query(hashedPW, w, t, server)
        z = vpop.wrap(pyrelic.vpop.update(vpop.unwrapY(z), long(hashedPW.encode('hex'),16)))
        #t = secureRandom()
        #z,p = query(password, w, t, server)
    return w, t, z, p

def update(wPrime,w,t,z,p,server=defaultServer):
    # Query the service via HTTP(S) GET
    response = fetch(queryUrlUpdateTemplate.format(server,w,wPrime))
    
    # Grab the required fields from the response.
    pPrime,delta = extract(response, ["pPrime","delta"])
    updatedZ = vpop.wrap(pyrelic.vpop.update(vpop.unwrapY(z), pyrelic.vpop.unwrapDelta(delta)))
    updateP = vpop.wrap(vpop.unwrapP(p)*vpop.unwrapLong(delta))
    return wPrime, t, updatedZ, updateP

def check(password, w, t, z, p, server=defaultServer, username="alice"):
    """
    Checks an existing @password against the Pythia server using the 
    values (w,t,z,p).
    @returns: True if the password passes authentication; False otherwise.
    """
    
    if ersatzHash:
        ersatzHashGen = ersatzlib.ErsatzHashGenerator(hash.pbkdf2_sha1,\
                                                      username, password, \
                                                      "ersatz", rounds=5000)
        ersatzHashGen.salt = t
        ersatzInput = ersatzHashGen._ersatzfy_input(password)
        
        #check true password
        zPrime1,_ = query(ersatzInput, w, t, previousPubkey=p, server=server)
        zPrime2,_ = query(password, w, t, previousPubkey=p, server=server)
        

        #create ersatz salt
        a = passlib.utils.ab64_decode(ersatzHashGen._compute_ersatz_hash(password))
        
        zPrime1 = vpop.wrap(pyrelic.vpop.update(vpop.unwrapY(zPrime1), long(a.encode('hex'),16)))
        
        a = passlib.utils.ab64_decode(hash.pbkdf2_sha1.encrypt(password, salt=t, rounds=5000))
        zPrime2 = vpop.wrap(pyrelic.vpop.update(vpop.unwrapY(zPrime2), long(a.encode('hex'),16)))
        
        if z == zPrime1:
            return 1
        elif z == zPrime2:
            return 2
        else:
            return 0
        #check ersatz password
    else:
        hashedPW = pbkdf2_sha1.encrypt(password, salt=t, rounds=5000)
        zPrime,_ = query(hashedPW, w, t, previousPubkey=p, server=server)
        zPrime = vpop.wrap(pyrelic.vpop.update(vpop.unwrapY(zPrime), long(hashedPW.encode('hex'),16)))
        
        #zPrime,_ = query(password, w, t, previousPubkey=p, server=server)
        return z == zPrime


def query(password, w, t, server=defaultServer, previousPubkey=None):
    """
    Queries the a Pythia PRF service and verifies the server's ZKP.
    @returns (z,p) where: @z is the encrypted password and @p is the
        server's pubkey bound to clientId

    Raises an exception if there are any problems interacting with the service
        or if the server's ZKP fails verification.
    """
    # Blind the password
    r,x = vpop.blind(password)
    xSerialized = vpop.wrap(x)

    # Query the service via HTTP(S) GET
    response = fetch(queryUrlTemplate.format(server,w,t,xSerialized))

    # Grab the required fields from the response.
    p,y,c,u = extract(response, ["p","y","c","u"])

    # Check the pubkey
    if previousPubkey and previousPubkey != p:
        print "previous: " + previousPubkey
        print "p: "+ p
        raise Exception("Server-provided pubkey doesn't match previous pubkey.")

    # Deserialize the response fields
    p,y,c,u = (vpop.unwrapP(p), vpop.unwrapY(y), 
            vpop.unwrapC(c), vpop.unwrapU(u))

    pi = (p,c,u)

    # Verify the result by checking the proof
    vpop.verify(x, t, y, pi)

    # Deblind the result
    z = vpop.deblind(r,y)

    # Return the important fields in serialied form
    z,p = vpop.wrap(z), vpop.wrap(p)
    return z,p


def main():
    """
    Run the safeid command line program
    """
    # DEBUG
    process(sys.argv)
    return
    try:
        process(sys.argv)
    except Exception as e:
        print e

def writeToCSV(fileName, data):
    with open(fileName + '.csv', 'wb') as myfile:
        wr = csv.writer(myfile)
        wr.writerow(data)

def calcLatency(iterations, a, args):
    timeLatency = list()
    for i in range(iterations):
        if i % 100 == 0:
            print str(i) + "/" + str(iterations)
        if "new" in a.COMMAND:
            start = timeit.default_timer()
            new(a.passphrase, a.server, username=a.username)
            stop = timeit.default_timer()
        elif "update" in a.COMMAND:
            args = readJson(a.protectedPassphrase)
            start = timeit.default_timer()
            update(secureRandom(),*args, server=a.server)
            stop = timeit.default_timer()
        elif "check" in a.COMMAND:
            args = readJson(a.protectedPassphrase)
            start = timeit.default_timer()
            check(a.passphrase,*args,server=a.server, username=a.username)
            stop = timeit.default_timer()
        timeLatency.append(stop - start)
    if ersatzHash:
        runType = "ersatz"
    else:
        runType = "baseline"
    outName = a.COMMAND + "_" +a.passphrase + "_" + runType
    writeToCSV(outName, timeLatency)

def process(args):
    """
    Command line interface to SafeID
    """
    # Parse arguments
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("COMMAND", choices=["new", "check", "update", \
                                            "new_latency", "update_latency",\
                                            "check_latency"])
    parser.add_argument("username", type=str)
    parser.add_argument("passphrase", type=str)
    parser.add_argument("protectedPassphrase", nargs="?", type=str)
    parser.add_argument("-s", "--server", default=defaultServer, type=str)
    
    a = parser.parse_args(args[1:])

    ##
    # Run the requested command
    ##

    # New password
    if "latency" in a.COMMAND:
        calcLatency(iterations, a, args)
    elif a.COMMAND == "new":
        print json.dumps(new(a.passphrase, a.server, username=a.username))
    elif a.COMMAND == "update":
        args = readJson(a.protectedPassphrase)
        print json.dumps(update(secureRandom(),*args, server=a.server))

    # Check existing password
    elif a.COMMAND == "check" and a.protectedPassphrase:

        # Parse the encrypted password
        args = readJson(a.protectedPassphrase)

        # Check the password
        if ersatzHash:
            checkVal = check(a.passphrase,*args,server=a.server, username=a.username)
            if checkVal == 1:
                print  "Password is authentic"
            elif checkVal == 2:
                print "Ersatz password"
            else:
                print "Invalid password "
        else:
            if check(a.passphrase,*args,server=a.server):
                print  "Password is authentic"
            else:
                print "Invalid password "

    else:
        print "usage: " + usage


def readJson(text):
    """
    Parses JSON array and returns (w,t,z,p) as strings.
    """
    # Convert all unicode JSON results to strings. ZK proofs fail when
    # one party uses unicode and the other uses strings.
    return map(str, json.loads(text))


# Run!
if __name__ == "__main__":
    main()

