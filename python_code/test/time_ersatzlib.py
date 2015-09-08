'''
Created on Sep 7, 2015

@author: krix
'''
import ersatzlib, timeit
from passlib import hash

def time_ersatz_hash(hashFunc, username, realPW, ersatzPW, \
                      hashRounds, count):
    erh = ersatzlib.ErsatzHashGenerator(hashFunc, username, realPW, \
                                        ersatzPW, rounds=hashRounds)
    saltTime = list()   
    for i in range(count):
        start = timeit.default_timer()
        erh._compute_ersatz_salt(realPW, ersatzPW)
        stop = timeit.default_timer()
        saltTime.append(stop - start)
        
    hashTime = list()
    for i in range(count):
        start = timeit.default_timer()
        erh._compute_ersatz_hash(realPW)
        stop = timeit.default_timer()
        hashTime.append(stop - start)
        
    verifyTrueTime = list()   
    for i in range(count):
        start = timeit.default_timer()
        erh.verify(realPW)
        stop = timeit.default_timer()
        verifyTrueTime.append(stop - start)
        
    verifyErsatzTime = list()   
    for i in range(count):
        start = timeit.default_timer()
        erh.verify(ersatzPW)
        stop = timeit.default_timer()
        verifyErsatzTime.append(stop - start)
    
    verifyFalseTime = list()   
    for i in range(count):
        start = timeit.default_timer()
        erh.verify("false")
        stop = timeit.default_timer()
        verifyFalseTime.append(stop - start)
        
    return {"saltTime":saltTime, "hashTime":hashTime,\
            "verifyTrueTime":verifyTrueTime,\
            "verifyErsatzTime":verifyErsatzTime,\
            "verifyFalseTime":verifyFalseTime}


        
if __name__ == '__main__':
    
    print time_ersatz_hash(hash.sha1_crypt, "chris", "123456", "ersatz", 5000, 100)
    
    pass