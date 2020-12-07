import string
import hashlib
import random
import codecs
import time

# Shingling
# Computes set of shingles from documents
class Shingling( object ):
    def __init__( self, doc ):
        self.doc = doc
        self.shingles = []
        
    def hashFamily( self, i ):
        resultSize = 8
        maxLen = 20
        salt = str( i ).zfill( maxLen )[-maxLen:]
        def hashMember( x ):
            a = x + salt
            return hashlib.sha1( a.encode('utf-8') ).digest()[-resultSize:]
        return hashMember
        
    def shingle( self, n ):
        
        # Remove punctuation and lowercase
        doc = self.doc.translate( str.maketrans( '', '', string.punctuation ) )
        doc = doc.lower()
        
        # Hashing shingles
        for i in range( 0, len( doc ) - n + 1 ):
            shingle = doc[i:i+n]
            self.shingles.append( int.from_bytes( self.hashFamily( 20 )( shingle ), "big" ) )
            
        return self.shingles
        
# Minwise hashing
# Computes signature vectors from set of shingles     
class MinwiseHashing( object ):
    def __init__( self, set ):
        self.set = set
        self.n = len( set )
        
    def genMatrix( self ):
        m = []
        objs = []
        
        for i in range( 0, self.n ):
            reps = []
            # If shingle is in matrix, just append a 1, otherwise create new row
            for j in self.set[i]:                
                if j in objs and j not in reps:
                    m[objs.index( j )] = m[objs.index( j )] + [1]
                else:
                    objs.append( j )
                    ne = [0] * i + [1]
                    m.append( ne )
                reps.append( j )
            # Append a 0 for all the other shingles
            for j in range( 0, len( m ) ):
                if len( m[j] ) == i:
                    m[j] = m[j] + [0]
             
        self.objs = objs
        self.m = m        
        
    def hashFamily( self, i ):
        resultSize = 8
        maxLen = 20
        salt = str( i ).zfill( maxLen )[-maxLen:]
        def hashMember( x ):
            a = x + salt
            return hashlib.sha1( a.encode('utf-8') ).digest()[-resultSize:]
        return hashMember   
        
    def sign( self ):
        self.genMatrix()
        self.h = [[0 for x in range( 20 )] for y in range( len( self.objs ) )] 
        self.sm = [[0 for x in range( 20 )] for y in range( self.n ) ] 
        
        # Hash each shingle with 20 different hash function
        for i in range( 0, len( self.objs ) ):
            for j in range( 0, 20 ):
                obj = str( self.objs[i] )
                self.h[i][j] = int.from_bytes( self.hashFamily( j )( obj ), "big" )
                
        # Take minimum shingle between the ones contained in the document
        for i in range( 0, self.n ):
            for j in range( 0, 20 ):
                minv = 0
                for k in range( 0, len( self.objs ) ):
                    if self.m[k][i] == 1 and ( minv == 0 or self.h[k][j] < minv ):
                        minv = self.h[k][j]
                self.sm[i][j] = minv
        
        return self.sm
            

# Locality sensitive hashing
# Hashes bands of signature vector set and computes similar 
class LocalitySensitiveHashing( object ):
    def __init__( self, signs ):
        self.signs = signs
        self.r = 0
        
    def hashFamily( self, i ):
        resultSize = 8
        maxLen = 20
        salt = str( i ).zfill( maxLen )[-maxLen:]
        def hashMember( x ):
            a = x + salt
            return hashlib.sha1( a.encode('utf-8') ).digest()[-resultSize:]
        return hashMember

    def findNear( self, r ):
        s = self.signs 
        self.similar = []
        
        # Hash bands of r rows and compare them 
        for i in range( len( s ) - 1 ):
            for j in range( i+1, len( self.signs ) ):
                n = int( 20 / r )
                score = 0
                for k in range( n ):
                    v = list( map( str, s[i][k*r:(k+1)*r] ) )
                    w = list( map( str, s[j][k*r:(k+1)*r] ) )
                    v = int.from_bytes( self.hashFamily( 21 )( ''.join( v ) ), "big" )
                    w = int.from_bytes( self.hashFamily( 21 )( ''.join( w ) ), "big" )
                    if v == w:
                        score += (1/n)
                if score >= 0.8:
                    self.similar.append( [i,j] )
                    
        return self.similar
        
        
# Classic similarity class
# Computes intersection and union of sets, then returns pairs with score higher or equal to 80%
class Similarity( object ):
    def __init__( self, set ):
        self.set = set
        
    def findNear( self ):
        self.similar = []
        
        # Take sets one by one and compare them
        for i in range( len( self.set ) - 1 ):
            for j in range( i+1, len( self.set ) ):
                union = []
                inter = []
                for k in range( len( self.set[i] ) ):
                    if self.set[i][k] not in union:
                        union.append( self.set[i][k] )
                    for l in range( len( self.set[j] ) ):
                        if self.set[j][l] not in union:
                            union.append( self.set[j][l] )
                        if self.set[i][k] == self.set[j][l] and self.set[i][k] not in inter:
                            inter.append( self.set[i][k] )
                            
                sim = len( inter ) / len( union )
                if sim >= 0.8:
                    self.similar.append( [i,j] )
                            
        return self.similar  


# Reding the file and computing the shingling operation
# Appending each set of shingles to the dictionary

dict = []

f = codecs.open( "products.tsv", "r", 'utf-8' )

for l in f:
    doc = l.split("\t")
    s = Shingling( doc[0] )
    dict.append( s.shingle( 10 ) )

f.close()  

# Computing classic similarity computation   

start_time = time.time()
s = Similarity( dict )
fnc = s.findNear()
#print(fnc)
print(len( fnc ))
print("--- %s seconds ---" % (time.time() - start_time))

# Computing signatures and LSH
start_time = time.time()
m = MinwiseHashing( dict )
l = LocalitySensitiveHashing( m.sign() )
fnl = l.findNear( 2 )
#print(fnl)
print(len( fnl ))
print("--- %s seconds ---" % (time.time() - start_time))

# Computing intersection set

intersection = [value for value in fnc if value in fnl] 
print( len( intersection )  )