import hashlib


file_md5="md5.hash"
file_sha256="sha256.hash"
file_sha3= "sha3.hash"


#Έλεγχος ακεραιότητας αρχείου με βάση το αποθηκευμένο hash
def hash_integrityCheck(hashFile, hashValue):
    #Εισαγωγή βιβλιοθήκης os για έλεγχο ύπαρξης αρχείου αλλα και για να μην κανουμε το προγραμμα ποιο πολυπλοκο
    import os
    #Ελέγχουμε αν το αρχείο hash υπάρχει και αν είναι άδειο. 
    # Αν δεν υπάρχει, σημαίνει ότι είναι η πρώτη εγγραφή και δεν υπάρχει προηγούμενο hash για σύγκριση. 
     
    if not os.path.exists(hashFile) or os.path.getsize(hashFile) == 0:
        print("Πρώτη εγγραφή, δεν υπάρχει προηγούμενο hash.")
        return
    # Αν υπάρχει, διαβάζουμε το αποθηκευμένο hash και συγκρίνουμε με το νέο hash που υπολογίσαμε.
    with open(hashFile, "r") as f:
        storedHash = f.read().strip()
    #Αν τα δύο hash είναι ίδια, σημαίνει ότι το αρχείο δεν έχει τροποποιηθεί.
    if storedHash == hashValue:
        print("Το αρχείο δεν έχει τροποποιηθεί ")
    # Αν είναι διαφορετικά, σημαίνει ότι το αρχείο έχει αλλοιωθεί.
    else:
        print("Το αρχείο έχει αλλοιωθεί ")

#Αποθήκευση των hash σε αρχείο .hash
def saveHash(hashFile,hashValue):
 with open(hashFile,"w") as f:
  f.write(hashValue)
 print(f"Το hash αποθηκεύτηκε στο αρχείο {hashFile}")

#Είσοδος αρχείου και έλεγχος αν υπάρχει
try:
 
 print("Δώσε όνομα αρχείου .txt")
 giveFile=input()

 with open(giveFile,"rb") as f:
  readFile=f.read()
  
except FileNotFoundError:
 print("Το αρχείο δεν βρέθηκε, δοκίμασε ξανά")
 giveFile=input()

#Επιλογή αλγορίθμου και υπολογισμός hash
print("Επίλεξε Αλγόριθμο MD5(1),SHA256(2),SHA3(3) ή όλους(4)")
algSelect=input()

#υπολογισμός MD5 hash
if algSelect=="1":
 
 hashMD5=hashlib.md5(readFile).hexdigest()
 print(f"Το MD5 hash του {giveFile} είναι:{hashMD5}")
 hash_integrityCheck(file_md5,hashMD5)
 saveHash(file_md5,hashMD5)

#υπολογισμός SHA256 hash
elif algSelect=="2":
 
 hashSHA256=hashlib.sha256(readFile).hexdigest()
 print(f"Το SHA256 hash του {giveFile} είναι:{hashSHA256}")
 hash_integrityCheck(file_sha256,hashSHA256)
 saveHash(file_sha256,hashSHA256)

#υπολογισμός SHA3 hash
elif algSelect=="3":

 hashSHA3=hashlib.sha3_256(readFile).hexdigest()
 print(f"Το SHA3 hash του {giveFile} είναι:{hashSHA3}")
 hash_integrityCheck(file_sha3,hashSHA3)    
 saveHash(file_sha3,hashSHA3)
 
#υπολογισμός όλων των hash
elif algSelect=="4":
 
 hashMD5=hashlib.md5(readFile).hexdigest()
 print(f"Το MD5 hash του {giveFile} είναι:{hashMD5}")
 hash_integrityCheck(file_md5,hashMD5)
 saveHash(file_md5,hashMD5)

 hashSHA256=hashlib.sha256(readFile).hexdigest()
 print(f"Το SHA256 hash του {giveFile} είναι:{hashSHA256}")
 hash_integrityCheck(file_sha256,hashSHA256)
 saveHash(file_sha256,hashSHA256)

 hashSHA3=hashlib.sha3_256(readFile).hexdigest()
 print(f"Το SHA3 hash του {giveFile} είναι:{hashSHA3}")
 hash_integrityCheck(file_sha3,hashSHA3)
 saveHash(file_sha3,hashSHA3)

#Ελεγχος για μηέγκυρη επιλογή αλγορίθμου
else:
 
 print("Μη έγκυρη επιλογή, δοκίμασε ξανά")
 algSelect=input()


 